package wireguard

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport/protect"
)

// Config is everything needed to bring up one WireGuard transport.
//
// PrivateKey is generated on the device and never leaves it. The control
// plane issues a peer by storing only the corresponding public key, so a full
// compromise of the control-plane database yields no key material that can
// decrypt any user's traffic. Any API shape that has the server generating
// the keypair and shipping the private half down to the client is a finding,
// not a convenience — see docs/DUE_DILIGENCE_GAPS.md.
type Config struct {
	// PrivateKey is this device's WireGuard private key.
	PrivateKey Key

	// PeerPublicKey is the exit node's public key.
	PeerPublicKey Key

	// PresharedKey is optional. It adds a symmetric layer on top of the
	// Noise handshake, which is what makes a WireGuard session
	// post-quantum-resistant against a passive attacker recording traffic
	// today to decrypt later. Zero means unused.
	PresharedKey Key

	// Endpoint is the exit node's UDP address.
	Endpoint netip.AddrPort

	// Addresses are the tunnel-interface addresses assigned to this device.
	Addresses []netip.Prefix

	// AllowedIPs are the destinations routed into this peer. For a full-tunnel
	// consumer VPN this is 0.0.0.0/0 and ::/0.
	AllowedIPs []netip.Prefix

	// DNS servers to advertise to the OS. The engine's DNS proxy answers on
	// these addresses, so they are reachable only inside the tunnel.
	DNS []netip.Addr

	// MTU for the tunnel interface. Zero selects DefaultMTU.
	MTU int

	// PersistentKeepalive keeps a NAT mapping alive. Zero disables it.
	//
	// On mobile this is not optional in practice: carrier NATs expire UDP
	// mappings aggressively (tens of seconds on some networks), and without
	// a keepalive the first packet after an idle period is silently dropped,
	// which the user experiences as "the VPN is connected but nothing
	// loads". 25s is the value WireGuard recommends and the one that fits
	// inside the shortest mappings observed in the wild.
	PersistentKeepalive time.Duration

	// Name identifies this transport in logs and metrics, for example
	// "wireguard/fra-03".
	Name string

	// ListenPort binds the transport to a fixed UDP source port.
	//
	// Leave this zero on a client. A fixed source port is a fingerprint: it
	// lets a passive observer recognise the same device across reconnects and
	// across networks, which for a privacy product is a defect rather than a
	// tuning knob. It exists because the *other* end of a tunnel has to
	// listen somewhere — the end-to-end tests stand up a listening peer, and
	// a hub-and-spoke deployment would too.
	ListenPort int

	// Protect, if set, is applied to the transport's UDP sockets before
	// anything is sent on them, so they bypass the VPN route. Required on
	// Android unless the app excludes itself from its own VPN; nil on iOS.
	// See package protect.
	Protect protect.Func

	// DeadPeerTimeout is how long data sent to the peer may go without
	// anything at all coming back before the transport declares the peer
	// dead and closes itself. Zero selects DefaultDeadPeerTimeout; negative
	// disables the check. See Transport.monitor.
	DeadPeerTimeout time.Duration
}

// DefaultDeadPeerTimeout is the DeadPeerTimeout used when the field is zero.
//
// WireGuard guarantees a live peer answers any data packet within
// KEEPALIVE_TIMEOUT + REKEY_TIMEOUT (10s + 5s): with data of its own, or
// failing that a passive keepalive. 20s is that bound plus margin for one
// lost reply and a slow radio, so a healthy-but-quiet peer never trips it.
const DefaultDeadPeerTimeout = 20 * time.Second

// DefaultMTU is the tunnel MTU used when Config.MTU is zero.
//
// 1420 is 1500 minus WireGuard's 80 bytes of IPv6+UDP+WireGuard overhead,
// which is the conservative choice: computing it from IPv4 overhead instead
// gives 1440 and then breaks the moment the underlying path is IPv6, in the
// hard-to-diagnose way where small packets work and large ones vanish.
const DefaultMTU = 1420

// Config validation errors.
var (
	ErrNoPrivateKey   = errors.New("wireguard: private key is unset")
	ErrNoPeerKey      = errors.New("wireguard: peer public key is unset")
	ErrNoEndpoint     = errors.New("wireguard: endpoint is unset")
	ErrNoAllowedIPs   = errors.New("wireguard: no allowed IPs configured")
	ErrSelfPeering    = errors.New("wireguard: peer public key equals our own public key")
	ErrMTUOutOfRange  = errors.New("wireguard: MTU out of range")
	ErrBadKeepaliveIv = errors.New("wireguard: persistent keepalive out of range")
)

// Validate checks the config for the mistakes that otherwise present as a
// handshake that simply never completes, with nothing in any log to say why.
func (c *Config) Validate() error {
	if c.PrivateKey.IsZero() {
		return ErrNoPrivateKey
	}
	if c.PeerPublicKey.IsZero() {
		return ErrNoPeerKey
	}
	// Configuring our own public key as the peer is what happens when a
	// provisioning bug crosses the two fields. WireGuard does not reject it;
	// it just never handshakes.
	if c.PrivateKey.PublicKey().Equal(c.PeerPublicKey) {
		return ErrSelfPeering
	}
	if !c.Endpoint.IsValid() || c.Endpoint.Port() == 0 {
		return ErrNoEndpoint
	}
	if len(c.AllowedIPs) == 0 {
		return ErrNoAllowedIPs
	}
	if c.MTU != 0 && (c.MTU < 576 || c.MTU > 1500) {
		return fmt.Errorf("%w: %d", ErrMTUOutOfRange, c.MTU)
	}
	if c.PersistentKeepalive != 0 &&
		(c.PersistentKeepalive < time.Second || c.PersistentKeepalive > 65535*time.Second) {
		return fmt.Errorf("%w: %s", ErrBadKeepaliveIv, c.PersistentKeepalive)
	}
	return nil
}

func (c *Config) mtu() int {
	if c.MTU == 0 {
		return DefaultMTU
	}
	return c.MTU
}

// deadPeerTimeout returns the effective timeout, or 0 when disabled.
func (c *Config) deadPeerTimeout() time.Duration {
	switch {
	case c.DeadPeerTimeout < 0:
		return 0
	case c.DeadPeerTimeout == 0:
		return DefaultDeadPeerTimeout
	default:
		return c.DeadPeerTimeout
	}
}

func (c *Config) name() string {
	if c.Name == "" {
		return "wireguard/" + c.Endpoint.String()
	}
	return c.Name
}

// uapi renders the config in wireguard-go's IPC configuration format.
//
// The returned string contains the private key in hex. It is passed straight
// to device.IpcSet and must never be logged; that is why this method is
// unexported and why nothing in this package returns it to a caller.
func (c *Config) uapi() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", c.PrivateKey.Hex())
	// Zero selects a random ephemeral source port, which is what a client
	// wants; see Config.ListenPort and portReportingBind.
	fmt.Fprintf(&sb, "listen_port=%d\n", c.ListenPort)
	sb.WriteString("replace_peers=true\n")

	fmt.Fprintf(&sb, "public_key=%s\n", c.PeerPublicKey.Hex())
	if !c.PresharedKey.IsZero() {
		fmt.Fprintf(&sb, "preshared_key=%s\n", c.PresharedKey.Hex())
	}
	fmt.Fprintf(&sb, "endpoint=%s\n", c.Endpoint.String())
	if c.PersistentKeepalive > 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n",
			int(c.PersistentKeepalive.Seconds()))
	}
	sb.WriteString("replace_allowed_ips=true\n")
	for _, p := range c.AllowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", p.String())
	}
	return sb.String()
}

// FullTunnelAllowedIPs is the AllowedIPs set for a consumer VPN that carries
// all traffic.
func FullTunnelAllowedIPs() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
}
