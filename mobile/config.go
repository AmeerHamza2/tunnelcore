package mobile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport/obfs"
	"github.com/ameerhamza2/tunnelcore/transport/shadowsocks"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// config is the JSON the control plane serves and the mobile app passes
// straight through.
//
// JSON rather than a bound struct with setters is a deliberate choice forced
// by gomobile: a bound API cannot express a slice of structs, a map, or an
// optional field, so a configuration with "a list of candidate servers, each
// with a protocol and its own parameters" is simply not representable as a
// generated Java or Swift type. The alternatives are a long chain of
// addServer/setServerKey calls — stateful, order-dependent, and painful to
// validate — or one opaque string.
//
// The string also happens to be the right seam operationally: the control
// plane can add a field, a protocol, or an obfuscation plugin and existing
// clients keep working, because the mobile layer never parses it. Only Go
// does, and only in this file.
//
// The type and its parts (serverConfig, pluginConfig) are unexported for the
// same reason. Exported, gomobile generated Java and Swift classes for them
// with every slice field silently missing — a half-empty Config class that
// looks usable and is not. The JSON field names are the contract; the Go
// types are an implementation detail of parsing it.
type config struct {
	// Servers are the candidates to race, in preference order.
	Servers []serverConfig `json:"servers"`

	// TunnelAddresses are the addresses assigned to the tunnel interface, in
	// CIDR form.
	TunnelAddresses []string `json:"tunnel_addresses"`

	// DNSServers are the in-tunnel resolver addresses. Host or host:port; a
	// bare host gets port 53.
	DNSServers []string `json:"dns_servers"`

	// MTU for the tunnel interface. Zero selects 1420, the WireGuard-safe
	// default; it must match what the app passed to the OS when it built the
	// interface.
	MTU int `json:"mtu,omitempty"`

	// RaceStaggerMS and RaceTimeoutMS tune the transport race. Zero selects
	// the defaults in package transport.
	RaceStaggerMS int `json:"race_stagger_ms,omitempty"`
	RaceTimeoutMS int `json:"race_timeout_ms,omitempty"`

	// BlockedDomains are refused by the DNS proxy with NXDOMAIN.
	BlockedDomains []string `json:"blocked_domains,omitempty"`
}

// serverConfig is one candidate exit node.
type serverConfig struct {
	// Name identifies the server in logs and metrics, for example "fra-03".
	// It must not contain anything user-identifying: it ends up in metrics.
	Name string `json:"name"`

	// Protocol is "wireguard" or "shadowsocks".
	Protocol string `json:"protocol"`

	// Endpoint is host:port.
	Endpoint string `json:"endpoint"`

	// --- WireGuard ---

	// PrivateKey is this device's WireGuard private key, base64.
	//
	// The control plane never sends this. It is generated on the device by
	// GeneratePrivateKey, stored in the platform keystore by the app, and
	// merged into the config here. The server only ever holds the
	// corresponding public key, so a full compromise of the control-plane
	// database yields nothing that can decrypt any user's traffic.
	PrivateKey string `json:"private_key,omitempty"`

	// PublicKey is the server's WireGuard public key, base64.
	PublicKey string `json:"public_key,omitempty"`

	// PresharedKey is optional, base64. It adds a symmetric layer over the
	// Noise handshake, which is what makes a recorded session resistant to
	// later decryption by an attacker with a quantum computer.
	PresharedKey string `json:"preshared_key,omitempty"`

	// AllowedIPs are the destinations routed into this peer. Empty means full
	// tunnel.
	AllowedIPs []string `json:"allowed_ips,omitempty"`

	// KeepaliveSeconds keeps a carrier NAT mapping alive. Zero disables it,
	// which on mobile is usually wrong; see wireguard.Config.
	KeepaliveSeconds int `json:"keepalive_seconds,omitempty"`

	// --- Shadowsocks ---

	// Method is the AEAD cipher, for example "chacha20-ietf-poly1305".
	Method string `json:"method,omitempty"`

	// Password is the per-user secret for this server.
	Password string `json:"password,omitempty"`

	// Plugins are obfuscation layers, innermost first.
	Plugins []pluginConfig `json:"plugins,omitempty"`
}

// pluginConfig configures one obfuscation plugin.
type pluginConfig struct {
	// Type is "tlsfrag" or "prefix".
	Type string `json:"type"`

	// SplitAt is the tlsfrag offset. Zero selects SNI-aware splitting, which
	// is what you want; see obfs.TLSFragment.
	SplitAt int `json:"split_at,omitempty"`

	// Prefix is base64 bytes for the prefix plugin.
	Prefix string `json:"prefix,omitempty"`

	// ResponsePrefixLen is how many bytes to strip from the server's reply.
	ResponsePrefixLen int `json:"response_prefix_len,omitempty"`

	// Label names the plugin in logs without revealing its parameters.
	Label string `json:"label,omitempty"`
}

// Config errors.
var (
	ErrNoServers     = errors.New("mobile: config has no servers")
	ErrUnknownProto  = errors.New("mobile: unknown protocol")
	ErrUnknownPlugin = errors.New("mobile: unknown plugin type")
	ErrBadConfigJSON = errors.New("mobile: config is not valid JSON")
	ErrNoTunnelAddrs = errors.New("mobile: config has no tunnel addresses")
)

// parseConfig decodes and validates the JSON configuration.
//
// Validation happens here, entirely, and returns a single error naming the
// field at fault. The reason is debuggability across a language boundary: a
// config mistake that is caught here produces one legible message in the app's
// log, whereas one that slips through surfaces three layers down as a
// handshake that never completes, with nothing to connect it to the typo that
// caused it.
func parseConfig(raw string) (*config, error) {
	var cfg config
	dec := json.NewDecoder(stringReader(raw))
	// Reject unknown fields rather than ignoring them. A client that silently
	// ignores a field the control plane thinks it is honouring is how a
	// security setting ends up believed-enabled and actually off.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadConfigJSON, err)
	}
	// Decode stops after the first value. Anything but whitespace after it is
	// a second document the backend thinks is being honoured.
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after the configuration object", ErrBadConfigJSON)
	}

	if len(cfg.Servers) == 0 {
		return nil, ErrNoServers
	}
	if len(cfg.TunnelAddresses) == 0 {
		return nil, ErrNoTunnelAddrs
	}
	for i, s := range cfg.Servers {
		switch s.Protocol {
		case protoWireGuard, protoShadowsocks:
		default:
			return nil, fmt.Errorf("%w: servers[%d] (%s) has protocol %q", ErrUnknownProto, i, s.Name, s.Protocol)
		}
	}
	if _, err := cfg.tunnelPrefixes(); err != nil {
		return nil, err
	}
	if _, err := cfg.dnsUpstreams(); err != nil {
		return nil, err
	}
	if cfg.MTU != 0 && (cfg.MTU < 576 || cfg.MTU > 1500) {
		return nil, fmt.Errorf("%w: %d", ErrBadMTU, cfg.MTU)
	}
	// Bounded before they are multiplied into a time.Duration, which would
	// otherwise overflow into a negative or arbitrary value.
	if cfg.RaceStaggerMS < 0 || cfg.RaceStaggerMS > maxRaceStaggerMS {
		return nil, fmt.Errorf("%w: race_stagger_ms %d not in [0, %d]", ErrBadTiming, cfg.RaceStaggerMS, maxRaceStaggerMS)
	}
	if cfg.RaceTimeoutMS < 0 || cfg.RaceTimeoutMS > maxRaceTimeoutMS {
		return nil, fmt.Errorf("%w: race_timeout_ms %d not in [0, %d]", ErrBadTiming, cfg.RaceTimeoutMS, maxRaceTimeoutMS)
	}

	// Every server is built once here, with the same code Start will use,
	// so a malformed key or endpoint is reported now rather than as a
	// handshake that never completes. One bad server does not reject the
	// config — Candidates skips it, so a control plane that ships one bad
	// record costs that server, not the product — but a config in which no
	// server is usable is rejected with the first server's error.
	var firstErr error
	usable := 0
	for i := range cfg.Servers {
		if err := cfg.Servers[i].validate(cfg.mtu()); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		usable++
	}
	if usable == 0 {
		return nil, firstErr
	}
	return &cfg, nil
}

// ErrBadMTU is returned for an MTU outside what both transports accept.
var ErrBadMTU = errors.New("mobile: mtu out of range [576, 1500]")

// ErrBadTiming is returned for a race or keepalive setting out of range.
var ErrBadTiming = errors.New("mobile: timing setting out of range")

// Upper bounds for the timing settings. Each is far beyond any sensible
// value; they exist so the conversion to time.Duration cannot overflow.
const (
	maxRaceStaggerMS    = 60_000
	maxRaceTimeoutMS    = 300_000
	maxKeepaliveSeconds = 65535 // WireGuard's own limit (a uint16)
)

func (c *config) mtu() int {
	if c.MTU <= 0 {
		return defaultTunnelMTU
	}
	return c.MTU
}

// validate builds the transport config for one server and runs its own
// validation, without creating a transport.
func (s *serverConfig) validate(mtu int) error {
	switch s.Protocol {
	case protoWireGuard:
		c, err := s.wireguardConfig(mtu)
		if err != nil {
			return err
		}
		return c.Validate()
	case protoShadowsocks:
		c, err := s.shadowsocksConfig()
		if err != nil {
			return err
		}
		if err := c.Validate(); err != nil {
			return fmt.Errorf("mobile: server %s: %w", s.Name, err)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnknownProto, s.Protocol)
	}
}

const (
	protoWireGuard   = "wireguard"
	protoShadowsocks = "shadowsocks"
)

// tunnelPrefixes parses the tunnel addresses.
func (c *config) tunnelPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.TunnelAddresses))
	for i, s := range c.TunnelAddresses {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// Accept a bare address too: an app that passes "10.9.0.2"
			// instead of "10.9.0.2/32" has made a forgivable mistake, and
			// failing the whole tunnel over it is not worth it.
			if addr, aerr := netip.ParseAddr(s); aerr == nil {
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				out = append(out, netip.PrefixFrom(addr, bits))
				continue
			}
			return nil, fmt.Errorf("mobile: tunnel_addresses[%d] = %q: %w", i, s, err)
		}
		out = append(out, p)
	}
	for i, p := range out {
		// The userspace stack cannot own any of these; accepting one only
		// moved the failure to every session build, as a reconnect loop.
		if a := p.Addr(); a.IsUnspecified() || a.IsMulticast() || a.Is4In6() {
			return nil, fmt.Errorf("mobile: tunnel_addresses[%d] = %s is not a usable interface address", i, p)
		}
	}
	return out, nil
}

// dnsUpstreams parses the DNS server addresses, defaulting the port to 53.
func (c *config) dnsUpstreams() ([]netip.AddrPort, error) {
	out := make([]netip.AddrPort, 0, len(c.DNSServers))
	for i, s := range c.DNSServers {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			addr, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("mobile: dns_servers[%d] = %q: %w", i, s, aerr)
			}
			ap = netip.AddrPortFrom(addr, 53)
		}
		// dnsproxy.New refuses these, and it runs on every session build:
		// accepting one here turned a typo into an endless reconnect loop
		// over a perfectly healthy transport.
		if ap.Port() == 0 || ap.Addr().IsUnspecified() || ap.Addr().IsMulticast() {
			return nil, fmt.Errorf("mobile: dns_servers[%d] = %q is not a usable resolver address", i, s)
		}
		out = append(out, ap)
	}
	return out, nil
}

// wireguardConfig converts one server entry into a WireGuard transport config.
func (s *serverConfig) wireguardConfig(mtu int) (wireguard.Config, error) {
	priv, err := wireguard.ParseKey(s.PrivateKey)
	if err != nil {
		return wireguard.Config{}, fmt.Errorf("mobile: server %s private key: %w", s.Name, err)
	}
	pub, err := wireguard.ParseKey(s.PublicKey)
	if err != nil {
		return wireguard.Config{}, fmt.Errorf("mobile: server %s public key: %w", s.Name, err)
	}

	var psk wireguard.Key
	if s.PresharedKey != "" {
		psk, err = wireguard.ParseKey(s.PresharedKey)
		if err != nil {
			return wireguard.Config{}, fmt.Errorf("mobile: server %s preshared key: %w", s.Name, err)
		}
	}

	endpoint, err := resolveEndpoint(s.Endpoint)
	if err != nil {
		return wireguard.Config{}, fmt.Errorf("mobile: server %s endpoint: %w", s.Name, err)
	}
	if s.KeepaliveSeconds < 0 || s.KeepaliveSeconds > maxKeepaliveSeconds {
		return wireguard.Config{}, fmt.Errorf("%w: server %s keepalive_seconds %d not in [0, %d]",
			ErrBadTiming, s.Name, s.KeepaliveSeconds, maxKeepaliveSeconds)
	}

	allowed := wireguard.FullTunnelAllowedIPs()
	if len(s.AllowedIPs) > 0 {
		allowed = allowed[:0]
		for i, a := range s.AllowedIPs {
			p, perr := netip.ParsePrefix(a)
			if perr != nil {
				return wireguard.Config{}, fmt.Errorf("mobile: server %s allowed_ips[%d] = %q: %w", s.Name, i, a, perr)
			}
			allowed = append(allowed, p)
		}
	}

	return wireguard.Config{
		Name:                "wireguard/" + s.Name,
		PrivateKey:          priv,
		PeerPublicKey:       pub,
		PresharedKey:        psk,
		Endpoint:            endpoint,
		AllowedIPs:          allowed,
		MTU:                 mtu,
		PersistentKeepalive: time.Duration(s.KeepaliveSeconds) * time.Second,
	}, nil
}

// shadowsocksConfig converts one server entry into a Shadowsocks config.
func (s *serverConfig) shadowsocksConfig() (shadowsocks.Config, error) {
	plugins, err := s.obfsPlugins()
	if err != nil {
		return shadowsocks.Config{}, err
	}
	method := shadowsocks.Method(s.Method)
	if s.Method == "" {
		// ChaCha20-Poly1305 rather than AES-GCM as the default, because this
		// runs on phones: ARM cores without AES hardware acceleration are
		// still common in the low-end devices this product targets, and on
		// those ChaCha20 is several times faster.
		method = shadowsocks.ChaCha20Poly1305
	}
	// The same literal-address rule as WireGuard, and for the same reason
	// (see resolveEndpoint). It matters more here, not less: a hostname in
	// Server would be resolved by the dialer on every single connection, by
	// the system resolver, in cleartext, outside the tunnel — and on Android
	// through a resolver socket that Protect never sees.
	endpoint, err := resolveEndpoint(s.Endpoint)
	if err != nil {
		return shadowsocks.Config{}, fmt.Errorf("mobile: server %s endpoint: %w", s.Name, err)
	}
	return shadowsocks.Config{
		Name:     "shadowsocks/" + s.Name,
		Server:   endpoint.String(),
		Method:   method,
		Password: s.Password,
		Plugins:  plugins,
	}, nil
}

func (s *serverConfig) obfsPlugins() ([]obfs.Plugin, error) {
	if len(s.Plugins) == 0 {
		return nil, nil
	}
	out := make([]obfs.Plugin, 0, len(s.Plugins))
	for i, p := range s.Plugins {
		switch p.Type {
		case "tlsfrag":
			out = append(out, obfs.TLSFragment{SplitAt: p.SplitAt})
		case "prefix":
			b, err := base64.StdEncoding.DecodeString(p.Prefix)
			if err != nil {
				return nil, fmt.Errorf("mobile: server %s plugins[%d] prefix is not base64: %w", s.Name, i, err)
			}
			out = append(out, obfs.Prefix{
				Bytes:             b,
				ResponsePrefixLen: p.ResponsePrefixLen,
				Label:             p.Label,
			})
		default:
			return nil, fmt.Errorf("%w: server %s plugins[%d] type %q", ErrUnknownPlugin, s.Name, i, p.Type)
		}
	}
	return out, nil
}

// resolveEndpoint parses host:port into an AddrPort.
//
// A literal address is required: name resolution here would have to happen
// before the tunnel exists, which means a cleartext DNS query to whatever
// resolver the local network supplied — revealing which VPN server the user is
// about to connect to, to exactly the observer the VPN is meant to hide from.
// The control plane therefore serves addresses, not names.
func resolveEndpoint(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf(
			"%q must be a literal address:port (a hostname would need a cleartext DNS lookup outside the tunnel): %w", s, err)
	}
	return ap, nil
}
