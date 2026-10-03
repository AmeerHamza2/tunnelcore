package shadowsocks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport"
	"github.com/ameerhamza2/tunnelcore/transport/obfs"
	"github.com/ameerhamza2/tunnelcore/transport/protect"
)

// Config configures a Shadowsocks transport.
type Config struct {
	// Name identifies this transport in logs and metrics, for example
	// "shadowsocks/sgp-01".
	Name string

	// Server is the exit node's host:port.
	Server string

	// Method is the AEAD cipher.
	Method Method

	// Password is the shared secret for this server.
	//
	// The control plane provisions this as 32 bytes of base64-encoded CSPRNG
	// output per user per server, never a human-chosen string. See the comment
	// on NewCipher for why that matters given the spec's MD5 key derivation.
	Password string

	// Plugins wrap the underlying TCP connection, innermost first. This is
	// where obfuscation goes; see package obfs.
	Plugins []obfs.Plugin

	// DialTimeout bounds a single outbound dial. Zero selects
	// DefaultDialTimeout.
	DialTimeout time.Duration

	// ProbeTarget, if set, is dialed through the proxy by Up to verify that
	// the server is not merely reachable but actually accepting this
	// password. See the comment on Up.
	ProbeTarget netip.AddrPort

	// Protect, if set, is applied to every socket this transport opens (the
	// TCP connections and the UDP associations) before it connects, so they
	// bypass the VPN route. See package protect.
	Protect protect.Func
}

// DefaultDialTimeout bounds one outbound dial.
const DefaultDialTimeout = 10 * time.Second

// minPasswordBytes is the shortest password this package accepts.
//
// This is a guard against the real failure mode rather than a style rule. The
// spec's key derivation is a single unsalted MD5, so the master key has
// exactly as much entropy as the password and no more; a short or
// human-memorable password is brute-forceable offline from one captured
// stream. Sixteen bytes of CSPRNG output is the floor at which that stops
// being feasible, and provisioning is where it is actually enforced.
const minPasswordBytes = 16

// Config validation errors.
var (
	ErrNoServer     = errors.New("shadowsocks: server address is unset")
	ErrWeakPassword = fmt.Errorf("shadowsocks: password shorter than %d bytes", minPasswordBytes)
	ErrProbeFailed  = errors.New("shadowsocks: probe through the proxy failed")
	ErrProbeNoReply = errors.New("shadowsocks: probe target sent no data")
)

// Validate checks the config.
func (c *Config) Validate() error {
	if c.Server == "" {
		return ErrNoServer
	}
	if _, _, err := net.SplitHostPort(c.Server); err != nil {
		return fmt.Errorf("shadowsocks: server %q is not host:port: %w", c.Server, err)
	}
	if c.Password == "" {
		return ErrNoPassword
	}
	if len(c.Password) < minPasswordBytes {
		return ErrWeakPassword
	}
	if _, err := keySizeFor(c.Method); err != nil {
		return err
	}
	return nil
}

func (c *Config) dialTimeout() time.Duration {
	if c.DialTimeout <= 0 {
		return DefaultDialTimeout
	}
	return c.DialTimeout
}

func (c *Config) name() string {
	if c.Name != "" {
		return c.Name
	}
	return "shadowsocks/" + c.Server
}

// Transport is a Shadowsocks stream transport.
type Transport struct {
	cfg    Config
	cipher *Cipher

	mu     sync.Mutex
	up     bool
	closed bool

	// dialer is swappable so tests can inject a loopback dialer without
	// standing up a real network.
	dialer func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New creates a Shadowsocks transport. It performs no network I/O.
func New(cfg Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ciph, err := NewCipher(cfg.Method, cfg.Password)
	if err != nil {
		return nil, err
	}
	return &Transport{
		cfg:    cfg,
		cipher: ciph,
		dialer: cfg.Protect.Dialer().DialContext,
	}, nil
}

func (t *Transport) Name() string         { return t.cfg.name() }
func (t *Transport) Kind() transport.Kind { return transport.KindStream }

// Up verifies the server is usable.
//
// What "usable" can mean here is weaker than for WireGuard, and the difference
// is worth stating because it directly limits what connection-success-rate
// measures for this transport. Shadowsocks has no handshake: there is no
// message the server sends that proves it holds the same key. A TCP connection
// that completes proves only that the port is open and the network did not
// block it — which is genuinely the thing most likely to fail in a restrictive
// network, so it is not worthless, but it does not distinguish a working
// server from one with a rotated password.
//
// ProbeTarget closes that gap when the control plane supplies one: Up dials
// through the proxy to a known-responsive address and waits for the first
// authenticated chunk to decrypt. A wrong password cannot produce one, so a
// successful probe proves reachability *and* credentials.
func (t *Transport) Up(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return transport.ErrClosed
	}
	if t.up {
		t.mu.Unlock()
		return nil
	}
	t.mu.Unlock()

	if err := t.probe(ctx); err != nil {
		return err
	}

	t.mu.Lock()
	t.up = true
	t.mu.Unlock()
	return nil
}

func (t *Transport) probe(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, t.cfg.dialTimeout())
	defer cancel()

	raw, err := t.dialServer(dialCtx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: %s unreachable", transport.ErrHandshakeTimeout, t.Name())
		}
		return fmt.Errorf("shadowsocks: dialing %s: %w", t.Name(), err)
	}

	if !t.cfg.ProbeTarget.IsValid() {
		// Reachability only; see the doc comment on Up.
		return raw.Close()
	}
	defer raw.Close()

	conn := newStreamConn(raw, t.cipher)
	header := appendAddr(make([]byte, 0, maxAddrLen), t.cfg.ProbeTarget)
	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("%w: sending probe header: %w", ErrProbeFailed, err)
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(t.cfg.dialTimeout())
	}
	if err := raw.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("%w: %w", ErrProbeFailed, err)
	}

	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		if errors.Is(err, ErrAuthFailed) {
			// The only way to get here is a key mismatch, so say so plainly:
			// this is the error that tells an operator the password was
			// rotated without the clients being updated.
			return fmt.Errorf("%w: server rejected our key or replied with a key we do not hold", ErrProbeFailed)
		}
		return fmt.Errorf("%w: %w", ErrProbeNoReply, err)
	}
	return nil
}

// dialServer opens the raw TCP connection to the exit node and wraps it in the
// configured obfuscation plugins.
func (t *Transport) dialServer(ctx context.Context) (net.Conn, error) {
	c, err := t.dialer(ctx, "tcp", t.cfg.Server)
	if err != nil {
		return nil, err
	}
	wrapped, err := obfs.Chain(c, t.cfg.Plugins)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return wrapped, nil
}

// DialTCP opens a proxied TCP connection to dst.
//
// No round trip happens here beyond the TCP connect: the target address is
// queued and sent in the same chunk as the application's first write (or
// alone, shortly after, if the application reads first; see
// streamConn.setPendingHeader). A write error on the header therefore
// surfaces from the first Write or Read rather than from DialTCP. Shadowsocks has no connect-acknowledgement, which means a
// failure at the exit node surfaces as a read error on the first read rather
// than as a dial error. That is a property of the protocol, not of this
// implementation, and it is why the userspace stack's dial-then-create
// ordering cannot distinguish "refused by the destination" as precisely for
// this transport as it can for a direct connection.
func (t *Transport) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, transport.ErrClosed
	}
	if !t.up {
		t.mu.Unlock()
		return nil, transport.ErrNotReady
	}
	t.mu.Unlock()

	dialCtx, cancel := context.WithTimeout(ctx, t.cfg.dialTimeout())
	defer cancel()

	raw, err := t.dialServer(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: dialing %s: %w", t.Name(), err)
	}

	conn := newStreamConn(raw, t.cipher)
	// Queued, not written: it goes out in the same chunk as the
	// application's first write. See streamConn.setPendingHeader.
	conn.setPendingHeader(appendAddr(make([]byte, 0, maxAddrLen), dst))
	return conn, nil
}

// DialTCPDomain is DialTCP with the destination left as a name.
//
// Preferring this over DialTCP when the name is known moves resolution to the
// exit node: one fewer round trip on a high-latency link, and the local
// network sees no DNS at all for the connection.
func (t *Transport) DialTCPDomain(ctx context.Context, host string, port uint16) (net.Conn, error) {
	t.mu.Lock()
	ready := t.up && !t.closed
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, transport.ErrClosed
	}
	if !ready {
		return nil, transport.ErrNotReady
	}

	dialCtx, cancel := context.WithTimeout(ctx, t.cfg.dialTimeout())
	defer cancel()

	raw, err := t.dialServer(dialCtx)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: dialing %s: %w", t.Name(), err)
	}

	header, err := appendDomainAddr(make([]byte, 0, maxAddrLen), host, port)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	conn := newStreamConn(raw, t.cipher)
	conn.setPendingHeader(header)
	return conn, nil
}

// Close marks the transport closed. Connections already handed out stay open
// until their own Close; the userspace stack owns their lifetime.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.up = false
	t.closed = true
	return nil
}

var (
	_ transport.Transport    = (*Transport)(nil)
	_ transport.StreamDialer = (*Transport)(nil)
)
