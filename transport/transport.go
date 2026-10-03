// Package transport defines what the engine dials to reach an exit node, and
// the two shapes that VPN and proxy protocols actually come in.
//
// The split is the central design decision in this engine, so it is worth
// stating plainly:
//
//	KindPacket  A packet transport consumes raw IP packets and returns raw IP
//	            packets. WireGuard is one: the client encrypts whole IP
//	            datagrams and sends them over UDP. No userspace TCP/IP stack
//	            is involved, because nothing needs to understand TCP — the
//	            peer's kernel does that.
//
//	KindStream  A stream transport consumes *connections*. Shadowsocks,
//	            SOCKS5 and HTTP CONNECT are all like this: you hand them a
//	            destination address and they hand you back a byte stream.
//	            Raw IP packets are meaningless to them, so something has to
//	            terminate TCP locally and turn flows into streams. That
//	            something is the userspace stack in package netstack.
//
// Most VPN clients hard-wire one of these two and bolt the other on later,
// which is how you end up with two parallel data paths that drift apart. Here
// both kinds sit behind one interface, the engine owns the tunnel file
// descriptor in both cases, and the racer in this package can swap between
// them at runtime without touching the fd.
package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// Kind distinguishes the two transport shapes described in the package doc.
type Kind int

const (
	KindPacket Kind = iota + 1
	KindStream
)

func (k Kind) String() string {
	switch k {
	case KindPacket:
		return "packet"
	case KindStream:
		return "stream"
	default:
		return "kind?"
	}
}

// Transport errors.
var (
	// ErrClosed means the transport has been closed and will not reconnect.
	// The engine treats this as terminal for that transport and re-races.
	ErrClosed = errors.New("transport: closed")

	// ErrNotReady means the transport has not completed its handshake. The
	// engine never writes to a transport before Up returns, so seeing this
	// indicates a bug in the engine's state machine rather than a network
	// problem — it is reported separately in metrics for that reason.
	ErrNotReady = errors.New("transport: not ready")

	// ErrHandshakeTimeout means the transport could not establish itself
	// within the deadline. This is the single most common failure in
	// restrictive networks and the thing connection-success-rate measures.
	ErrHandshakeTimeout = errors.New("transport: handshake timed out")

	// ErrUnsupportedFlow means the transport cannot carry this flow, for
	// example UDP over a proxy that only speaks TCP.
	ErrUnsupportedFlow = errors.New("transport: unsupported flow")
)

// Transport is the behaviour common to both kinds.
//
// Up must be safe to cancel through ctx, because the racer starts several
// transports concurrently and cancels the losers. Implementations that leak a
// goroutine or a socket on cancellation show up as a slow resource leak over a
// day of network flapping, so Up is expected to leave nothing behind when it
// returns an error.
type Transport interface {
	// Name identifies this transport instance in logs and metrics. It should
	// include enough detail to tell two instances of the same protocol apart
	// (for example "wireguard/fra-03"), and must not contain secrets.
	Name() string

	// Kind reports which of the two interfaces below this transport also
	// implements.
	Kind() Kind

	// Up establishes the transport: completes a handshake, confirms
	// reachability, and returns only when the transport is ready to carry
	// traffic. It must be idempotent — calling it on an already-up transport
	// returns nil.
	Up(ctx context.Context) error

	// Close tears the transport down. It must be safe to call concurrently
	// with Up and more than once.
	Close() error
}

// PacketPipe is implemented by transports of KindPacket.
//
// The engine drives the copy loop: it reads an IP packet off the tunnel and
// calls WritePacket, and separately calls ReadPacket in a loop and writes
// whatever comes back to the tunnel.
type PacketPipe interface {
	Transport

	// WritePacket sends one outbound IP packet. It must not retain p.
	WritePacket(p []byte) error

	// ReadPacket blocks until one inbound IP packet is available, copies it
	// into b, and returns its length. It returns ErrClosed after Close.
	ReadPacket(b []byte) (int, error)

	// MTU is the largest IP packet this transport can carry without
	// fragmenting. The engine derives the tunnel MTU from this, minus its own
	// overhead.
	MTU() int
}

// StreamDialer is implemented by transports of KindStream.
//
// Both methods take the *original* destination as observed on the tunnel, not
// a resolved address: a stream transport is expected to carry the destination
// to the exit node and let it resolve, which is both faster (no extra RTT) and
// more private (the local network never sees the name).
type StreamDialer interface {
	Transport

	// DialTCP opens a proxied TCP connection to dst.
	//
	// The returned connection must support half-close, i.e. it must
	// additionally implement interface{ CloseWrite() error }. The userspace
	// stack relies on this to propagate the application's end-of-request
	// without tearing down the direction still carrying the response; a
	// connection that cannot be half-closed truncates every
	// request/response protocol that signals completion by closing, HTTP/1.0
	// among them. A *net.TCPConn satisfies this.
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)

	// DialUDP opens a proxied UDP association. Transports that cannot carry
	// UDP return ErrUnsupportedFlow, and the engine then drops UDP flows
	// rather than silently leaking them outside the tunnel — which is the
	// failure mode that turns a "UDP not supported" footnote into a privacy
	// incident.
	DialUDP(ctx context.Context, dst netip.AddrPort) (UDPSession, error)
}

// UDPSession is a proxied UDP association for a single local flow.
type UDPSession interface {
	// WriteTo sends one datagram to dst.
	WriteTo(b []byte, dst netip.AddrPort) (int, error)

	// ReadFrom receives one datagram and reports which address it came from.
	ReadFrom(b []byte) (int, netip.AddrPort, error)

	// Close releases the association.
	Close() error
}

// Compile-time assertions that the two sub-interfaces are supersets of
// Transport, so a *PacketPipe can always be stored as a Transport.
var (
	_ Transport = PacketPipe(nil)
	_ Transport = StreamDialer(nil)
)
