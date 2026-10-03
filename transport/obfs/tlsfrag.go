package obfs

import (
	"fmt"
	"net"
	"sync"
)

// TLSFragment splits the first write of a connection across more than one TCP
// segment.
//
// This is the cheapest effective answer to the most widely deployed form of
// VPN and site blocking: a middlebox that reads the SNI out of a TLS
// ClientHello and drops the connection if the name is on a list. Such a
// middlebox almost always inspects a single TCP segment — reassembling flows
// costs state per connection, and at carrier scale that state is the
// expensive part. Splitting the ClientHello so that the SNI straddles a
// segment boundary means the matcher never sees the complete string in any one
// segment it examines, and the connection survives.
//
// The destination is unaffected: TCP is a byte stream, so the server
// reassembles the ClientHello normally and has no idea it arrived in pieces.
// Nothing about the bytes changes, only how they are chunked, which is why
// this works against a classifier and is invisible to the endpoint.
//
// By default the split point is found by locating the SNI and cutting through
// the middle of the hostname. A fixed offset is available via SplitAt, but it
// is the weaker option and worth understanding why: an offset that lands
// *before* the SNI stops the first segment from containing the hostname, yet
// leaves the name whole and contiguous in the second segment, where a matcher
// inspecting each segment independently still finds it. Only a cut inside the
// name defeats that.
//
// Its limits are equally worth knowing. A middlebox that *does* reassemble
// defeats it outright. It only perturbs the first write, so it does nothing
// for a classifier keyed on anything later in the stream. It cannot help where
// there is no cleartext SNI to split (TLS 1.3 with ECH), though in that case
// there is nothing for a name matcher to match either. And it is a behaviour a
// determined censor can itself fingerprint — an unusually small first segment
// is its own anomaly. It buys time against a specific, very common
// implementation shortcut; it is not a cloak.
type TLSFragment struct {
	// SplitAt overrides the split point with a fixed byte offset into the
	// first write.
	//
	// Leave it zero to use SNI-aware splitting, which is what you want. Set
	// it only when you know the exact layout you are producing — the
	// Shadowsocks tests set it to make segment boundaries predictable.
	SplitAt int
}

// DefaultTLSSplitOffset is the fallback split point used when SplitAt is zero
// and no SNI could be located — a non-TLS first write, a ClientHello that
// arrives in pieces, or ECH.
//
// It is past the record and handshake headers and inside the client random, so
// it splits something rather than producing one empty segment, and it keeps the
// behaviour uniform for traffic this plugin cannot parse.
const DefaultTLSSplitOffset = 32

func (f TLSFragment) Name() string {
	if f.SplitAt > 0 {
		return fmt.Sprintf("tlsfrag(%d)", f.SplitAt)
	}
	return "tlsfrag(sni)"
}

func (f TLSFragment) Wrap(c net.Conn) (net.Conn, error) {
	if c == nil {
		return nil, ErrNilConn
	}
	return &tlsFragConn{Conn: c, fixedSplit: f.SplitAt}, nil
}

type tlsFragConn struct {
	net.Conn
	// fixedSplit is >0 when an explicit offset was configured.
	fixedSplit int

	mu    sync.Mutex
	split bool // whether the first write has already happened
}

// splitPoint decides where to cut p.
//
// Returning 0 means "do not split".
func (c *tlsFragConn) splitPoint(p []byte) int {
	if c.fixedSplit > 0 {
		if len(p) <= c.fixedSplit {
			return 0
		}
		return c.fixedSplit
	}

	if start, end, ok := findSNI(p); ok {
		// Cut through the middle of the hostname. The midpoint rather than
		// the first byte, because a one-byte-in cut leaves all but the first
		// character of the name in the second segment, and a matcher using a
		// suffix match on the registrable domain would still fire.
		mid := start + (end-start)/2 + 1
		if mid > 0 && mid < len(p) {
			return mid
		}
	}

	if len(p) <= DefaultTLSSplitOffset {
		return 0
	}
	return DefaultTLSSplitOffset
}

// Write splits only the first write, then gets out of the way.
//
// The return value is the number of *payload* bytes accepted, not the number
// of bytes written to the socket, so a caller doing the usual
// `n, err := Write(p)` sees exactly what it expects. A partial failure after
// the first segment reports the bytes that did land, which is what io.Copy
// and friends require to behave correctly.
func (c *tlsFragConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	first := !c.split
	c.split = true
	c.mu.Unlock()

	if !first {
		return c.Conn.Write(p)
	}
	at := c.splitPoint(p)
	if at <= 0 {
		return c.Conn.Write(p)
	}

	n1, err := c.Conn.Write(p[:at])
	if err != nil {
		return n1, err
	}
	n2, err := c.Conn.Write(p[at:])
	return n1 + n2, err
}

// CloseWrite preserves half-close through the wrapper, which the userspace
// stack requires of every transport connection.
func (c *tlsFragConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

var _ Plugin = TLSFragment{}
var _ net.Conn = (*tlsFragConn)(nil)
