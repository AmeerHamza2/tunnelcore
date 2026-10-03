package obfs

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// maxPrefixLen bounds a configured prefix. A prefix is overhead on every
// connection, and anything larger than this is being used for something other
// than disguising a first packet.
const maxPrefixLen = 512

// ErrPrefixTooLong means the configured prefix exceeds maxPrefixLen.
var ErrPrefixTooLong = fmt.Errorf("obfs: prefix longer than %d bytes", maxPrefixLen)

// ErrNoPrefix means Prefix was configured with no bytes.
var ErrNoPrefix = errors.New("obfs: prefix is empty")

// Prefix prepends a fixed byte string to the client's first write, and strips
// a matching prefix from the server's first response.
//
// This is the Shadowsocks "prefix" plugin idea: the problem it solves is that
// a Shadowsocks stream's first bytes are a uniformly random salt, and
// uniformly random bytes at the start of a connection are themselves a
// classifier signal — real protocols begin with recognisable structure. A
// classifier looking for "high-entropy first packet on a non-standard port"
// flags Shadowsocks precisely *because* it is well encrypted. Prefixing bytes
// that look like the start of a protocol the network expects to see (an HTTP
// request line, a TLS record header) gives the classifier something ordinary
// to match instead.
//
// This is a disguise, not a security layer. The prefix is sent in the clear
// and carries no authentication, so it must never contain anything secret, and
// it provides no confidentiality of its own — the AEAD underneath does all the
// real work. Its only job is to change what the first packet looks like.
//
// Client and server must be configured with the same prefix. A mismatch
// presents as a connection that establishes and then stalls, because the
// server reads the prefix as the start of the salt.
type Prefix struct {
	// Bytes is the prefix sent before the first client write.
	Bytes []byte

	// ResponsePrefixLen is how many bytes to discard from the start of the
	// server's response. Zero means discard nothing.
	//
	// This is separate from len(Bytes) because the two directions do not have
	// to be symmetric, and in deployed configurations frequently are not: a
	// server may answer an HTTP-looking request with an HTTP-looking status
	// line of a completely different length.
	ResponsePrefixLen int

	// Label names this prefix in logs without revealing it.
	Label string
}

// HTTPGetPrefix is a prefix that makes a connection's first bytes look like
// the beginning of a plain HTTP request.
//
// It is provided as a documented example rather than a recommendation. A
// static prefix is itself a fingerprint once a censor learns it, which is why
// the control plane serves the prefix as part of a server's configuration
// instead of this being hardcoded in shipped clients: rotating it then costs
// an API response, not an app-store release.
func HTTPGetPrefix() Prefix {
	return Prefix{
		Bytes: []byte("GET / HTTP/1.1\r\n"),
		Label: "http-get",
	}
}

func (p Prefix) Name() string {
	if p.Label != "" {
		return "prefix(" + p.Label + ")"
	}
	return fmt.Sprintf("prefix(%d bytes)", len(p.Bytes))
}

func (p Prefix) Wrap(c net.Conn) (net.Conn, error) {
	if c == nil {
		return nil, ErrNilConn
	}
	if len(p.Bytes) == 0 {
		return nil, ErrNoPrefix
	}
	if len(p.Bytes) > maxPrefixLen {
		return nil, ErrPrefixTooLong
	}
	if p.ResponsePrefixLen < 0 || p.ResponsePrefixLen > maxPrefixLen {
		return nil, fmt.Errorf("obfs: response prefix length %d out of range", p.ResponsePrefixLen)
	}
	return &prefixConn{
		Conn:      c,
		prefix:    p.Bytes,
		stripLeft: p.ResponsePrefixLen,
	}, nil
}

type prefixConn struct {
	net.Conn
	prefix []byte

	writeMu sync.Mutex
	wrote   bool

	readMu    sync.Mutex
	stripLeft int
}

func (c *prefixConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.wrote {
		return c.Conn.Write(p)
	}

	// Send the prefix and the payload in one write. Two writes would put the
	// prefix in its own tiny segment, which recreates the anomaly the prefix
	// exists to remove.
	buf := make([]byte, 0, len(c.prefix)+len(p))
	buf = append(buf, c.prefix...)
	buf = append(buf, p...)

	n, err := c.Conn.Write(buf)
	c.wrote = true

	// Report only the caller's bytes. Returning n here would tell the caller
	// we accepted more than it gave us, and io.Copy treats a short write as
	// an error — so a naive implementation breaks every copy loop above it.
	if n < len(c.prefix) {
		return 0, err
	}
	accepted := n - len(c.prefix)
	if accepted > len(p) {
		accepted = len(p)
	}
	return accepted, err
}

func (c *prefixConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.stripLeft > 0 {
		// Discard in place, bounded by the caller's buffer, so a large
		// configured strip length cannot be turned into a large allocation.
		n := c.stripLeft
		if n > len(p) {
			n = len(p)
		}
		if n == 0 {
			return 0, nil
		}
		read, err := c.Conn.Read(p[:n])
		c.stripLeft -= read
		if err != nil {
			return 0, err
		}
	}
	return c.Conn.Read(p)
}

func (c *prefixConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

var _ Plugin = Prefix{}
var _ net.Conn = (*prefixConn)(nil)
