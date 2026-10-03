// Package ssserver is a small Shadowsocks AEAD (AEAD-2018) TCP server.
//
// It exists for the tun-harness demo and for tests: the engine's Shadowsocks
// client is only convincingly exercised against an independent implementation
// of the server side, and the one in transport/shadowsocks/testserver_test.go
// is unexported test code that reuses the client's own streamConn. This
// package re-implements the framing from the spec using only the exported
// pieces of package shadowsocks (NewCipher and Cipher.AEAD, i.e. the key and
// subkey derivation), so a framing mistake that the client makes consistently
// in both directions would show up here as an authentication failure rather
// than round-tripping silently.
//
// It is a fixture, not a deployable server: it listens wherever it is told
// (the harness only ever uses loopback), keeps no replay filter, applies no
// rate limits, and on an authentication failure simply closes the connection.
// A server exposed to the internet must instead keep reading for a random
// while before closing, or the close itself becomes an active-probing oracle
// that identifies it as Shadowsocks.
package ssserver

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"github.com/ameerhamza2/tunnelcore/transport/shadowsocks"
)

// maxChunkPayload is the spec's cap on one chunk's payload. The top two bits
// of the length field must be zero; see transport/shadowsocks/stream.go.
const maxChunkPayload = 0x3fff

// SOCKS5 address types, which Shadowsocks reuses for its target header.
const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

// Errors reported for a malformed client stream.
var (
	ErrAuth         = errors.New("ssserver: AEAD authentication failed (wrong password or corrupted stream)")
	ErrChunkLength  = errors.New("ssserver: invalid chunk length")
	ErrBadAddrType  = errors.New("ssserver: unknown target address type")
	ErrServerClosed = errors.New("ssserver: server closed")
)

// Target is the destination a client asked the server to connect to.
// Exactly one of Addr or Host is set.
type Target struct {
	Addr netip.AddrPort
	Host string
	Port uint16
}

func (t Target) String() string {
	if t.Host != "" {
		return net.JoinHostPort(t.Host, fmt.Sprint(t.Port))
	}
	return t.Addr.String()
}

// Handler serves one decrypted client stream. conn reads and writes
// plaintext, supports CloseWrite, and is closed by the server when the
// handler returns.
type Handler func(target Target, conn net.Conn)

// Config configures a Server.
type Config struct {
	// Addr is the TCP listen address, for example "127.0.0.1:0".
	Addr     string
	Method   shadowsocks.Method
	Password string
	Handler  Handler

	// OnError, if set, is told about streams rejected before reaching the
	// handler — chiefly authentication failures, which is what a client with
	// a rotated password produces.
	OnError func(remote net.Addr, err error)
}

// Server is a running Shadowsocks server.
type Server struct {
	cfg    Config
	cipher *shadowsocks.Cipher
	ln     net.Listener

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// Listen starts a server.
func Listen(cfg Config) (*Server, error) {
	if cfg.Handler == nil {
		return nil, errors.New("ssserver: no handler")
	}
	ciph, err := shadowsocks.NewCipher(cfg.Method, cfg.Password)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, cipher: ciph, ln: ln, conns: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go s.acceptLoop()
	return s, nil
}

// Addr is the address the server is listening on.
func (s *Server) Addr() netip.AddrPort {
	return s.ln.Addr().(*net.TCPAddr).AddrPort()
}

// Close stops accepting, tears down every live connection and waits for the
// handlers to return.
//
// Tearing live connections down, rather than letting them drain, is what
// makes Close usable to simulate an exit node dying: a crashed server does not
// politely finish its in-flight streams.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()

	err := s.ln.Close()
	s.wg.Wait()
	return err
}

// Track registers an auxiliary connection (for example a handler's upstream
// dial) so that Close tears it down too. It reports false, having closed c,
// if the server is already closed.
func (s *Server) Track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

// Untrack reverses Track.
func (s *Server) Untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !s.Track(raw) {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.Untrack(raw)
			defer raw.Close()
			s.serve(raw)
		}()
	}
}

func (s *Server) serve(raw net.Conn) {
	c := newConn(raw, s.cipher)
	target, err := readTarget(c)
	if err != nil {
		if s.cfg.OnError != nil && !errors.Is(err, io.EOF) {
			s.cfg.OnError(raw.RemoteAddr(), err)
		}
		return
	}
	s.cfg.Handler(target, c)
}

// readTarget decodes the SOCKS5-form address at the front of the plaintext.
func readTarget(r io.Reader) (Target, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return Target{}, err
	}
	var t Target
	switch atyp[0] {
	case atypIPv4:
		var b [4 + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Target{}, err
		}
		t.Addr = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), binary.BigEndian.Uint16(b[4:]))
	case atypIPv6:
		var b [16 + 2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Target{}, err
		}
		t.Addr = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[:16])), binary.BigEndian.Uint16(b[16:]))
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return Target{}, err
		}
		b := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return Target{}, err
		}
		t.Host = string(b[:l[0]])
		t.Port = binary.BigEndian.Uint16(b[l[0]:])
	default:
		return Target{}, fmt.Errorf("%w: %d", ErrBadAddrType, atyp[0])
	}
	return t, nil
}

// conn is the server side of one AEAD stream.
//
// The two directions are fully independent — each has its own salt, subkey
// and nonce counter — which is why they are guarded by separate locks and
// why the read side cannot be initialised until the client's salt arrives.
type conn struct {
	net.Conn
	cipher *shadowsocks.Cipher

	rmu      sync.Mutex
	raead    cipher.AEAD
	rnonce   []byte
	rbuf     []byte
	leftover []byte

	wmu    sync.Mutex
	waead  cipher.AEAD
	wnonce []byte
	wsalt  []byte // pending until the first chunk carries it
	wbuf   []byte
}

func newConn(c net.Conn, ciph *shadowsocks.Cipher) *conn {
	tag := ciph.Overhead()
	return &conn{
		Conn:   c,
		cipher: ciph,
		rbuf:   make([]byte, maxChunkPayload+tag),
		wbuf:   make([]byte, 0, ciph.SaltSize()+2+tag+maxChunkPayload+tag),
	}
}

func (c *conn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()

	if len(c.leftover) > 0 {
		n := copy(p, c.leftover)
		c.leftover = c.leftover[n:]
		return n, nil
	}
	if c.raead == nil {
		salt := make([]byte, c.cipher.SaltSize())
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return 0, err
		}
		aead, err := c.cipher.AEAD(salt)
		if err != nil {
			return 0, err
		}
		c.raead = aead
		c.rnonce = make([]byte, aead.NonceSize())
	}

	tag := c.raead.Overhead()
	lenBlock := c.rbuf[:2+tag]
	if _, err := io.ReadFull(c.Conn, lenBlock); err != nil {
		return 0, err
	}
	plainLen, err := c.raead.Open(lenBlock[:0], c.rnonce, lenBlock, nil)
	if err != nil {
		return 0, ErrAuth
	}
	increment(c.rnonce)

	size := int(binary.BigEndian.Uint16(plainLen))
	if size == 0 || size > maxChunkPayload {
		return 0, fmt.Errorf("%w: %d", ErrChunkLength, size)
	}
	payload := c.rbuf[:size+tag]
	if _, err := io.ReadFull(c.Conn, payload); err != nil {
		return 0, err
	}
	plain, err := c.raead.Open(payload[:0], c.rnonce, payload, nil)
	if err != nil {
		return 0, ErrAuth
	}
	increment(c.rnonce)

	n := copy(p, plain)
	if n < len(plain) {
		c.leftover = append(c.leftover[:0], plain[n:]...)
	}
	return n, nil
}

func (c *conn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()

	if c.waead == nil {
		// A fresh random salt per direction. Echoing the client's salt back
		// would derive the same subkey, and with both nonce counters starting
		// at zero that is nonce reuse under one key — fatal for both AEADs.
		salt := make([]byte, c.cipher.SaltSize())
		if _, err := rand.Read(salt); err != nil {
			return 0, err
		}
		aead, err := c.cipher.AEAD(salt)
		if err != nil {
			return 0, err
		}
		c.waead, c.wnonce, c.wsalt = aead, make([]byte, aead.NonceSize()), salt
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunkPayload {
			chunk = chunk[:maxChunkPayload]
		}
		out := c.wbuf[:0]
		if c.wsalt != nil {
			out = append(out, c.wsalt...)
		}
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(chunk)))
		out = c.waead.Seal(out, c.wnonce, l[:], nil)
		increment(c.wnonce)
		out = c.waead.Seal(out, c.wnonce, chunk, nil)
		increment(c.wnonce)

		if _, err := c.Conn.Write(out); err != nil {
			return written, err
		}
		c.wsalt = nil
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// CloseWrite half-closes the underlying TCP connection, so a handler can
// signal end-of-response while still reading.
func (c *conn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

// increment adds one to a little-endian nonce counter.
func increment(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// Splice copies between a and b in both directions, propagating half-closes,
// until both directions are done. It is the body of a forwarding handler.
func Splice(a, b net.Conn) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		// Half-close rather than Close: the other direction may still be
		// carrying the response to the request that just finished.
		if hc, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}
	wg.Add(2)
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}
