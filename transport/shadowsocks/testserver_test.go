package shadowsocks

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// testServer is a minimal Shadowsocks AEAD server.
//
// It exists so the client can be tested against something that actually
// implements the protocol rather than against a mock of itself. That matters
// more than usual here: the chunk framing, the nonce sequence and the HKDF
// subkey derivation are all things a client can get consistently wrong and
// still round-trip with its own mirror image. A separate implementation that
// reads what the client writes — and crucially, one that uses the *same*
// streamConn in the opposite role, so the salt-read and salt-write paths are
// both exercised — catches the asymmetric mistakes.
//
// It is a test fixture and nothing more: no replay protection, no rate
// limiting, no concurrency bounds, and it listens on loopback only.
type testServer struct {
	ln     net.Listener
	udp    *net.UDPConn
	cipher *Cipher

	// handler receives the decrypted target address and the client stream.
	handler func(target parsedAddr, conn net.Conn)

	// stripPrefix is discarded from the front of each accepted connection
	// before the Shadowsocks reader sees it, standing in for the server side
	// of an obfs.Prefix plugin.
	stripPrefix []byte

	mu       sync.Mutex
	requests []parsedAddr

	closeOnce sync.Once
}

// newTestServer starts a server that applies handler to each accepted stream.
func newTestServer(t *testing.T, method Method, password string, handler func(parsedAddr, net.Conn)) *testServer {
	t.Helper()
	return newTestServerWithPrefix(t, method, password, nil, handler)
}

// newTestServerWithPrefix is newTestServer for a server behind an obfs.Prefix
// plugin, which it stands in for by discarding prefix bytes from the front of
// each connection.
//
// The prefix is passed at construction rather than assigned to the field
// afterwards because the accept loop reads it from another goroutine; setting
// it post-hoc is a data race that -race catches.
func newTestServerWithPrefix(t *testing.T, method Method, password string, prefix []byte, handler func(parsedAddr, net.Conn)) *testServer {
	t.Helper()

	ciph, err := NewCipher(method, password)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	s := &testServer{ln: ln, cipher: ciph, handler: handler, stripPrefix: prefix}
	go s.acceptLoop()
	t.Cleanup(s.Close)
	return s
}

// newTestUDPServer starts a server that echoes UDP datagrams back to the
// address the datagram named.
//
// It also opens a TCP listener on the *same* port, because Config.Server is a
// single host:port used for both and the client's Up probes TCP. Binding both
// is what a real Shadowsocks server does too.
func newTestUDPServer(t *testing.T, method Method, password string) *testServer {
	t.Helper()

	ciph, err := NewCipher(method, password)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening on TCP: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		_ = ln.Close()
		t.Fatalf("listening on UDP port %d: %v", port, err)
	}

	s := &testServer{ln: ln, udp: udp, cipher: ciph, handler: echoHandler}
	go s.acceptLoop()
	go s.udpEchoLoop()
	t.Cleanup(s.Close)
	return s
}

func (s *testServer) addr() string {
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.udp.LocalAddr().String()
}

func (s *testServer) acceptLoop() {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(raw)
	}
}

func (s *testServer) serve(raw net.Conn) {
	defer raw.Close()

	if len(s.stripPrefix) > 0 {
		discard := make([]byte, len(s.stripPrefix))
		if _, err := io.ReadFull(raw, discard); err != nil {
			return
		}
	}

	conn := newStreamConn(raw, s.cipher)

	target, leftover, err := readTargetAddr(conn)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, target)
	s.mu.Unlock()

	if len(leftover) > 0 {
		// Push the bytes that arrived alongside the header back in front of
		// the stream so the handler sees a clean byte stream.
		conn2 := &prefixedConn{Conn: conn, pending: leftover}
		s.handler(target, conn2)
		return
	}
	s.handler(target, conn)
}

// readTargetAddr reads the SOCKS5 target address off the front of a decrypted
// stream and returns any payload bytes that arrived with it.
func readTargetAddr(r io.Reader) (parsedAddr, []byte, error) {
	buf := make([]byte, 0, maxAddrLen+512)
	tmp := make([]byte, 512)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			addr, perr := parseAddr(buf)
			if perr == nil {
				return addr, buf[addr.Len:], nil
			}
			if !errors.Is(perr, ErrAddrTooShort) {
				return parsedAddr{}, nil, perr
			}
			if len(buf) > maxAddrLen {
				return parsedAddr{}, nil, ErrBadAddrType
			}
		}
		if err != nil {
			return parsedAddr{}, nil, err
		}
	}
}

// prefixedConn replays buffered bytes before reading from the connection.
type prefixedConn struct {
	net.Conn
	pending []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (s *testServer) udpEchoLoop() {
	buf := make([]byte, 64<<10)
	for {
		n, from, err := s.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		saltSize := s.cipher.SaltSize()
		if n < saltSize+s.cipher.Overhead() {
			continue
		}
		aead, err := s.cipher.AEAD(buf[:saltSize])
		if err != nil {
			continue
		}
		zero := make([]byte, aead.NonceSize())
		plain, err := aead.Open(nil, zero, buf[saltSize:n], nil)
		if err != nil {
			continue
		}
		addr, err := parseAddr(plain)
		if err != nil {
			continue
		}
		s.mu.Lock()
		s.requests = append(s.requests, addr)
		s.mu.Unlock()

		// Echo the payload back, re-sealed under a fresh salt as the protocol
		// requires, naming the same address.
		payload := plain[addr.Len:]
		reply := make([]byte, 0, saltSize+maxAddrLen+len(payload)+aead.Overhead())
		salt := make([]byte, saltSize)
		copy(salt, buf[:saltSize])
		// A conforming server uses a *fresh* salt rather than echoing the
		// client's, because reusing it would reuse the subkey.
		salt[0] ^= 0xff
		outAEAD, err := s.cipher.AEAD(salt)
		if err != nil {
			continue
		}
		inner := appendAddr(nil, addr.Addr)
		inner = append(inner, payload...)
		reply = append(reply, salt...)
		reply = outAEAD.Seal(reply, make([]byte, outAEAD.NonceSize()), inner, nil)

		_, _ = s.udp.WriteToUDP(reply, from)
	}
}

func (s *testServer) seenRequests() []parsedAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]parsedAddr(nil), s.requests...)
}

func (s *testServer) Close() {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			_ = s.ln.Close()
		}
		if s.udp != nil {
			_ = s.udp.Close()
		}
	})
}

// echoHandler echoes the stream back, upper-cased.
func echoHandler(_ parsedAddr, conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			out := make([]byte, n)
			for i := 0; i < n; i++ {
				c := buf[i]
				if c >= 'a' && c <= 'z' {
					c -= 'a' - 'A'
				}
				out[i] = c
			}
			if _, werr := conn.Write(out); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// --- client helpers ---

const testPassword = "0123456789abcdefghijklmnopqrstuv" // 32 bytes, as provisioned

func newTestTransport(t *testing.T, srv *testServer, cfg Config) *Transport {
	t.Helper()
	if cfg.Server == "" {
		cfg.Server = srv.addr()
	}
	if cfg.Method == "" {
		cfg.Method = srv.cipher.Method()
	}
	if cfg.Password == "" {
		cfg.Password = testPassword
	}
	tr, err := New(cfg)
	if err != nil {
		t.Fatalf("shadowsocks.New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func upTransport(t *testing.T, tr *Transport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
}

var testTarget = netip.MustParseAddrPort("93.184.216.34:443")
