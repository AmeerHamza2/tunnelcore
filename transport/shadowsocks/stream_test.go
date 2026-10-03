package shadowsocks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// recordConn is a net.Conn that records every Write as a separate segment,
// which is what a passive observer sees as the connection's first packets.
type recordConn struct {
	net.Conn // nil unless wrapping a real conn

	mu       sync.Mutex
	writes   [][]byte
	failNext error
	closed   bool
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failNext != nil {
		err := c.failNext
		c.failNext = nil
		return 0, err
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	if c.Conn != nil {
		return c.Conn.Write(p)
	}
	return len(p), nil
}

func (c *recordConn) Read(p []byte) (int, error) {
	if c.Conn != nil {
		return c.Conn.Read(p)
	}
	return 0, io.EOF
}

func (c *recordConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func (c *recordConn) segments() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.writes...)
}

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	c, err := NewCipher(ChaCha20Poly1305, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// firstChunkLen is the on-wire size of a first segment carrying n plaintext
// bytes in one chunk.
func firstChunkLen(c *Cipher, n int) int {
	return c.SaltSize() + 2 + c.Overhead() + n + c.Overhead()
}

// decryptFirstChunk opens the first chunk of a recorded client stream with
// a server-side streamConn and returns its plaintext.
func decryptFirstChunk(t *testing.T, c *Cipher, wire []byte) []byte {
	t.Helper()
	srv := newStreamConn(&readOnlyConn{r: bytes.NewReader(wire)}, c)
	buf := make([]byte, maxChunkPayload)
	n, err := srv.Read(buf)
	if err != nil {
		t.Fatalf("server could not open the first chunk: %v", err)
	}
	return buf[:n]
}

type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (c *readOnlyConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// TestHeaderCoalescedWithFirstWrite is the fingerprinting property: the
// target address and the application's first bytes share one AEAD chunk, so
// the first segment's length is not a constant of the address type.
func TestHeaderCoalescedWithFirstWrite(t *testing.T) {
	ciph := testCipher(t)
	rec := &recordConn{}
	c := newStreamConn(rec, ciph)
	header := appendAddr(nil, testTarget)
	c.setPendingHeaderAfter(header, time.Hour)

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write = %d, %v; want %d, nil (the header is not the caller's bytes)", n, err, len(payload))
	}
	segs := rec.segments()
	if len(segs) != 1 {
		t.Fatalf("%d segments written, want 1 (header and payload in one chunk)", len(segs))
	}
	if got, want := len(segs[0]), firstChunkLen(ciph, len(header)+len(payload)); got != want {
		t.Fatalf("first segment is %d bytes, want %d", got, want)
	}
	if got := decryptFirstChunk(t, ciph, segs[0]); !bytes.Equal(got, append(append([]byte(nil), header...), payload...)) {
		t.Fatalf("first chunk plaintext = %x, want header+payload", got)
	}

	// Later writes are untouched.
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if segs := rec.segments(); len(segs) != 2 || len(segs[1]) != 2+ciph.Overhead()+1+ciph.Overhead() {
		t.Fatalf("second write produced %d segments / unexpected size", len(segs))
	}
}

// TestDialTCPCoalescesHeader checks the same property through DialTCP,
// against a real server, so the queued header is also proven to be parsed
// correctly when it arrives glued to the payload.
func TestDialTCPCoalescesHeader(t *testing.T) {
	srv := newTestServer(t, ChaCha20Poly1305, testPassword, echoHandler)
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)

	var rec *recordConn
	inner := tr.dialer
	tr.dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := inner(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		rec = &recordConn{Conn: c}
		return rec, nil
	}

	conn, err := tr.DialTCP(context.Background(), testTarget)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()
	dialed := time.Now()
	payload := []byte("hello through the proxy")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if time.Since(dialed) >= headerCoalesceDelay {
		t.Skip("scheduler delayed the first Write past the coalescing window")
	}
	header := appendAddr(nil, testTarget)
	segs := rec.segments()
	if len(segs) == 0 || len(segs[0]) != firstChunkLen(tr.cipher, len(header)+len(payload)) {
		t.Fatalf("first segment is not header+payload in one chunk (segments: %d)", len(segs))
	}

	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, bytes.ToUpper(payload)) { // echoHandler upper-cases
		t.Fatalf("echo = %q, %v", got, err)
	}
}

// TestHeaderFlushedAloneWithoutWrite: a connection the application never
// writes to still has to reach its destination, or a server-speaks-first
// protocol never gets its banner.
func TestHeaderFlushedAloneWithoutWrite(t *testing.T) {
	ciph := testCipher(t)
	rec := &recordConn{}
	c := newStreamConn(rec, ciph)
	header := appendAddr(nil, testTarget)
	c.setPendingHeader(header)

	deadline := time.Now().Add(2 * time.Second)
	for len(rec.segments()) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	segs := rec.segments()
	if len(segs) != 1 || len(segs[0]) != firstChunkLen(ciph, len(header)) {
		t.Fatalf("header was not flushed on its own by the timer (segments: %d)", len(segs))
	}
	// A later write must not resend it.
	if _, err := c.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	if segs := rec.segments(); len(segs) != 2 || len(segs[1]) != 2+ciph.Overhead()+4+ciph.Overhead() {
		t.Fatal("write after the timer flush resent the header")
	}
}

func TestReadAndCloseWriteFlushHeader(t *testing.T) {
	ciph := testCipher(t)
	header := appendAddr(nil, testTarget)
	for name, op := range map[string]func(*streamConn){
		"read":       func(c *streamConn) { _, _ = c.Read(make([]byte, 16)) },
		"closewrite": func(c *streamConn) { _ = c.CloseWrite() },
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recordConn{}
			c := newStreamConn(rec, ciph)
			c.setPendingHeaderAfter(header, time.Hour)
			op(c)
			segs := rec.segments()
			if len(segs) != 1 || len(segs[0]) != firstChunkLen(ciph, len(header)) {
				t.Fatalf("%s did not flush the pending header first (segments: %d)", name, len(segs))
			}
		})
	}
}

// TestWriteErrorIsSticky: a failed underlying write has already consumed
// two nonces, so a later write would be sealed under nonces the peer has not
// seen (and, before the salt has gone out, without the salt). The stream must
// stay failed rather than emit a chunk the server rejects or misparses.
func TestWriteErrorIsSticky(t *testing.T) {
	ciph := testCipher(t)
	boom := errors.New("boom")
	rec := &recordConn{failNext: boom}
	c := newStreamConn(rec, ciph)

	if _, err := c.Write([]byte("first")); !errors.Is(err, boom) {
		t.Fatalf("first Write = %v, want boom", err)
	}
	n, err := c.Write([]byte("second"))
	if !errors.Is(err, boom) || n != 0 {
		t.Fatalf("Write after a failed Write = %d, %v; want 0, the sticky error", n, err)
	}
	if segs := rec.segments(); len(segs) != 0 {
		t.Fatalf("%d segments reached the wire after the stream broke", len(segs))
	}
}

// orderConn blocks its first Write until release is closed and records the
// order in which writes and the half-close reach the socket.
type orderConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once

	mu     sync.Mutex
	events []string
}

func (c *orderConn) record(e string) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *orderConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.started); <-c.release })
	c.record("write")
	return len(p), nil
}

func (c *orderConn) Read([]byte) (int, error) { <-c.release; return 0, io.EOF }
func (c *orderConn) CloseWrite() error        { c.record("closewrite"); return nil }
func (c *orderConn) Close() error             { return nil }

// TestCloseWriteWaitsForInFlightHeaderWrite is the regression test for a
// half-close overtaking the target-address header.
//
// Read flushes a still-pending header (a server-speaks-first protocol reads
// before writing) and clears headerPending as it takes the header, before the
// write. CloseWrite used to look only at headerPending, so a CloseWrite racing
// that write shut the socket's write half down underneath it: the header
// write failed with EPIPE and the exit node saw EOF before the destination.
// The soak test against internal/ssserver hit this on an empty request to a
// server-first target.
func TestCloseWriteWaitsForInFlightHeaderWrite(t *testing.T) {
	ciph := testCipher(t)
	conn := &orderConn{started: make(chan struct{}), release: make(chan struct{})}
	c := newStreamConn(conn, ciph)
	c.setPendingHeaderAfter(appendAddr(nil, testTarget), time.Hour)

	go func() { _, _ = c.Read(make([]byte, 16)) }() // takes and writes the header
	<-conn.started                                  // the header write is now in progress

	done := make(chan error, 1)
	go func() { done <- c.CloseWrite() }()
	var err error
	returned := false
	select {
	case err = <-done:
		returned = true // did not wait for the header write in progress
	case <-time.After(100 * time.Millisecond):
	}
	close(conn.release)
	if !returned {
		err = <-done
	}
	if err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.events) != 2 || conn.events[0] != "write" || conn.events[1] != "closewrite" {
		t.Fatalf("socket saw %v, want [write closewrite]: the half-close overtook the header", conn.events)
	}
}
