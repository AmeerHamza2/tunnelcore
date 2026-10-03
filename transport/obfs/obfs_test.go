package obfs

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// recordingConn captures each individual Write as a separate entry, which is
// how the fragmenter's behaviour becomes observable: the whole point of
// TLSFragment is *how many* writes happen, not what bytes they contain.
type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
	// readFrom supplies bytes to Read.
	readFrom []byte
	closed   bool
}

func newRecordingConn() *recordingConn { return &recordingConn{} }

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *recordingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.readFrom) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.readFrom)
	c.readFrom = c.readFrom[n:]
	return n, nil
}

func (c *recordingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *recordingConn) segments() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.writes...)
}

func (c *recordingConn) joined() []byte {
	var out []byte
	for _, w := range c.segments() {
		out = append(out, w...)
	}
	return out
}

func (*recordingConn) LocalAddr() net.Addr              { return nil }
func (*recordingConn) RemoteAddr() net.Addr             { return nil }
func (*recordingConn) SetDeadline(time.Time) error      { return nil }
func (*recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordingConn) SetWriteDeadline(time.Time) error { return nil }

// --- Chain ---

func TestChainEmptyReturnsOriginal(t *testing.T) {
	c := newRecordingConn()
	got, err := Chain(c, nil)
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if got != net.Conn(c) {
		t.Error("Chain with no plugins did not return the original connection")
	}
}

func TestChainNilConn(t *testing.T) {
	if _, err := Chain(nil, []Plugin{TLSFragment{}}); !errors.Is(err, ErrNilConn) {
		t.Errorf("Chain(nil, ...) = %v, want ErrNilConn", err)
	}
}

func TestChainSkipsNilPlugins(t *testing.T) {
	c := newRecordingConn()
	got, err := Chain(c, []Plugin{nil, nil})
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}
	if got != net.Conn(c) {
		t.Error("Chain with only nil plugins did not return the original connection")
	}
}

// TestChainOrderIsInnermostFirst pins the documented composition order. Get
// this backwards and a prefix lands after the bytes it is supposed to precede.
func TestChainOrderIsInnermostFirst(t *testing.T) {
	c := newRecordingConn()

	// TLSFragment first (inner), Prefix second (outer). The prefix is
	// therefore prepended before the fragmenter ever sees the buffer, so the
	// prefix bytes are part of what gets split.
	wrapped, err := Chain(c, []Plugin{
		TLSFragment{SplitAt: 4},
		Prefix{Bytes: []byte("PRE"), Label: "t"},
	})
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}

	if _, err := wrapped.Write([]byte("0123456789")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := string(c.joined())
	if want := "PRE0123456789"; got != want {
		t.Errorf("bytes on the wire = %q, want %q", got, want)
	}
	segs := c.segments()
	if len(segs) != 2 {
		t.Fatalf("got %d segments, want 2 (the fragmenter should have split the prefixed buffer)", len(segs))
	}
	if string(segs[0]) != "PRE0" {
		t.Errorf("first segment = %q, want %q", segs[0], "PRE0")
	}
}

func TestNames(t *testing.T) {
	got := Names([]Plugin{
		TLSFragment{SplitAt: 16},
		nil,
		Prefix{Bytes: []byte("x"), Label: "http-get"},
	})
	want := []string{"tlsfrag(16)", "prefix(http-get)"}
	if len(got) != len(want) {
		t.Fatalf("Names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// --- TLSFragment ---

func TestTLSFragmentSplitsFirstWriteOnly(t *testing.T) {
	c := newRecordingConn()
	conn, err := TLSFragment{SplitAt: 5}.Wrap(c)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if _, err := conn.Write([]byte("0123456789")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if _, err := conn.Write([]byte("second")); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	segs := c.segments()
	if len(segs) != 3 {
		t.Fatalf("got %d segments, want 3 (two from the split first write, one for the second)", len(segs))
	}
	if string(segs[0]) != "01234" {
		t.Errorf("segment 0 = %q, want %q", segs[0], "01234")
	}
	if string(segs[1]) != "56789" {
		t.Errorf("segment 1 = %q, want %q", segs[1], "56789")
	}
	if string(segs[2]) != "second" {
		t.Errorf("segment 2 = %q, want %q; subsequent writes must not be split", segs[2], "second")
	}
}

func TestTLSFragmentShortWriteNotSplit(t *testing.T) {
	c := newRecordingConn()
	conn, _ := TLSFragment{SplitAt: 32}.Wrap(c)

	// Shorter than the offset: there is nothing to split and no SNI to hide.
	if _, err := conn.Write([]byte("short")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if segs := c.segments(); len(segs) != 1 {
		t.Errorf("got %d segments for a short write, want 1", len(segs))
	}
}

func TestTLSFragmentReturnsPayloadByteCount(t *testing.T) {
	c := newRecordingConn()
	conn, _ := TLSFragment{SplitAt: 4}.Wrap(c)

	payload := []byte("0123456789")
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// A wrapper that reported anything other than the caller's byte count
	// would break every io.Copy above it.
	if n != len(payload) {
		t.Errorf("Write returned %d, want %d", n, len(payload))
	}
}

// TestTLSFragmentFallbackOffset covers the non-TLS path: with no SNI to find,
// the plugin must still behave predictably rather than refusing the write.
func TestTLSFragmentFallbackOffset(t *testing.T) {
	t.Run("long non-TLS write splits at the default offset", func(t *testing.T) {
		c := newRecordingConn()
		conn, _ := TLSFragment{}.Wrap(c)
		payload := make([]byte, DefaultTLSSplitOffset*2)
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		segs := c.segments()
		if len(segs) != 2 {
			t.Fatalf("got %d segments, want 2", len(segs))
		}
		if len(segs[0]) != DefaultTLSSplitOffset {
			t.Errorf("first segment is %d bytes, want %d", len(segs[0]), DefaultTLSSplitOffset)
		}
	})

	t.Run("short non-TLS write is not split", func(t *testing.T) {
		c := newRecordingConn()
		conn, _ := TLSFragment{}.Wrap(c)
		if _, err := conn.Write(make([]byte, 8)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if segs := c.segments(); len(segs) != 1 {
			t.Errorf("got %d segments for an 8-byte write, want 1", len(segs))
		}
	})

	t.Run("negative SplitAt falls back to SNI mode", func(t *testing.T) {
		if got := (TLSFragment{SplitAt: -5}).Name(); got != "tlsfrag(sni)" {
			t.Errorf("Name() = %q, want %q", got, "tlsfrag(sni)")
		}
	})
}

// TestTLSFragmentHidesSNIFromFirstSegment is the property the plugin exists
// for, asserted against a realistic ClientHello rather than a toy buffer: no
// single segment may contain the full hostname.
func TestTLSFragmentHidesSNIFromFirstSegment(t *testing.T) {
	const host = "blocked.example.com"
	hello := clientHello(host)

	c := newRecordingConn()
	conn, _ := TLSFragment{}.Wrap(c)
	if _, err := conn.Write(hello); err != nil {
		t.Fatalf("Write: %v", err)
	}

	segs := c.segments()
	if len(segs) < 2 {
		t.Fatalf("ClientHello was sent in %d segment(s); the fragmenter did not split it", len(segs))
	}
	for i, seg := range segs {
		if containsSubstring(seg, []byte(host)) {
			t.Errorf("segment %d contains the complete hostname %q; an SNI matcher inspecting one segment would still see it", i, host)
		}
	}
	// And reassembly must be lossless.
	if string(c.joined()) != string(hello) {
		t.Error("the reassembled stream does not match the original ClientHello")
	}
}

// clientHello builds a structurally valid TLS ClientHello carrying host in
// its SNI extension, with every length field correct.
//
// The lengths matter: findSNI walks them, so a fixture with hand-waved lengths
// would exercise only the fallback path and the test would pass while proving
// nothing. It is not a *complete* handshake — the cipher list is token and
// nothing here speaks TLS — but it is byte-accurate everywhere findSNI looks.
func clientHello(host string) []byte {
	// server_name extension.
	var sni []byte
	sni = append(sni, 0x00)                                     // name_type: host_name
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host))) // host length
	sni = append(sni, host...)

	var sniExtData []byte
	sniExtData = binary.BigEndian.AppendUint16(sniExtData, uint16(len(sni))) // list length
	sniExtData = append(sniExtData, sni...)

	var extensions []byte
	extensions = binary.BigEndian.AppendUint16(extensions, 0x0000) // server_name
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(sniExtData)))
	extensions = append(extensions, sniExtData...)

	// ClientHello body.
	var body []byte
	body = append(body, 0x03, 0x03) // client_version TLS 1.2
	for i := 0; i < 32; i++ {       // client random
		body = append(body, byte(i))
	}
	body = append(body, 0x00)                     // session_id length
	body = binary.BigEndian.AppendUint16(body, 4) // cipher_suites length
	body = append(body, 0x13, 0x01, 0x13, 0x02)   // two suites
	body = append(body, 0x01, 0x00)               // compression: 1 method, null
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	// Handshake header: client_hello, 3-byte length.
	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	// Record header.
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

func containsSubstring(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// --- Prefix ---

func TestPrefixPrependsOnFirstWriteOnly(t *testing.T) {
	c := newRecordingConn()
	conn, err := Prefix{Bytes: []byte("PREFIX"), Label: "t"}.Wrap(c)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	n, err := conn.Write([]byte("first"))
	if err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if n != 5 {
		t.Errorf("first Write returned %d, want 5 (the caller's byte count, not the wire count)", n)
	}
	if _, err := conn.Write([]byte("second")); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	if got, want := string(c.joined()), "PREFIXfirstsecond"; got != want {
		t.Errorf("wire bytes = %q, want %q", got, want)
	}
	// The prefix must share the first segment, not occupy its own tiny one:
	// a 16-byte segment followed by a larger one is the anomaly the prefix
	// exists to remove.
	if segs := c.segments(); string(segs[0]) != "PREFIXfirst" {
		t.Errorf("first segment = %q, want %q", segs[0], "PREFIXfirst")
	}
}

func TestPrefixStripsResponsePrefix(t *testing.T) {
	c := newRecordingConn()
	c.readFrom = []byte("HTTP/1.1 200 OK\r\npayload")

	conn, err := Prefix{
		Bytes:             []byte("GET / HTTP/1.1\r\n"),
		ResponsePrefixLen: len("HTTP/1.1 200 OK\r\n"),
		Label:             "t",
	}.Wrap(c)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("after stripping the response prefix: %q, want %q", got, "payload")
	}
}

func TestPrefixValidation(t *testing.T) {
	c := newRecordingConn()

	t.Run("empty prefix", func(t *testing.T) {
		if _, err := (Prefix{}).Wrap(c); !errors.Is(err, ErrNoPrefix) {
			t.Errorf("Wrap with no bytes = %v, want ErrNoPrefix", err)
		}
	})
	t.Run("oversize prefix", func(t *testing.T) {
		if _, err := (Prefix{Bytes: make([]byte, maxPrefixLen+1)}).Wrap(c); !errors.Is(err, ErrPrefixTooLong) {
			t.Errorf("Wrap with an oversize prefix = %v, want ErrPrefixTooLong", err)
		}
	})
	t.Run("negative response prefix", func(t *testing.T) {
		if _, err := (Prefix{Bytes: []byte("x"), ResponsePrefixLen: -1}).Wrap(c); err == nil {
			t.Error("Wrap with a negative response prefix length = nil, want an error")
		}
	})
	t.Run("nil conn", func(t *testing.T) {
		if _, err := (Prefix{Bytes: []byte("x")}).Wrap(nil); !errors.Is(err, ErrNilConn) {
			t.Errorf("Wrap(nil) = %v, want ErrNilConn", err)
		}
	})
}

func TestPrefixNameDoesNotLeakBytes(t *testing.T) {
	// Plugin parameters are frequently shared secrets, and Name goes into
	// logs. The unlabelled form must report a length, never the bytes.
	p := Prefix{Bytes: []byte("s3cret-prefix-value")}
	if got := p.Name(); containsSubstring([]byte(got), p.Bytes) {
		t.Errorf("Name() = %q, which contains the prefix bytes", got)
	}
}

func TestHTTPGetPrefix(t *testing.T) {
	p := HTTPGetPrefix()
	if len(p.Bytes) == 0 {
		t.Fatal("HTTPGetPrefix has no bytes")
	}
	if p.Name() != "prefix(http-get)" {
		t.Errorf("Name() = %q, want %q", p.Name(), "prefix(http-get)")
	}
	if _, err := p.Wrap(newRecordingConn()); err != nil {
		t.Errorf("Wrap: %v", err)
	}
}

// --- half-close propagation ---

// halfCloseConn records whether CloseWrite reached the bottom of the chain.
type halfCloseConn struct {
	*recordingConn
	mu         sync.Mutex
	closeWrote bool
}

func (c *halfCloseConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeWrote = true
	return nil
}

func (c *halfCloseConn) didCloseWrite() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeWrote
}

// TestHalfClosePropagatesThroughChain is load-bearing for correctness, not
// just tidiness: the userspace stack relies on CloseWrite to avoid truncating
// responses, and a plugin that swallows it silently breaks HTTP/1.0 through
// the tunnel.
func TestHalfClosePropagatesThroughChain(t *testing.T) {
	base := &halfCloseConn{recordingConn: newRecordingConn()}

	wrapped, err := Chain(base, []Plugin{
		TLSFragment{SplitAt: 4},
		Prefix{Bytes: []byte("PRE"), Label: "t"},
	})
	if err != nil {
		t.Fatalf("Chain: %v", err)
	}

	hc, ok := wrapped.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the wrapped connection does not implement CloseWrite; the stack would truncate responses through it")
	}
	if err := hc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !base.didCloseWrite() {
		t.Error("CloseWrite did not reach the underlying connection")
	}
}
