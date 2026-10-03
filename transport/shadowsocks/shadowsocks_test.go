package shadowsocks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport"
	"github.com/ameerhamza2/tunnelcore/transport/obfs"
)

func TestConfigValidate(t *testing.T) {
	base := Config{
		Server:   "example.com:8388",
		Method:   AES256GCM,
		Password: testPassword,
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"valid", func(*Config) {}, nil},
		{"no server", func(c *Config) { c.Server = "" }, ErrNoServer},
		{"server without port", func(c *Config) { c.Server = "example.com" }, nil},
		{"no password", func(c *Config) { c.Password = "" }, ErrNoPassword},
		{"short password", func(c *Config) { c.Password = "hunter2" }, ErrWeakPassword},
		{"unknown method", func(c *Config) { c.Method = "rc4-md5" }, ErrUnknownMethod},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			err := cfg.Validate()
			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Validate = %v, want %v", err, tt.wantErr)
				}
			case tt.name == "server without port":
				if err == nil {
					t.Error("Validate = nil, want an error for a server without a port")
				}
			default:
				if err != nil {
					t.Errorf("Validate = %v, want nil", err)
				}
			}
		})
	}
}

// TestRoundTripAllMethods is the core protocol test: for every supported
// cipher, a proxied connection must carry bytes to a separately-implemented
// server and back.
func TestRoundTripAllMethods(t *testing.T) {
	for _, method := range []Method{AES128GCM, AES256GCM, ChaCha20Poly1305} {
		t.Run(string(method), func(t *testing.T) {
			srv := newTestServer(t, method, testPassword, echoHandler)
			tr := newTestTransport(t, srv, Config{Method: method})
			upTransport(t, tr)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			conn, err := tr.DialTCP(ctx, testTarget)
			if err != nil {
				t.Fatalf("DialTCP: %v", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte("hello shadowsocks")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			buf := make([]byte, 64)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if got, want := string(buf[:n]), "HELLO SHADOWSOCKS"; got != want {
				t.Errorf("echo = %q, want %q", got, want)
			}

			// The server must have been told the original destination.
			reqs := srv.seenRequests()
			if len(reqs) != 1 {
				t.Fatalf("server saw %d requests, want 1", len(reqs))
			}
			if reqs[0].Addr != testTarget {
				t.Errorf("server saw target %v, want %v", reqs[0].Addr, testTarget)
			}
		})
	}
}

// TestRoundTripLargePayloadSpansChunks pushes more than one maximum-size chunk
// through, which is where the nonce sequencing and the length-block framing
// are actually exercised. A client that fails to increment the nonce per seal
// round-trips a single small write fine and fails here.
func TestRoundTripLargePayloadSpansChunks(t *testing.T) {
	const size = maxChunkPayload*3 + 1234
	payload := strings.Repeat("ab", size/2)

	srv := newTestServer(t, AES256GCM, testPassword, func(_ parsedAddr, conn net.Conn) {
		// Read exactly len(payload) bytes, then write them back.
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = conn.Write(buf)
	})
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := tr.DialTCP(ctx, testTarget)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := io.WriteString(conn, payload)
		errCh <- err
	}()

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull of %d bytes: %v", len(payload), err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if string(got) != payload {
		t.Errorf("payload did not survive a multi-chunk round trip (%d bytes)", len(payload))
	}
}

// TestShortReadBufferKeepsRemainder covers the leftover path: a chunk larger
// than the caller's buffer must be delivered across successive Reads, not
// truncated.
func TestShortReadBufferKeepsRemainder(t *testing.T) {
	const msg = "0123456789abcdefghijklmnopqrstuvwxyz"

	srv := newTestServer(t, AES256GCM, testPassword, func(_ parsedAddr, conn net.Conn) {
		// Wait for the client's probe byte, then send the whole message in
		// one chunk.
		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		_, _ = io.WriteString(conn, msg)
	})
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.DialTCP(ctx, testTarget)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	// Read 7 bytes at a time: the server's single chunk is 36 bytes.
	var assembled []byte
	small := make([]byte, 7)
	for len(assembled) < len(msg) {
		n, err := conn.Read(small)
		if err != nil {
			t.Fatalf("Read after %d bytes: %v", len(assembled), err)
		}
		if n == 0 {
			t.Fatal("Read returned 0 bytes with no error")
		}
		assembled = append(assembled, small[:n]...)
	}
	if string(assembled) != msg {
		t.Errorf("assembled %q, want %q", assembled, msg)
	}
}

// TestWrongPasswordFailsAuthentication is the property that makes the AEAD
// worth anything: a client with the wrong key cannot read the server's stream.
func TestWrongPasswordFailsAuthentication(t *testing.T) {
	srv := newTestServer(t, AES256GCM, testPassword, echoHandler)

	tr := newTestTransport(t, srv, Config{
		Password: "wrongwrongwrongwrongwrongwrong!!",
	})
	upTransport(t, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.DialTCP(ctx, testTarget)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	// The write succeeds — there is no handshake to reject it — but the
	// server cannot decrypt it, so nothing comes back and no read can
	// authenticate.
	_, _ = conn.Write([]byte("hello"))
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if n, err := conn.Read(make([]byte, 64)); err == nil {
		t.Errorf("Read returned %d bytes with the wrong password, want an error", n)
	}

	if reqs := srv.seenRequests(); len(reqs) != 0 {
		t.Errorf("server decoded %d requests from a wrong-key client, want 0", len(reqs))
	}
}

// TestTamperedChunkIsRejected confirms the AEAD actually authenticates:
// flipping one ciphertext bit must produce ErrAuthFailed rather than corrupt
// plaintext.
func TestTamperedChunkIsRejected(t *testing.T) {
	ciph, err := NewCipher(AES256GCM, testPassword)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	// Seal a stream through a streamConn writing into a buffer.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	out := newStreamConn(client, ciph)
	go func() {
		_, _ = out.Write([]byte("authenticated payload"))
	}()

	raw := make([]byte, 256)
	n, err := server.Read(raw)
	if err != nil {
		t.Fatalf("reading the sealed stream: %v", err)
	}
	framed := raw[:n]

	// Flip a bit inside the payload ciphertext, past the salt and the length
	// block.
	tamperAt := ciph.SaltSize() + 2 + ciph.Overhead() + 3
	if tamperAt >= len(framed) {
		t.Fatalf("framed stream is only %d bytes; cannot tamper at %d", len(framed), tamperAt)
	}
	framed[tamperAt] ^= 0x01

	// Feed the tampered stream to a reader.
	rp, wp := net.Pipe()
	defer rp.Close()
	go func() {
		_, _ = wp.Write(framed)
		_ = wp.Close()
	}()

	in := newStreamConn(rp, ciph)
	if _, err := in.Read(make([]byte, 256)); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("Read of a tampered stream = %v, want ErrAuthFailed", err)
	}
}

// TestOversizeChunkLengthIsRejected covers the 0x3fff cap. A malicious or
// broken server must not be able to make the client accept a length the
// format forbids.
func TestOversizeChunkLengthIsRejected(t *testing.T) {
	ciph, err := NewCipher(AES256GCM, testPassword)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	salt := make([]byte, ciph.SaltSize())
	for i := range salt {
		salt[i] = byte(i)
	}
	aead, err := ciph.AEAD(salt)
	if err != nil {
		t.Fatalf("AEAD: %v", err)
	}

	// A correctly-sealed length block declaring 0xffff, which exceeds the cap.
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], 0xffff)
	framed := append([]byte{}, salt...)
	framed = aead.Seal(framed, make([]byte, aead.NonceSize()), lenBuf[:], nil)

	rp, wp := net.Pipe()
	defer rp.Close()
	go func() {
		_, _ = wp.Write(framed)
	}()

	in := newStreamConn(rp, ciph)
	_, err = in.Read(make([]byte, 64))
	if !errors.Is(err, ErrChunkTooLarge) {
		t.Errorf("Read of an oversize chunk length = %v, want ErrChunkTooLarge", err)
	}
}

func TestDialBeforeUp(t *testing.T) {
	srv := newTestServer(t, AES256GCM, testPassword, echoHandler)
	tr := newTestTransport(t, srv, Config{})

	ctx := context.Background()
	if _, err := tr.DialTCP(ctx, testTarget); !errors.Is(err, transport.ErrNotReady) {
		t.Errorf("DialTCP before Up = %v, want ErrNotReady", err)
	}
	if _, err := tr.DialUDP(ctx, testTarget); !errors.Is(err, transport.ErrNotReady) {
		t.Errorf("DialUDP before Up = %v, want ErrNotReady", err)
	}
}

func TestDialAfterClose(t *testing.T) {
	srv := newTestServer(t, AES256GCM, testPassword, echoHandler)
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := tr.DialTCP(context.Background(), testTarget); !errors.Is(err, transport.ErrClosed) {
		t.Errorf("DialTCP after Close = %v, want ErrClosed", err)
	}
}

func TestUpOnUnreachableServer(t *testing.T) {
	// Bind and release a port so nothing is listening on it.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	tr, err := New(Config{
		Server:      addr,
		Method:      AES256GCM,
		Password:    testPassword,
		DialTimeout: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tr.Up(ctx); err == nil {
		t.Error("Up against a closed port = nil, want an error")
	}
}

// TestUpProbeDetectsWrongPassword is the point of ProbeTarget: without it, Up
// cannot tell a server with a rotated password from a working one.
func TestUpProbeDetectsWrongPassword(t *testing.T) {
	// The server greets immediately so a correctly-keyed probe succeeds.
	srv := newTestServer(t, AES256GCM, testPassword, func(_ parsedAddr, conn net.Conn) {
		_, _ = conn.Write([]byte("ok"))
	})

	t.Run("correct password probes successfully", func(t *testing.T) {
		tr := newTestTransport(t, srv, Config{ProbeTarget: testTarget})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tr.Up(ctx); err != nil {
			t.Errorf("Up with the right password = %v, want nil", err)
		}
	})

	t.Run("wrong password fails the probe", func(t *testing.T) {
		tr := newTestTransport(t, srv, Config{
			Password:    "wrongwrongwrongwrongwrongwrong!!",
			ProbeTarget: testTarget,
			DialTimeout: 2 * time.Second,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := tr.Up(ctx)
		if err == nil {
			t.Fatal("Up with the wrong password = nil, want an error")
		}
		if !errors.Is(err, ErrProbeFailed) && !errors.Is(err, ErrProbeNoReply) {
			t.Errorf("Up error = %v, want ErrProbeFailed or ErrProbeNoReply", err)
		}
	})
}

func TestUpIsIdempotent(t *testing.T) {
	srv := newTestServer(t, AES256GCM, testPassword, echoHandler)
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)
	upTransport(t, tr)
}

// TestRoundTripThroughObfsChain runs the same echo test with obfuscation
// plugins in place. The server is configured with the matching prefix, so a
// successful round trip proves the chain is transparent to the protocol.
func TestRoundTripThroughObfsChain(t *testing.T) {
	prefix := []byte("GET / HTTP/1.1\r\n")

	// The server strips the prefix before its Shadowsocks reader sees the
	// stream, which is where the server half of the plugin sits.
	srv := newTestServerWithPrefix(t, AES256GCM, testPassword, prefix, echoHandler)

	tr := newTestTransport(t, srv, Config{
		Plugins: []obfs.Plugin{
			obfs.TLSFragment{SplitAt: 8},
			obfs.Prefix{Bytes: prefix, Label: "http-get"},
		},
	})
	upTransport(t, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.DialTCP(ctx, testTarget)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("obfuscated")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got, want := string(buf[:n]), "OBFUSCATED"; got != want {
		t.Errorf("echo through the obfs chain = %q, want %q", got, want)
	}
}

func TestUDPRoundTrip(t *testing.T) {
	srv := newTestUDPServer(t, AES256GCM, testPassword)
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := tr.DialUDP(ctx, testTarget)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer session.Close()

	if _, err := session.WriteTo([]byte("datagram"), testTarget); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	buf := make([]byte, 128)
	n, from, err := session.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if got, want := string(buf[:n]), "datagram"; got != want {
		t.Errorf("echo = %q, want %q", got, want)
	}
	if from != testTarget {
		t.Errorf("ReadFrom reported %v, want %v", from, testTarget)
	}

	reqs := srv.seenRequests()
	if len(reqs) != 1 || reqs[0].Addr != testTarget {
		t.Errorf("server saw %v, want one request for %v", reqs, testTarget)
	}
}

func TestUDPOversizePayloadRejected(t *testing.T) {
	srv := newTestUDPServer(t, AES256GCM, testPassword)
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)

	session, err := tr.DialUDP(context.Background(), testTarget)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer session.Close()

	if _, err := session.WriteTo(make([]byte, maxUDPPayload+1), testTarget); !errors.Is(err, ErrUDPTooLarge) {
		t.Errorf("WriteTo with an oversize payload = %v, want ErrUDPTooLarge", err)
	}
}

func BenchmarkStreamWrite(b *testing.B) {
	ciph, err := NewCipher(AES256GCM, testPassword)
	if err != nil {
		b.Fatal(err)
	}
	conn := newStreamConn(discardConn{}, ciph)
	payload := make([]byte, 1400)

	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

// discardConn is a net.Conn that swallows writes, so the benchmark measures
// framing and encryption rather than the loopback stack.
type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error) { return len(p), nil }
func (discardConn) Close() error                { return nil }

// TestUDPOversizeDatagramDropped: a datagram larger than the receive buffer
// arrives truncated, so it cannot be authenticated. It must be dropped and the
// session must keep working — before, the read failed and the userspace stack
// tore the whole flow down over one oversized packet.
func TestUDPOversizeDatagramDropped(t *testing.T) {
	srv := newTestUDPServer(t, ChaCha20Poly1305, testPassword)
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)

	sess, err := tr.DialUDP(context.Background(), testTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if _, err := sess.WriteTo(make([]byte, maxUDPRecvPayload+1000), testTarget); err != nil {
		t.Fatalf("WriteTo (large): %v", err)
	}
	time.Sleep(50 * time.Millisecond) // keep the two echoes in order
	if _, err := sess.WriteTo([]byte("small"), testTarget); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _, err := sess.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after an oversized datagram: %v", err)
	}
	if string(buf[:n]) != "small" {
		t.Fatalf("got %q, want the small datagram", buf[:n])
	}
	if got := sess.(*udpSession).oversize.Load(); got != 1 {
		t.Errorf("oversize drops = %d, want 1", got)
	}
}

// TestUDPSessionMemory is the regression test for every UDP session
// allocating 2 x 64 KiB of buffers up front. dnsproxy opens one per lookup and
// the userspace stack keeps up to a thousand, so that was ~130 KiB of garbage
// per DNS query and up to ~130 MiB resident on a phone.
func TestUDPSessionMemory(t *testing.T) {
	for _, m := range SupportedMethods() {
		c, err := NewCipher(Method(m), testPassword)
		if err != nil {
			t.Fatal(err)
		}
		if c.SaltSize() > maxSaltSize || c.Overhead() > maxTagSize {
			t.Fatalf("%s: salt %d / tag %d exceed the pooled buffer's sizing", m, c.SaltSize(), c.Overhead())
		}
	}
	srv := newTestUDPServer(t, AES256GCM, testPassword)
	tr := newTestTransport(t, srv, Config{})
	upTransport(t, tr)

	const sessions = 100
	run := func() {
		sess, err := tr.DialUDP(context.Background(), testTarget)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.WriteTo([]byte("dns query"), testTarget); err != nil {
			t.Fatal(err)
		}
		if _, _, err := sess.ReadFrom(make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
		_ = sess.Close()
	}
	run() // warm the pool
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < sessions; i++ {
		run()
	}
	runtime.ReadMemStats(&after)
	perSession := (after.TotalAlloc - before.TotalAlloc) / sessions
	t.Logf("%d bytes allocated per UDP session (query + reply)", perSession)
	if perSession > 64<<10 { // was ~150 KiB: two 64 KiB buffers per session
		t.Errorf("each UDP session allocates %d bytes; want well under the old 130 KiB", perSession)
	}
}
