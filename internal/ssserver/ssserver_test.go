package ssserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport/shadowsocks"
)

const testPassword = "0123456789abcdefghijklmnopqrstuv"

var probeTarget = netip.MustParseAddrPort("198.51.100.1:7")

// startServer runs a server whose handler answers the probe target with a
// banner and echoes every other stream back upper-cased.
func startServer(t *testing.T, method shadowsocks.Method) (*Server, chan Target) {
	t.Helper()
	targets := make(chan Target, 16)
	srv, err := Listen(Config{
		Addr:     "127.0.0.1:0",
		Method:   method,
		Password: testPassword,
		Handler: func(tg Target, c net.Conn) {
			targets <- tg
			if tg.Addr == probeTarget {
				_, _ = c.Write([]byte("probe-ok\n"))
				return
			}
			b, _ := io.ReadAll(c)
			_, _ = c.Write([]byte(strings.ToUpper(string(b))))
		},
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, targets
}

func newClient(t *testing.T, srv *Server, method shadowsocks.Method, password string) *shadowsocks.Transport {
	t.Helper()
	tr, err := shadowsocks.New(shadowsocks.Config{
		Name:        "shadowsocks/test",
		Server:      srv.Addr().String(),
		Method:      method,
		Password:    password,
		ProbeTarget: probeTarget,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("shadowsocks.New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// TestInteropWithClient runs the package's client against this independent
// server for every supported cipher, through the probe and a half-closed
// request/response exchange.
func TestInteropWithClient(t *testing.T) {
	for _, m := range shadowsocks.SupportedMethods() {
		method := shadowsocks.Method(m)
		t.Run(m, func(t *testing.T) {
			srv, targets := startServer(t, method)
			tr := newClient(t, srv, method, testPassword)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tr.Up(ctx); err != nil {
				t.Fatalf("Up (probe): %v", err)
			}
			if got := <-targets; got.Addr != probeTarget {
				t.Fatalf("probe target = %v, want %v", got, probeTarget)
			}

			dst := netip.MustParseAddrPort("203.0.113.9:80")
			c, err := tr.DialTCP(ctx, dst)
			if err != nil {
				t.Fatalf("DialTCP: %v", err)
			}
			defer c.Close()
			// A payload larger than one chunk, to exercise chunk splitting in
			// both directions.
			payload := strings.Repeat("abcdefgh", 4096)
			if _, err := c.Write([]byte(payload)); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatalf("CloseWrite: %v", err)
			}
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if string(got) != strings.ToUpper(payload) {
				t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(payload))
			}
			if tg := <-targets; tg.Addr != dst {
				t.Fatalf("target = %v, want %v", tg, dst)
			}
		})
	}
}

// TestWrongPasswordFailsProbe checks that the probe distinguishes a server
// holding a different key, which is the whole point of configuring one.
func TestWrongPasswordFailsProbe(t *testing.T) {
	var authErr = make(chan error, 1)
	srv, err := Listen(Config{
		Addr:     "127.0.0.1:0",
		Method:   shadowsocks.ChaCha20Poly1305,
		Password: testPassword,
		Handler:  func(Target, net.Conn) { t.Error("handler reached with a wrong password") },
		OnError: func(_ net.Addr, err error) {
			select {
			case authErr <- err:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer srv.Close()

	tr := newClient(t, srv, shadowsocks.ChaCha20Poly1305, "a-completely-different-password!")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tr.Up(ctx); err == nil {
		t.Fatal("Up succeeded against a server with a different password")
	}
	select {
	case err := <-authErr:
		if !errors.Is(err, ErrAuth) {
			t.Errorf("server error = %v, want ErrAuth", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("server never reported the authentication failure")
	}
}

// TestCloseTearsDownLiveStreams checks the property the demo relies on to
// simulate an exit node dying.
func TestCloseTearsDownLiveStreams(t *testing.T) {
	srv, _ := startServer(t, shadowsocks.ChaCha20Poly1305)
	tr := newClient(t, srv, shadowsocks.ChaCha20Poly1305, testPassword)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.Up(ctx); err != nil {
		t.Fatalf("Up: %v", err)
	}
	c, err := tr.DialTCP(ctx, netip.MustParseAddrPort("203.0.113.9:80"))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hold")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Give the server a moment to accept and enter the handler.
	time.Sleep(50 * time.Millisecond)

	done := make(chan struct{})
	go func() { _ = srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return while a stream was live")
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 16)); err == nil {
		t.Error("read on a stream to a closed server succeeded")
	}
}
