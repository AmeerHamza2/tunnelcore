//go:build soak

package ssserver

import (
	"context"
	"crypto/sha256"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport/shadowsocks"
)

// Soak target ports select the server's behaviour per stream.
const (
	portEcho        = 7    // echo until the client half-closes, then half-close
	portServerFirst = 25   // send a banner first (server-speaks-first), then echo
	portSink        = 9    // read everything, reply with its SHA-256, close
	bannerLen       = 1000 // bytes in the server-first banner
)

// TestSoakShadowsocksConcurrentStreams runs 200 concurrent streams per cipher
// through the real client transport against the independent server in this
// package: random payload sizes spanning many chunks, random write sizes,
// half-closes, and server-speaks-first streams (which exercise the client's
// header-flush path). Every byte is checked, and the process must return to
// its baseline goroutine count afterwards.
func TestSoakShadowsocksConcurrentStreams(t *testing.T) {
	streams := 200
	if testing.Short() {
		streams = 40
	}
	for _, m := range []shadowsocks.Method{shadowsocks.ChaCha20Poly1305, shadowsocks.AES256GCM, shadowsocks.AES128GCM} {
		t.Run(string(m), func(t *testing.T) { soakSS(t, m, streams) })
	}
}

func soakSS(t *testing.T, method shadowsocks.Method, streams int) {
	runtime.GC()
	baseG := runtime.NumGoroutine()

	srv, err := Listen(Config{
		Addr: "127.0.0.1:0", Method: method, Password: testPassword,
		Handler: func(tg Target, c net.Conn) {
			switch tg.Addr.Port() {
			case portServerFirst:
				banner := make([]byte, bannerLen)
				for i := range banner {
					banner[i] = byte(i)
				}
				if _, err := c.Write(banner); err != nil {
					return
				}
				fallthrough
			case portEcho:
				_, _ = io.Copy(c, c)
				_ = c.(interface{ CloseWrite() error }).CloseWrite()
			case portSink:
				h := sha256.New()
				_, _ = io.Copy(h, c)
				_, _ = c.Write(h.Sum(nil))
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	tr, err := shadowsocks.New(shadowsocks.Config{
		Name: "shadowsocks/soak", Server: srv.Addr().String(), Method: method,
		Password: testPassword, DialTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := tr.Up(ctx); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var bad, moved atomic.Int64
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(i) * 7919))
			// Sizes from 0 to ~256 KiB: zero, sub-chunk, exactly one chunk
			// (0x3fff), and many chunks.
			var size int
			switch i % 5 {
			case 0:
				size = 0
			case 1:
				size = 0x3fff
			default:
				size = rng.Intn(256 << 10)
			}
			payload := make([]byte, size)
			rng.Read(payload)
			port := []uint16{portEcho, portServerFirst, portSink}[i%3]
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), port)

			c, err := tr.DialTCP(ctx, dst)
			if err != nil {
				bad.Add(1)
				t.Errorf("stream %d: dial: %v", i, err)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Minute))

			readBuf := make([]byte, 1+rng.Intn(64<<10))
			wrng := rand.New(rand.NewSource(rng.Int63()))

			// Writer: random write sizes, then a half-close.
			werr := make(chan error, 1)
			go func() {
				p := payload
				for len(p) > 0 {
					n := 1 + wrng.Intn(40000)
					if n > len(p) {
						n = len(p)
					}
					if _, err := c.Write(p[:n]); err != nil {
						werr <- err
						return
					}
					p = p[n:]
				}
				werr <- c.(interface{ CloseWrite() error }).CloseWrite()
			}()

			// Reader: random read sizes.
			var got []byte
			buf := readBuf
			for {
				n, err := c.Read(buf)
				got = append(got, buf[:n]...)
				if err == io.EOF {
					break
				}
				if err != nil {
					bad.Add(1)
					t.Errorf("stream %d: read after %d bytes: %v", i, len(got), err)
					return
				}
			}
			if err := <-werr; err != nil {
				bad.Add(1)
				t.Errorf("stream %d: write: %v", i, err)
				return
			}

			var want []byte
			switch port {
			case portEcho:
				want = payload
			case portServerFirst:
				want = make([]byte, bannerLen, bannerLen+len(payload))
				for j := range want {
					want[j] = byte(j)
				}
				want = append(want, payload...)
			case portSink:
				sum := sha256.Sum256(payload)
				want = sum[:]
			}
			if sha256.Sum256(got) != sha256.Sum256(want) {
				bad.Add(1)
				t.Errorf("stream %d (port %d): got %d bytes, want %d; content differs", i, port, len(got), len(want))
				return
			}
			moved.Add(int64(len(payload) + len(got)))
		}(i)
	}
	wg.Wait()
	t.Logf("%d streams, %.1f MiB through the AEAD framing, %d failures", streams, float64(moved.Load())/(1<<20), bad.Load())

	_ = tr.Close()
	_ = srv.Close()
	var g int
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		runtime.GC()
		if g = runtime.NumGoroutine(); g <= baseG+2 {
			return
		}
	}
	t.Errorf("goroutines %d -> %d after closing every stream", baseG, g)
}
