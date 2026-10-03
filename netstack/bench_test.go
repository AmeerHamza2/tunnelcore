package netstack

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// BenchmarkStackTCPThroughput measures one bulk TCP flow from an app-side
// userspace stack, through the Stack under test (termination, splice and
// re-origination), to a loopback sink: the whole Shadowsocks-path data plane
// minus the cipher. b.SetBytes makes the result read as MB/s.
func BenchmarkStackTCPThroughput(b *testing.B) {
	for _, dir := range []string{"upload", "download"} {
		b.Run(dir, func(b *testing.B) { benchTCP(b, dir == "upload") })
	}
}

func benchTCP(b *testing.B, upload bool) {
	const chunk = 64 << 10
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	total := int64(b.N) * chunk
	done := make(chan int64, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- -1
			return
		}
		defer c.Close()
		if upload {
			n, _ := io.Copy(io.Discard, c)
			done <- n
			return
		}
		buf := make([]byte, chunk)
		var n int64
		for n < total {
			w, err := c.Write(buf)
			n += int64(w)
			if err != nil {
				break
			}
		}
		_ = c.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, c)
		done <- n
	}()

	dialer := newFakeDialer()
	addr := ln.Addr().String()
	dialer.onTCP = func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	ns, err := New(Config{Dialer: dialer, MTU: testMTU})
	if err != nil {
		b.Fatal(err)
	}
	defer ns.Close()
	peer := newTestPeer(b, tunnelAddr, testMTU, ns)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := peer.dialTCP(ctx, remoteHTTP)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, chunk)
	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	if upload {
		for i := 0; i < b.N; i++ {
			if _, err := conn.Write(buf); err != nil {
				b.Fatal(err)
			}
		}
		_ = conn.(interface{ CloseWrite() error }).CloseWrite()
		if n := <-done; n != total {
			b.Fatalf("sink received %d bytes, want %d", n, total)
		}
	} else {
		n, err := io.Copy(io.Discard, conn)
		if err != nil || n != total {
			b.Fatalf("received %d bytes (%v), want %d", n, err, total)
		}
		_ = conn.(interface{ CloseWrite() error }).CloseWrite()
		<-done
	}
	b.StopTimer()
}
