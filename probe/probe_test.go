package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport/protect"
)

// echoServer answers UDP datagrams. dropEvery > 0 drops every n-th packet;
// delay is added before each reply.
func echoServer(t *testing.T, dropEvery int, delay time.Duration) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 128)
		for i := 1; ; i++ {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if dropEvery > 0 && i%dropEvery == 0 {
				continue
			}
			reply := append([]byte(nil), buf[:n]...)
			go func() {
				time.Sleep(delay)
				_, _ = pc.WriteToUDP(reply, from)
			}()
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func closedUDPPort(t *testing.T) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ap := pc.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = pc.Close()
	return ap
}

func tcpListener(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

var fast = Config{Samples: 6, Interval: 5 * time.Millisecond, Timeout: 300 * time.Millisecond}

func TestUDPEchoReachable(t *testing.T) {
	addr := echoServer(t, 0, 20*time.Millisecond)
	rs, err := Run(context.Background(), fast, []Target{{Name: "fra", Addr: addr, Method: UDPEcho}})
	if err != nil {
		t.Fatal(err)
	}
	r := rs[0]
	if !r.Reachable || r.Loss != 0 {
		t.Fatalf("result = %+v, want reachable with no loss", r)
	}
	if r.Median < 20*time.Millisecond || r.Median > 200*time.Millisecond {
		t.Fatalf("median %v, want about the 20ms server delay", r.Median)
	}
	if r.P95 < r.Median {
		t.Fatalf("p95 %v < median %v", r.P95, r.Median)
	}
}

func TestUDPEchoMeasuresLoss(t *testing.T) {
	addr := echoServer(t, 2, 0) // drops every second packet
	rs, err := Run(context.Background(), fast, []Target{{Name: "lossy", Addr: addr, Method: UDPEcho}})
	if err != nil {
		t.Fatal(err)
	}
	if r := rs[0]; !r.Reachable || r.Loss != 0.5 {
		t.Fatalf("result = %+v, want reachable with loss 0.5", r)
	}
}

func TestUDPDeadServerIsUnreachable(t *testing.T) {
	start := time.Now()
	rs, err := Run(context.Background(), fast, []Target{{Name: "dead", Addr: closedUDPPort(t), Method: UDPEcho}})
	if err != nil {
		t.Fatal(err)
	}
	if r := rs[0]; r.Reachable || r.Loss != 1 || r.Err == "" {
		t.Fatalf("result = %+v, want unreachable with an error", r)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a dead server took %v; it must be bounded by the sample timeout", d)
	}
}

// TestHealthyServerDoesNotWaitOutTimeout: all samples answered means done,
// without sitting on the timeout. A list of 20 servers should feel instant.
func TestHealthyServerDoesNotWaitOutTimeout(t *testing.T) {
	addr := echoServer(t, 0, 0)
	cfg := Config{Samples: 3, Interval: time.Millisecond, Timeout: 5 * time.Second}
	start := time.Now()
	if _, err := Run(context.Background(), cfg, []Target{{Name: "x", Addr: addr, Method: UDPEcho}}); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("took %v with a 5s timeout; should return as soon as all echoes arrive", d)
	}
}

func TestStrayRepliesIgnored(t *testing.T) {
	// A server that answers with garbage of the right length never matches a
	// nonce, so it must read as unreachable, not as a fast server.
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			_, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(make([]byte, nonceLen), from)
		}
	}()
	rs, _ := Run(context.Background(), fast, []Target{{Name: "liar", Addr: pc.LocalAddr().(*net.UDPAddr).AddrPort(), Method: UDPEcho}})
	if rs[0].Reachable {
		t.Fatalf("garbage replies counted as reachable: %+v", rs[0])
	}
}

func TestTCPConnect(t *testing.T) {
	rs, err := Run(context.Background(), fast, []Target{{Name: "ss", Addr: tcpListener(t), Method: TCPConnect}})
	if err != nil {
		t.Fatal(err)
	}
	if r := rs[0]; !r.Reachable || r.Loss != 0 || r.Median <= 0 {
		t.Fatalf("result = %+v", r)
	}
}

func TestSortedBestFirst(t *testing.T) {
	slow := echoServer(t, 0, 60*time.Millisecond)
	quick := echoServer(t, 0, 0)
	rs, err := Run(context.Background(), fast, []Target{
		{Name: "dead", Addr: closedUDPPort(t), Method: UDPEcho},
		{Name: "slow", Addr: slow, Method: UDPEcho},
		{Name: "quick", Addr: quick, Method: UDPEcho},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rs[0].Name != "quick" || rs[1].Name != "slow" || rs[2].Name != "dead" {
		t.Fatalf("order = %s, %s, %s; want quick, slow, dead", rs[0].Name, rs[1].Name, rs[2].Name)
	}
}

// TestProbeSocketsAreProtected: on Android an unprotected probe socket would
// be routed into the tunnel and measure the tunnel, not the path.
func TestProbeSocketsAreProtected(t *testing.T) {
	var n atomic.Int32
	cfg := fast
	cfg.Protect = func(int) error { n.Add(1); return nil }
	if _, err := Run(context.Background(), cfg, []Target{
		{Name: "u", Addr: echoServer(t, 0, 0), Method: UDPEcho},
		{Name: "t", Addr: tcpListener(t), Method: TCPConnect},
	}); err != nil {
		t.Fatal(err)
	}
	// One UDP socket, plus one TCP socket per sample.
	if got, want := n.Load(), int32(1+cfg.Samples); got != want {
		t.Fatalf("protect called %d times, want %d", got, want)
	}

	cfg.Protect = protect.FromBool(func(int) bool { return false })
	rs, _ := Run(context.Background(), cfg, []Target{{Name: "u", Addr: echoServer(t, 0, 0), Method: UDPEcho}})
	if rs[0].Reachable {
		t.Fatal("an unprotectable socket was used anyway")
	}
}

func TestContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, fast, []Target{{Name: "x", Addr: echoServer(t, 0, 0), Method: UDPEcho}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestNoTargets(t *testing.T) {
	if _, err := Run(context.Background(), fast, nil); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("err = %v", err)
	}
}

func TestPercentiles(t *testing.T) {
	ms := func(v ...int) []time.Duration {
		out := make([]time.Duration, len(v))
		for i, x := range v {
			out[i] = time.Duration(x) * time.Millisecond
		}
		return out
	}
	med, p95 := percentiles(ms(50, 10, 30, 20, 40))
	if med != 30*time.Millisecond || p95 != 50*time.Millisecond {
		t.Fatalf("median %v p95 %v", med, p95)
	}
	med, p95 = percentiles(ms(7))
	if med != 7*time.Millisecond || p95 != 7*time.Millisecond {
		t.Fatalf("single sample: median %v p95 %v", med, p95)
	}
}
