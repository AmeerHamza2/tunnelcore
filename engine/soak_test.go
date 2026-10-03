//go:build soak

package engine

import (
	"context"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// settle lets teardown goroutines exit, then reports the goroutine count and
// live heap after a full GC.
func settle(d time.Duration) (goroutines int, heap uint64) {
	time.Sleep(d)
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return runtime.NumGoroutine(), ms.HeapAlloc
}

// wgServer is a long-lived WireGuard peer that each soak cycle's fresh client
// transport handshakes with. It roams to whichever client endpoint spoke last.
type wgServer struct {
	tr         *wireguard.Transport
	port       int
	clientPriv wireguard.Key
	serverPub  wireguard.Key
}

func newWGServer(t *testing.T) *wgServer {
	t.Helper()
	clientPriv, _ := wireguard.GeneratePrivateKey()
	serverPriv, _ := wireguard.GeneratePrivateKey()
	srv, err := wireguard.New(wireguard.Config{
		Name:          "wireguard/soak-server",
		PrivateKey:    serverPriv,
		PeerPublicKey: clientPriv.PublicKey(),
		Endpoint:      netip.MustParseAddrPort("127.0.0.1:1"),
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		_ = srv.Up(ctx) // returns at the first client handshake; the device stays up
	}()
	var port int
	for deadline := time.Now().Add(5 * time.Second); port == 0 && time.Now().Before(deadline); {
		port = srv.ListenPort()
		time.Sleep(5 * time.Millisecond)
	}
	if port == 0 {
		t.Fatal("WireGuard soak server never bound")
	}
	// Echo whatever arrives, so the engine's inbound path carries traffic.
	go func() {
		buf := make([]byte, 2048)
		for {
			n, err := srv.ReadPacket(buf)
			if err != nil {
				return
			}
			_ = srv.WritePacket(buf[:n])
		}
	}()
	t.Cleanup(func() { _ = srv.Close() })
	return &wgServer{tr: srv, port: port, clientPriv: clientPriv, serverPub: serverPriv.PublicKey()}
}

func (s *wgServer) client(t *testing.T) *wireguard.Transport {
	c, err := wireguard.New(wireguard.Config{
		Name:          "wireguard/soak",
		PrivateKey:    s.clientPriv,
		PeerPublicKey: s.serverPub,
		Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(s.port)),
		AllowedIPs:    []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSoakEngineReconnectCycles drives the engine through hundreds of
// reconnects — network changes and transport deaths, rotating between a
// packet fake, a stream fake (with a live userspace stack) and a real
// wireguard-go client against a real peer — and asserts that goroutines and
// heap come back to baseline. A phone runs the engine for days through
// constant handovers; a per-reconnect leak of even one goroutine is a crash
// eventually.
func TestSoakEngineReconnectCycles(t *testing.T) {
	cycles := 520
	if testing.Short() {
		cycles = 60
	}
	srv := newWGServer(t)

	var (
		mu      sync.Mutex
		current transport.Transport
		attempt int
	)
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{
		Backoff:               &Backoff{Base: time.Millisecond, Max: 2 * time.Millisecond},
		StableSessionDuration: time.Millisecond,
		RaceTimeout:           5 * time.Second,
	}, func() []transport.Transport {
		mu.Lock()
		defer mu.Unlock()
		attempt++
		var tr transport.Transport
		switch attempt % 5 {
		case 0:
			tr = srv.client(t)
		case 1, 3:
			tr = newFakeDialer("stream/soak")
		default:
			tr = newFakePipe("packet/soak")
		}
		current = tr
		return []transport.Transport{tr}
	})
	// Drain whatever the engine writes back to the "OS".
	go func() {
		for {
			select {
			case <-tun.inbound:
			case <-tun.closed:
				return
			}
		}
	}()
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}

	connected := func() transport.Transport {
		var tr transport.Transport
		if !waitFor(20*time.Second, func() bool {
			if e.State() != StateConnected {
				return false
			}
			mu.Lock()
			tr = current
			mu.Unlock()
			return e.Stats().ActiveTransport == tr.Name()
		}) {
			t.Fatalf("not connected; state = %s, last = %s", e.State(), e.LastChange())
		}
		return tr
	}

	var baseG int
	var baseHeap uint64
	var heapAt100 uint64
	port := uint16(20000)
	kinds := map[string]int{}
	for i := 0; i < cycles; i++ {
		tr := connected()
		before := e.Stats().Reconnects
		kinds[tr.Name()]++

		// Some traffic on every session.
		switch v := tr.(type) {
		case *fakePipe:
			tun.send(ipv4UDPPacket("soak"))
			v.deliver(ipv4UDPPacket("reply"))
		case *fakeDialer:
			port++
			tun.send(ipv4TCPSyn(port))
		case *wireguard.Transport:
			tun.send(ipv4UDPPacket("soak-wg"))
		}

		if i%2 == 0 {
			e.NetworkChanged()
		} else {
			switch v := tr.(type) {
			case *fakePipe:
				_ = v.Close()
			case *fakeDialer:
				v.closed.Store(true)
				port++
				tun.send(ipv4TCPSyn(port)) // the failing dial is what reveals it
			case *wireguard.Transport:
				_ = v.Close()
			}
		}
		if !waitFor(20*time.Second, func() bool { return e.Stats().Reconnects > before }) {
			t.Fatalf("cycle %d (%T): no reconnect; state = %s, last = %s", i, tr, e.State(), e.LastChange())
		}

		switch i {
		case 20:
			connected()
			baseG, baseHeap = settle(300 * time.Millisecond)
			t.Logf("baseline after %d cycles: %d goroutines, heap %.1f MiB", i, baseG, float64(baseHeap)/(1<<20))
		case 120:
			connected()
			_, heapAt100 = settle(300 * time.Millisecond)
		}
	}
	connected()
	g, heap := settle(500 * time.Millisecond)
	t.Logf("sessions by transport: %v", kinds)
	if kinds["wireguard/soak"] == 0 || kinds["stream/soak"] == 0 || kinds["packet/soak"] == 0 {
		t.Errorf("not every transport kind was exercised: %v", kinds)
	}
	t.Logf("after %d cycles (%d reconnects): %d goroutines (baseline %d), heap %.1f MiB (baseline %.1f, @120 %.1f)",
		cycles, e.Stats().Reconnects, g, baseG, float64(heap)/(1<<20), float64(baseHeap)/(1<<20), float64(heapAt100)/(1<<20))

	// Tolerance for runtime and fixture goroutines (the live session's own
	// workers differ by transport kind, and wireguard-go's per-CPU workers
	// are the largest set). What this catches is growth with cycle count.
	if g > baseG+40 {
		t.Errorf("goroutines grew from %d to %d over %d cycles", baseG, g, cycles)
	}
	// The heap must not trend upward: compare late against early.
	if heapAt100 > 0 && heap > heapAt100+8<<20 && heap > heapAt100*2 {
		t.Errorf("heap grew from %.1f MiB (cycle 120) to %.1f MiB (cycle %d)",
			float64(heapAt100)/(1<<20), float64(heap)/(1<<20), cycles)
	}

	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
}
