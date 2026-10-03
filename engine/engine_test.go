package engine

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/metrics"
	"github.com/ameerhamza2/tunnelcore/transport"
)

const testMTU = 1420

var tunnelAddrs = []netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")}

// newTestEngine builds an engine with a fake tun and a provider returning the
// given candidates on every attempt.
func newTestEngine(t *testing.T, tun *fakeTun, cfg Config, candidates func() []transport.Transport) *Engine {
	t.Helper()
	if cfg.Tun == nil {
		cfg.Tun = tun
	}
	if cfg.Provider == nil {
		cfg.Provider = ProviderFunc(func(context.Context) ([]transport.Transport, error) {
			return candidates(), nil
		})
	}
	if cfg.TunnelAddresses == nil {
		cfg.TunnelAddresses = tunnelAddrs
	}
	if cfg.Backoff == nil {
		// Keep the suite fast; the backoff maths is tested separately.
		cfg.Backoff = &Backoff{Base: time.Millisecond, Max: 5 * time.Millisecond}
	}
	if cfg.RaceStagger == 0 {
		cfg.RaceStagger = -1 // start candidates together
	}
	if cfg.RaceTimeout == 0 {
		cfg.RaceTimeout = 2 * time.Second
	}

	e, err := New(cfg)
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	return e
}

func TestNewValidation(t *testing.T) {
	t.Run("no tun", func(t *testing.T) {
		_, err := New(Config{Provider: ProviderFunc(func(context.Context) ([]transport.Transport, error) {
			return nil, nil
		})})
		if !errors.Is(err, ErrNoTun) {
			t.Errorf("New = %v, want ErrNoTun", err)
		}
	})
	t.Run("no provider", func(t *testing.T) {
		if _, err := New(Config{Tun: newFakeTun(testMTU)}); !errors.Is(err, ErrNoProvider) {
			t.Errorf("New = %v, want ErrNoProvider", err)
		}
	})
}

func TestStartReachesConnected(t *testing.T) {
	tun := newFakeTun(testMTU)
	pipe := newFakePipe("wireguard/test")

	var changes []Change
	var mu sync.Mutex
	e := newTestEngine(t, tun, Config{
		OnStateChange: func(c Change) {
			mu.Lock()
			changes = append(changes, c)
			mu.Unlock()
		},
	}, func() []transport.Transport { return []transport.Transport{pipe} })

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("engine never reached StateConnected; state = %s, last = %s", e.State(), e.LastChange())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(changes) < 2 {
		t.Fatalf("got %d state changes, want at least 2", len(changes))
	}
	if changes[0].To != StateConnecting {
		t.Errorf("first transition was to %s, want connecting", changes[0].To)
	}
	last := changes[len(changes)-1]
	if last.To != StateConnected || last.Transport != "wireguard/test" {
		t.Errorf("last transition = %s, want connected via wireguard/test", last)
	}
}

func TestStartIsNotIdempotent(t *testing.T) {
	tun := newFakeTun(testMTU)
	pipe := newFakePipe("wg")
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{pipe}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := e.Start(); !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("second Start = %v, want ErrAlreadyRunning", err)
	}
}

// TestPacketPathCarriesTrafficBothWays exercises the packet-transport data
// path end to end through the engine.
func TestPacketPathCarriesTrafficBothWays(t *testing.T) {
	tun := newFakeTun(testMTU)
	pipe := newFakePipe("wg")
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{pipe}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	// Outbound: the OS writes into the tunnel, the transport must see it.
	out := ipv4UDPPacket("outbound")
	tun.send(out)
	select {
	case got := <-pipe.written:
		if len(got) != len(out) {
			t.Errorf("transport got a %d-byte packet, want %d", len(got), len(out))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the outbound packet never reached the transport")
	}

	// Inbound: the transport's peer sends, the OS must see it.
	in := ipv4UDPPacket("inbound")
	pipe.deliver(in)
	select {
	case got := <-tun.inbound:
		if len(got) != len(in) {
			t.Errorf("tunnel got a %d-byte packet, want %d", len(got), len(in))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the inbound packet never reached the tunnel")
	}

	st := e.Stats()
	if st.PacketsOut == 0 || st.PacketsIn == 0 {
		t.Errorf("counters not updated: in=%d out=%d", st.PacketsIn, st.PacketsOut)
	}
}

// TestStreamPathCarriesTraffic checks that a stream transport brings up the
// userspace stack rather than the packet loop.
func TestStreamPathCarriesTraffic(t *testing.T) {
	tun := newFakeTun(testMTU)
	dialer := newFakeDialer("shadowsocks/test")
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{dialer}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("never connected; last = %s", e.LastChange())
	}
	if got := e.Stats().ActiveTransport; got != "shadowsocks/test" {
		t.Errorf("ActiveTransport = %q, want shadowsocks/test", got)
	}

	// Feeding a packet in must not error, and must be accepted by the stack.
	tun.send(ipv4UDPPacket("to the stack"))
	if !waitFor(2*time.Second, func() bool { return e.Stats().PacketsOut > 0 }) {
		t.Error("no outbound packet was counted on the stream path")
	}
}

// TestReconnectAfterTransportFailure is the behaviour a mobile VPN lives or
// dies by: the transport dies mid-session and the engine must notice and
// rebuild without intervention.
func TestReconnectAfterTransportFailure(t *testing.T) {
	tun := newFakeTun(testMTU)

	var created atomic.Int32
	var mu sync.Mutex
	var pipes []*fakePipe

	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		p := newFakePipe("wg")
		created.Add(1)
		mu.Lock()
		pipes = append(pipes, p)
		mu.Unlock()
		return []transport.Transport{p}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	mu.Lock()
	first := pipes[0]
	mu.Unlock()

	// Kill the transport under the engine. Closing it makes ReadPacket
	// return, which is the signal the inbound loop reports as a failure.
	_ = first.Close()

	if !waitFor(5*time.Second, func() bool { return e.Stats().Reconnects >= 1 }) {
		t.Fatalf("engine never reconnected; state = %s, last = %s", e.State(), e.LastChange())
	}
	if !waitFor(5*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("engine did not return to connected; state = %s, last = %s", e.State(), e.LastChange())
	}
	if created.Load() < 2 {
		t.Errorf("the provider was asked for candidates %d times, want at least 2: "+
			"a reconnect must re-fetch, because the control plane may have changed the server list",
			created.Load())
	}
}

// TestNetworkChangedTriggersImmediateReconnect: a handover is not a failure,
// so it must not be backed off. Backing off here is what makes a VPN take
// seconds to recover from walking out of wifi range.
func TestNetworkChangedTriggersImmediateReconnect(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{
		// A backoff long enough that an immediate reconnect is
		// distinguishable from a backed-off one.
		Backoff: &Backoff{Base: 3 * time.Second, Max: 3 * time.Second},
	}, func() []transport.Transport {
		return []transport.Transport{newFakePipe("wg")}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	start := time.Now()
	e.NetworkChanged()

	if !waitFor(3*time.Second, func() bool {
		return e.Stats().Reconnects >= 1 && e.State() == StateConnected
	}) {
		t.Fatalf("no reconnect after NetworkChanged; state = %s", e.State())
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("reconnect after a network change took %s; the backoff was applied to a handover", elapsed)
	}
}

// TestNetworkChangedIsCoalesced: an OS emits several notifications per
// handover, and reconnecting once per notification would thrash.
//
// The burst is delivered while the engine is provably inside one reconnect,
// blocked fetching candidates. An earlier version fired twenty notifications
// in a tight loop and allowed at most three reconnects. On a loaded 2-CPU box
// the loop was preempted between calls, the engine finished a sub-millisecond
// fake reconnect in each gap, and the test failed ("4 reconnects") although
// coalescing worked. What the engine promises is narrower than "a loop is
// atomic": notifications that arrive while one is already pending are merged,
// and one that arrives during a connect is honoured once afterwards, since
// that connect may have bound sockets to the network that just went away.
func TestNetworkChangedIsCoalesced(t *testing.T) {
	tun := newFakeTun(testMTU)
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		if calls.Add(1) == 2 { // the reconnect triggered by the first notification
			close(entered)
			<-release
		}
		return []transport.Transport{newFakePipe("wg")}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	e.NetworkChanged()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the first notification did not start a reconnect")
	}
	for i := 0; i < 19; i++ {
		e.NetworkChanged() // all during the same connect: one pending signal
	}
	close(release)

	// Exactly one more reconnect for the nineteen, then nothing.
	if !waitFor(3*time.Second, func() bool {
		return e.Stats().Reconnects >= 2 && e.State() == StateConnected
	}) {
		t.Fatalf("reconnects = %d, state = %s", e.Stats().Reconnects, e.State())
	}
	time.Sleep(200 * time.Millisecond)
	if n := e.Stats().Reconnects; n != 2 {
		t.Errorf("%d reconnects for 20 notifications (1, then 19 during its connect); want 2", n)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("provider called %d times, want 3", n)
	}
}

// TestPacketsDroppedBetweenSessions documents and pins the reconnect-window
// behaviour: the tunnel keeps being drained, and packets that cannot be
// forwarded are counted rather than queued.
func TestPacketsDroppedBetweenSessions(t *testing.T) {
	tun := newFakeTun(testMTU)

	// A provider that fails the first N attempts, so there is a real window
	// with no session.
	var attempts atomic.Int32
	e := newTestEngine(t, tun, Config{
		Backoff: &Backoff{Base: 50 * time.Millisecond, Max: 50 * time.Millisecond},
	}, func() []transport.Transport {
		if attempts.Add(1) <= 2 {
			p := newFakePipe("wg-broken")
			p.upErr = transport.ErrHandshakeTimeout
			return []transport.Transport{p}
		}
		return []transport.Transport{newFakePipe("wg-good")}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Push traffic during the failing window.
	for i := 0; i < 20; i++ {
		tun.send(ipv4UDPPacket("during reconnect"))
		time.Sleep(2 * time.Millisecond)
	}

	if !waitFor(5*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("never connected; last = %s", e.LastChange())
	}

	// The tunnel must have been drained throughout: the reads counter proves
	// the reader was not blocked or torn down.
	if tun.reads.Load() == 0 {
		t.Error("the tunnel was never read during the reconnect window; the OS queue would have backed up")
	}
	if e.Stats().DroppedNoSession == 0 {
		t.Log("no packets were dropped between sessions (the reconnect won the race); " +
			"the counter exists for the case where it does not")
	}
}

// TestMaxReconnectAttempts covers the bounded-retry path.
func TestMaxReconnectAttempts(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{
		MaxReconnectAttempts: 3,
		Backoff:              &Backoff{Base: time.Millisecond, Max: 2 * time.Millisecond},
	}, func() []transport.Transport {
		p := newFakePipe("wg-dead")
		p.upErr = transport.ErrHandshakeTimeout
		return []transport.Transport{p}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(5*time.Second, func() bool { return e.State() == StateDisconnected }) {
		t.Fatalf("engine did not give up after 3 attempts; state = %s", e.State())
	}
	if e.LastChange().Reason != ReasonNoCandidates {
		t.Errorf("final reason = %q, want %q", e.LastChange().Reason, ReasonNoCandidates)
	}
}

func TestProviderErrorIsRetried(t *testing.T) {
	tun := newFakeTun(testMTU)
	var calls atomic.Int32
	e := newTestEngine(t, tun, Config{
		Provider: ProviderFunc(func(context.Context) ([]transport.Transport, error) {
			if calls.Add(1) <= 2 {
				return nil, errors.New("control plane unreachable")
			}
			return []transport.Transport{newFakePipe("wg")}, nil
		}),
		Backoff: &Backoff{Base: time.Millisecond, Max: 2 * time.Millisecond},
	}, nil)

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(5*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("never recovered from provider errors; last = %s", e.LastChange())
	}
}

func TestEmptyCandidateListIsRetried(t *testing.T) {
	tun := newFakeTun(testMTU)
	var calls atomic.Int32
	e := newTestEngine(t, tun, Config{
		Provider: ProviderFunc(func(context.Context) ([]transport.Transport, error) {
			if calls.Add(1) <= 2 {
				return nil, nil
			}
			return []transport.Transport{newFakePipe("wg")}, nil
		}),
		Backoff: &Backoff{Base: time.Millisecond, Max: 2 * time.Millisecond},
	}, nil)

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(5*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("never recovered from an empty candidate list; last = %s", e.LastChange())
	}
}

// --- shutdown ---

// TestStopIsCleanAndIdempotent is the contract the mobile lifecycle depends
// on: when Stop returns, nothing is touching the fd any more, so the OS layer
// may close it.
func TestStopIsCleanAndIdempotent(t *testing.T) {
	tun := newFakeTun(testMTU)
	pipe := newFakePipe("wg")
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{pipe}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	done := make(chan error, 1)
	go func() { done <- e.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s; a goroutine blocked on an idle tunnel read would do this")
	}

	if e.State() != StateDisconnected {
		t.Errorf("state after Stop = %s, want disconnected", e.State())
	}
	if pipe.closeCalls.Load() == 0 {
		t.Error("the transport was not closed on Stop")
	}
	for i := 0; i < 3; i++ {
		if err := e.Stop(); err != nil {
			t.Errorf("Stop #%d = %v, want nil", i+2, err)
		}
	}
	if err := e.Start(); !errors.Is(err, ErrStopped) {
		t.Errorf("Start after Stop = %v, want ErrStopped", err)
	}
}

// TestStopOnIdleTunnelReturns is the regression test for the deadlock this
// design was restructured to avoid: a tunnel with no traffic leaves a reader
// blocked in ReadPacket, which context cancellation cannot interrupt. Stop
// must close the device to unblock it.
func TestStopOnIdleTunnelReturns(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{newFakePipe("wg")}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	// No traffic at all: every reader is blocked.
	done := make(chan struct{})
	go func() {
		_ = e.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop deadlocked on an idle tunnel")
	}
}

func TestStopDuringHandshake(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{
		RaceTimeout: 10 * time.Second,
	}, func() []transport.Transport {
		p := newFakePipe("wg-slow")
		p.upDelay = 5 * time.Second
		return []transport.Transport{p}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(2*time.Second, func() bool { return e.State() == StateConnecting }) {
		t.Fatalf("never reached connecting; state = %s", e.State())
	}

	start := time.Now()
	if err := e.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Stop took %s while a handshake was in flight; cancellation did not propagate", elapsed)
	}
}

// TestNoGoroutineLeakAcrossReconnects is the resource property that decides
// whether the engine survives a day on a phone. A mobile device reconnects on
// every network change — dozens of times a day — and one leaked goroutine per
// reconnect is a slow death.
func TestNoGoroutineLeakAcrossReconnects(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{
		Backoff: &Backoff{Base: time.Millisecond, Max: 2 * time.Millisecond},
	}, func() []transport.Transport {
		return []transport.Transport{newFakePipe("wg")}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	// Let things settle, then take a baseline.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()

	const cycles = 15
	for i := 0; i < cycles; i++ {
		e.NetworkChanged()
		if !waitFor(3*time.Second, func() bool {
			return e.Stats().Reconnects >= uint64(i+1) && e.State() == StateConnected
		}) {
			t.Fatalf("reconnect %d did not complete; state = %s", i, e.State())
		}
	}

	// Allow the last teardown to finish.
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	after := runtime.NumGoroutine()

	// A small allowance for runtime and test-fixture goroutines; what this
	// catches is growth proportional to the cycle count.
	const allowance = 10
	if after > baseline+allowance {
		t.Errorf("goroutines grew from %d to %d across %d reconnects (allowance %d): "+
			"roughly %.1f leaked per reconnect",
			baseline, after, cycles, allowance, float64(after-baseline)/float64(cycles))
	}
}

func TestStopClosesTheTunDevice(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{newFakePipe("wg")}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}
	_ = e.Stop()

	if err := tun.WritePacket([]byte{0x45}); err == nil {
		t.Error("the tun device is still writable after Stop; the engine did not close it")
	}
}

// --- concurrency ---

// TestConcurrentLifecycleCalls throws the API at the engine the way a mobile
// lifecycle does: overlapping start/stop/network-change/snapshot from several
// threads. The assertion is simply that nothing panics, nothing deadlocks and
// the state machine ends somewhere legal.
func TestConcurrentLifecycleCalls(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{
		Backoff: &Backoff{Base: time.Millisecond, Max: 2 * time.Millisecond},
	}, func() []transport.Transport {
		return []transport.Transport{newFakePipe("wg")}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				switch (w + i) % 5 {
				case 0:
					e.NetworkChanged()
				case 1:
					_ = e.State()
				case 2:
					_ = e.Stats()
				case 3:
					_ = e.Snapshot()
				case 4:
					tun.send(ipv4UDPPacket("concurrent"))
				}
			}
		}(w)
	}
	wg.Wait()

	done := make(chan struct{})
	go func() {
		_ = e.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop deadlocked after concurrent lifecycle calls")
	}

	if !e.State().IsTerminal() {
		t.Errorf("final state = %s, want a terminal state", e.State())
	}
	if n := e.Stats().RejectedTransitions; n > 0 {
		t.Logf("%d transitions were rejected by the table (expected under concurrent stop/reconnect)", n)
	}
}

// TestHighPacketRate pushes sustained traffic through to check the data path
// holds up and nothing is dropped for want of buffer management.
func TestHighPacketRate(t *testing.T) {
	const packets = 5000

	tun := newFakeTun(testMTU)
	pipe := newFakePipe("wg")
	// Room for every packet, so the only thing that can lose one is the
	// engine. With the fixture's default depth this test measured the
	// scheduler instead: on a two-CPU box the sender and the tunnel reader
	// hand the P back and forth directly, the drain goroutine below never
	// runs, and everything past the 256th packet was dropped by the fake.
	pipe.written = make(chan []byte, packets)
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{pipe}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	// Drain the transport side so the fixture's buffer is not the bottleneck.
	var received atomic.Int64
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-pipe.written:
				received.Add(1)
			case <-stop:
				return
			}
		}
	}()

	pkt := ipv4UDPPacket("load")
	for i := 0; i < packets; i++ {
		tun.send(pkt)
	}

	ok := waitFor(20*time.Second, func() bool { return received.Load() >= packets*9/10 })
	close(stop)
	if !ok {
		t.Errorf("only %d of %d packets reached the transport", received.Load(), packets)
	}

	st := e.Stats()
	t.Logf("pushed %d packets: counted out=%d, delivered=%d, dropped-no-session=%d",
		packets, st.PacketsOut, received.Load(), st.DroppedNoSession)
}

// TestSnapshotDoesNotResetStats pins the fix for Snapshot zeroing the packet
// counters that Stats reports (the mobile layer calls both, in that order).
func TestSnapshotDoesNotResetStats(t *testing.T) {
	tun := newFakeTun(1500)
	pipe := newFakePipe("wireguard/test")
	e, err := New(Config{
		Tun:      tun,
		Provider: ProviderFunc(func(context.Context) ([]transport.Transport, error) { return []transport.Transport{pipe}, nil }),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = e.Stop() })
	if !waitFor(2*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	for range 5 {
		tun.send(ipv4UDPPacket("x"))
	}
	if !waitFor(2*time.Second, func() bool { return e.Stats().PacketsOut >= 5 }) {
		t.Fatalf("PacketsOut = %d, want 5", e.Stats().PacketsOut)
	}

	snap1 := e.Snapshot()
	if got := e.Stats().PacketsOut; got < 5 {
		t.Fatalf("Stats().PacketsOut = %d after Snapshot, want >= 5 (Snapshot must not reset it)", got)
	}
	snap2 := e.Snapshot()
	if snap2.BytesUp != snap1.BytesUp {
		t.Fatalf("second Snapshot BytesUp = %d, want %d (deltas must not be double-counted)", snap2.BytesUp, snap1.BytesUp)
	}
}

// --- regressions ---

// TestDeadStreamTransportFailsOver: a Shadowsocks server that goes away
// leaves the transport object open, so nothing on the stream path errors on
// its own — each app connection just fails to dial. The engine must read that
// as the transport dying and fail over, rather than report Connected over a
// tunnel that carries nothing.
func TestDeadStreamTransportFailsOver(t *testing.T) {
	tun := newFakeTun(testMTU)
	dead := newFakeDialer("shadowsocks/dead")
	good := newFakePipe("wireguard/good")
	var calls atomic.Int32
	e := newTestEngine(t, tun, Config{StreamFailureThreshold: 3}, func() []transport.Transport {
		if calls.Add(1) == 1 {
			return []transport.Transport{dead}
		}
		return []transport.Transport{good}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("never connected; last = %s", e.LastChange())
	}

	dead.failDials(errors.New("dial tcp: connection refused"))
	for port := uint16(40000); port < 40010; port++ {
		tun.send(ipv4TCPSyn(port))
	}

	if !waitFor(5*time.Second, func() bool { return e.Stats().ActiveTransport == "wireguard/good" }) {
		t.Fatalf("engine never failed over from a stream transport whose every dial fails "+
			"(%d dials); state = %s, last = %s", dead.dialed.Load(), e.State(), e.LastChange())
	}
}

// TestClosedStreamTransportFailsImmediately: a dial reporting ErrClosed is the
// transport saying outright it is finished, so a single one is enough.
func TestClosedStreamTransportFailsImmediately(t *testing.T) {
	tun := newFakeTun(testMTU)
	var mu sync.Mutex
	var dialers []*fakeDialer
	e := newTestEngine(t, tun, Config{StreamFailureThreshold: 1000}, func() []transport.Transport {
		d := newFakeDialer("shadowsocks/test")
		mu.Lock()
		dialers = append(dialers, d)
		mu.Unlock()
		return []transport.Transport{d}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("never connected; last = %s", e.LastChange())
	}
	mu.Lock()
	first := dialers[0]
	mu.Unlock()
	first.closed.Store(true)
	tun.send(ipv4TCPSyn(41000))

	if !waitFor(5*time.Second, func() bool { return e.Stats().Reconnects >= 1 }) {
		t.Fatalf("a dial returning ErrClosed did not fail the session; state = %s, last = %s",
			e.State(), e.LastChange())
	}
}

func TestStreamHealthCounting(t *testing.T) {
	refused := errors.New("connection refused")
	var now time.Time
	newHealth := func(threshold int) (*streamHealth, *atomic.Int32) {
		var deaths atomic.Int32
		now = time.Unix(1000, 0)
		return &streamHealth{
			threshold: threshold,
			window:    time.Minute,
			now:       func() time.Time { return now },
			dead:      func(error) { deaths.Add(1) },
		}, &deaths
	}
	ctx := context.Background()

	t.Run("threshold trips", func(t *testing.T) {
		h, deaths := newHealth(3)
		h.observe(ctx, refused, true)
		h.observe(ctx, refused, true)
		if deaths.Load() != 0 {
			t.Fatal("tripped below the threshold")
		}
		h.observe(ctx, refused, false) // a failed UDP dial is evidence too
		if deaths.Load() != 1 {
			t.Fatal("did not trip at the threshold")
		}
	})
	t.Run("tcp success resets", func(t *testing.T) {
		h, deaths := newHealth(3)
		h.observe(ctx, refused, true)
		h.observe(ctx, refused, true)
		h.observe(ctx, nil, true)
		h.observe(ctx, refused, true)
		h.observe(ctx, refused, true)
		if deaths.Load() != 0 {
			t.Error("a successful TCP dial did not reset the count")
		}
	})
	t.Run("udp success does not reset", func(t *testing.T) {
		h, deaths := newHealth(3)
		h.observe(ctx, refused, true)
		h.observe(ctx, refused, true)
		h.observe(ctx, nil, false)
		h.observe(ctx, refused, true)
		if deaths.Load() != 1 {
			t.Error("a UDP dial, which never talks to the server, kept a dead transport healthy")
		}
	})
	t.Run("ignored errors", func(t *testing.T) {
		h, deaths := newHealth(1)
		h.observe(ctx, context.Canceled, true)
		h.observe(ctx, fmt.Errorf("dial: %w", context.Canceled), true)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		h.observe(cctx, refused, true)
		h.observe(ctx, transport.ErrUnsupportedFlow, false)
		if deaths.Load() != 0 {
			t.Error("a cancelled dial or an unsupported flow was counted as a transport failure")
		}
		h.observe(ctx, context.DeadlineExceeded, true)
		if deaths.Load() != 1 {
			t.Error("a dial timeout was not counted; that is how an unreachable server presents")
		}
	})
	t.Run("closed is immediate", func(t *testing.T) {
		h, deaths := newHealth(-1)
		h.observe(ctx, fmt.Errorf("x: %w", transport.ErrClosed), true)
		if deaths.Load() != 1 {
			t.Error("ErrClosed did not fail the session even with counting disabled")
		}
	})
	t.Run("window", func(t *testing.T) {
		h, deaths := newHealth(3)
		h.observe(ctx, refused, true)
		h.observe(ctx, refused, true)
		now = now.Add(2 * time.Minute)
		h.observe(ctx, refused, true)
		if deaths.Load() != 0 {
			t.Error("failures further apart than the window were added up")
		}
	})
}

// TestFlappingTransportIsBackedOffAndGivenUpOn: a transport that completes Up
// and dies milliseconds later used to reset the attempt counter on every
// connect, so it was reconnected at the first-retry delay forever and
// MaxReconnectAttempts never tripped.
func TestFlappingTransportIsBackedOffAndGivenUpOn(t *testing.T) {
	tun := newFakeTun(testMTU)
	var created atomic.Int32
	e := newTestEngine(t, tun, Config{
		MaxReconnectAttempts:  4,
		StableSessionDuration: time.Second,
		Backoff:               &Backoff{Base: time.Millisecond, Max: 2 * time.Millisecond},
	}, func() []transport.Transport {
		created.Add(1)
		p := newFakePipe("wg-flapping")
		p.dieAfterUp = 5 * time.Millisecond
		return []transport.Transport{p}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(5*time.Second, func() bool { return e.State() == StateDisconnected }) {
		t.Fatalf("a transport flapping every 5ms was reconnected %d times without the engine giving up; state = %s",
			created.Load(), e.State())
	}
	if c := e.LastChange(); c.Reason != ReasonTransportFail {
		t.Errorf("final reason = %q, want %q", c.Reason, ReasonTransportFail)
	}
	if n := created.Load(); n != 4 {
		t.Errorf("connected %d times before giving up, want 4", n)
	}
}

// TestFlappingTransportBackoffGrows checks the delays themselves: after a
// short-lived session the engine must use the growing backoff, not Delay(0).
func TestFlappingTransportBackoffGrows(t *testing.T) {
	tun := newFakeTun(testMTU)
	var mu sync.Mutex
	var connects []time.Time
	bo := &Backoff{Base: 20 * time.Millisecond, Max: time.Second, rng: func(n int64) int64 { return n - 1 }}
	e := newTestEngine(t, tun, Config{
		StableSessionDuration: time.Second,
		Backoff:               bo,
		OnStateChange: func(c Change) {
			if c.To == StateConnected {
				mu.Lock()
				connects = append(connects, time.Now())
				mu.Unlock()
			}
		},
	}, func() []transport.Transport {
		p := newFakePipe("wg-flapping")
		p.dieAfterUp = time.Millisecond
		return []transport.Transport{p}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Delays 20, 40, 80, 160ms: five connects take >= 300ms with backoff,
	// and about 5 * 20ms with the old fixed Delay(0).
	if !waitFor(5*time.Second, func() bool { mu.Lock(); defer mu.Unlock(); return len(connects) >= 5 }) {
		t.Fatal("fewer than five connects")
	}
	mu.Lock()
	span := connects[4].Sub(connects[0])
	mu.Unlock()
	if span < 280*time.Millisecond {
		t.Errorf("five connects of a flapping transport spanned %s, want >= 300ms of growing backoff", span)
	}
}

// TestStableSessionResetsAttempts: a session that stays up past
// StableSessionDuration clears the failure history, so occasional drops on a
// good transport never add up to MaxReconnectAttempts.
func TestStableSessionResetsAttempts(t *testing.T) {
	tun := newFakeTun(testMTU)
	var created atomic.Int32
	e := newTestEngine(t, tun, Config{
		MaxReconnectAttempts:  2,
		StableSessionDuration: 20 * time.Millisecond,
	}, func() []transport.Transport {
		created.Add(1)
		p := newFakePipe("wg")
		p.dieAfterUp = 80 * time.Millisecond
		return []transport.Transport{p}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(5*time.Second, func() bool { return created.Load() >= 5 }) {
		t.Fatalf("only %d connects; state = %s, last = %s", created.Load(), e.State(), e.LastChange())
	}
	if e.State() == StateDisconnected {
		t.Errorf("engine gave up on a transport whose sessions were each stable; last = %s", e.LastChange())
	}
}

// TestNetworkChangedCutsBackoffShort: a network change during a backoff sleep
// used to be ignored until the sleep ended, and the stale signal then tore
// down the session the retry had just established.
func TestNetworkChangedCutsBackoffShort(t *testing.T) {
	tun := newFakeTun(testMTU)
	var calls atomic.Int32
	e := newTestEngine(t, tun, Config{
		Backoff: &Backoff{Base: 3 * time.Second, Max: 3 * time.Second, rng: func(n int64) int64 { return n - 1 }},
	}, func() []transport.Transport {
		p := newFakePipe("wg")
		if calls.Add(1) == 1 {
			p.upErr = transport.ErrHandshakeTimeout
		}
		return []transport.Transport{p}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool {
		c := e.LastChange()
		return c.To == StateReconnecting && c.Reason == ReasonHandshakeFail
	}) {
		t.Fatalf("first attempt did not fail; last = %s", e.LastChange())
	}

	start := time.Now()
	e.NetworkChanged()
	if !waitFor(5*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatalf("never connected; last = %s", e.LastChange())
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("connect after a network change took %s; the backoff sleep ignored it", elapsed)
	}
	time.Sleep(200 * time.Millisecond)
	if n := e.Stats().Reconnects; n != 0 {
		t.Errorf("%d reconnects: the consumed network change tore down the fresh session", n)
	}
}

// TestStaleNetworkChangeDoesNotKillFreshSession: a signal raised before a
// connect starts is satisfied by that connect, and must not be left pending
// for runSession to act on.
func TestStaleNetworkChangeDoesNotKillFreshSession(t *testing.T) {
	tun := newFakeTun(testMTU)
	e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
		return []transport.Transport{newFakePipe("wg")}
	})
	e.NetworkChanged()
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}
	time.Sleep(200 * time.Millisecond)
	if n := e.Stats().Reconnects; n != 0 {
		t.Errorf("%d reconnects: a network change from before the connect tore down the new session", n)
	}
}

// TestSnapshotReportsDrops: Collector.Dropped had no caller, so drops never
// reached the uploaded snapshot.
func TestSnapshotReportsDrops(t *testing.T) {
	t.Run("between sessions", func(t *testing.T) {
		tun := newFakeTun(testMTU)
		e := newTestEngine(t, tun, Config{
			Backoff: &Backoff{Base: 50 * time.Millisecond, Max: 50 * time.Millisecond},
		}, func() []transport.Transport {
			p := newFakePipe("wg-broken")
			p.upErr = transport.ErrHandshakeTimeout
			return []transport.Transport{p}
		})
		if err := e.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		for range 10 {
			tun.send(ipv4UDPPacket("nowhere to go"))
		}
		if !waitFor(3*time.Second, func() bool { return e.Stats().DroppedNoSession >= 10 }) {
			t.Fatalf("DroppedNoSession = %d, want 10", e.Stats().DroppedNoSession)
		}
		s1 := e.Snapshot()
		if s1.DroppedOutbound != 10 {
			t.Errorf("Snapshot DroppedOutbound = %d, want 10", s1.DroppedOutbound)
		}
		if s2 := e.Snapshot(); s2.DroppedOutbound != s1.DroppedOutbound {
			t.Errorf("second Snapshot DroppedOutbound = %d, want %d (deltas must not be double-counted)",
				s2.DroppedOutbound, s1.DroppedOutbound)
		}
	})
	t.Run("userspace stack", func(t *testing.T) {
		tun := newFakeTun(testMTU)
		e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
			return []transport.Transport{newFakeDialer("shadowsocks/test")}
		})
		if err := e.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
			t.Fatal("never connected")
		}
		// Not IP: the stack drops it.
		tun.send(make([]byte, 40))
		if !waitFor(3*time.Second, func() bool { return e.Snapshot().DroppedOutbound > 0 }) {
			t.Error("a packet the userspace stack dropped never reached the snapshot")
		}
	})
}

// TestRaceDeadlineIsATimeout: a candidate still handshaking when the race
// deadline fires returns context.DeadlineExceeded, and that is a timeout —
// the "probably blocked" signal — not a refusal.
func TestRaceDeadlineIsATimeout(t *testing.T) {
	e, err := New(Config{Tun: newFakeTun(testMTU), Provider: ProviderFunc(func(context.Context) ([]transport.Transport, error) {
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	e.recordRaceResult(transport.Result{Name: "wg", Err: fmt.Errorf("handshake: %w", context.DeadlineExceeded)})
	snap := e.Snapshot()
	if len(snap.Transports) != 1 {
		t.Fatalf("got %d transports, want 1", len(snap.Transports))
	}
	out := snap.Transports[0].Outcomes
	if out[metrics.OutcomeTimeout] != 1 || out[metrics.OutcomeRefused] != 0 {
		t.Errorf("outcomes = %v, want one timeout and no refusal", out)
	}
}

// TestSessionDurationStopsWhileReconnecting: SessionEnded used to be called
// only on Stop, so SessionDuration kept growing through every reconnect.
func TestSessionDurationStopsWhileReconnecting(t *testing.T) {
	tun := newFakeTun(testMTU)
	var mu sync.Mutex
	var pipes []*fakePipe
	var broken atomic.Bool
	e := newTestEngine(t, tun, Config{
		Backoff: &Backoff{Base: 10 * time.Second, Max: 10 * time.Second},
	}, func() []transport.Transport {
		p := newFakePipe("wg")
		if broken.Load() {
			p.upErr = transport.ErrHandshakeTimeout
		}
		mu.Lock()
		pipes = append(pipes, p)
		mu.Unlock()
		return []transport.Transport{p}
	})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}
	time.Sleep(20 * time.Millisecond)
	if d := e.Snapshot().SessionDuration; d == 0 {
		t.Fatal("SessionDuration = 0 on a live session")
	}

	broken.Store(true)
	mu.Lock()
	_ = pipes[0].Close()
	mu.Unlock()
	if !waitFor(3*time.Second, func() bool { return e.Stats().Reconnects >= 1 }) {
		t.Fatalf("session did not end; last = %s", e.LastChange())
	}
	if !waitFor(time.Second, func() bool { return e.Snapshot().SessionDuration == 0 }) {
		s := e.Snapshot()
		t.Errorf("SessionDuration = %s (transport %q) while reconnecting, want 0", s.SessionDuration, s.ActiveTransport)
	}
}
