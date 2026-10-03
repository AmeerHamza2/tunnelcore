package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameerhamza2/tunnelcore/engine"
	"github.com/ameerhamza2/tunnelcore/transport"
)

// candidateSpec describes one server the provider offers the engine.
type candidateSpec struct {
	name     string // transport name, e.g. "wireguard/ams-02"
	endpoint string // for display
	role     string // what this candidate is standing in for
	// build returns a fresh transport. Fresh every time, because a closed
	// transport stays closed by contract and the engine closes every loser.
	build func() (transport.Transport, error)
}

// candidateStats is the harness's own per-candidate tally.
//
// It complements rather than duplicates the engine's metrics. The collector
// deliberately records nothing for a candidate that was abandoned because
// another one won (counting that as failure would make a healthy client look
// broken), and nothing at all for a candidate the stagger never started. Both
// are exactly what a demo of the racer wants to show, so the harness counts
// them itself from the outside.
type candidateStats struct {
	spec                        candidateSpec
	offered, dialed, won        int
	abandoned, failed, timedOut int
}

// tracer wraps each candidate so that its Up is narrated live, and keeps the
// latest race's instances so a fault can be injected into the active one.
type tracer struct {
	p *printer

	mu      sync.Mutex
	order   []string
	stats   map[string]*candidateStats
	current map[string]*traced
	races   int
}

func newTracer(p *printer, specs []candidateSpec) *tracer {
	t := &tracer{p: p, stats: make(map[string]*candidateStats)}
	for _, s := range specs {
		t.order = append(t.order, s.name)
		t.stats[s.name] = &candidateStats{spec: s}
	}
	return t
}

// provider is the engine.TransportProvider: it builds a fresh, traced
// instance of every candidate for each connection attempt.
func (t *tracer) provider(stagger, timeout time.Duration) engine.ProviderFunc {
	return func(ctx context.Context) ([]transport.Transport, error) {
		t.mu.Lock()
		t.races++
		race := t.races
		t.current = make(map[string]*traced, len(t.order))
		var out []transport.Transport
		for _, name := range t.order {
			st := t.stats[name]
			inner, err := st.spec.build()
			if err != nil {
				t.mu.Unlock()
				return nil, fmt.Errorf("building %s: %w", name, err)
			}
			st.offered++
			tr := &traced{inner: inner, t: t}
			t.current[name] = tr
			out = append(out, wrap(tr))
		}
		t.mu.Unlock()

		t.p.event(tagRace, "race #%d: %d candidates in preference order, stagger %s, timeout %s",
			race, len(out), stagger, timeout)
		return out, nil
	}
}

// wrap returns tr as the narrowest interface the inner transport implements.
// The engine picks the data path by type switch, so the wrapper must not
// claim an interface the inner transport lacks.
func wrap(tr *traced) transport.Transport {
	switch in := tr.inner.(type) {
	case transport.PacketPipe:
		return &tracedPipe{traced: tr, pipe: in}
	case transport.StreamDialer:
		return &tracedDialer{traced: tr, dialer: in}
	default:
		return tr
	}
}

// onConnected is called from the engine's state observer when a session
// comes up. Every candidate's Up has returned by then — the racer collects
// all outcomes before returning its winner — so this is the moment to report
// the ones the stagger never started.
func (t *tracer) onConnected(winner string) {
	t.mu.Lock()
	var skipped []string
	if st, ok := t.stats[winner]; ok {
		st.won++
	}
	for _, name := range t.order {
		if tr, ok := t.current[name]; ok && !tr.started.Load() {
			skipped = append(skipped, name)
		}
	}
	t.mu.Unlock()
	for _, name := range skipped {
		t.p.event(tagRace, "%s %-20s never dialed: a better candidate won before its turn (saved a handshake)",
			t.p.dim("–"), name)
	}
}

// closeActive closes the live instance of the named transport, as a
// dead-peer detector would on deciding the exit node is gone.
func (t *tracer) closeActive(name string) bool {
	t.mu.Lock()
	tr, ok := t.current[name]
	t.mu.Unlock()
	if !ok {
		return false
	}
	_ = tr.Close()
	return true
}

func (t *tracer) snapshot() []candidateStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]candidateStats, 0, len(t.order))
	for _, name := range t.order {
		out = append(out, *t.stats[name])
	}
	return out
}

// traced decorates a transport's Up with live narration.
type traced struct {
	inner   transport.Transport
	t       *tracer
	started atomic.Bool
}

func (c *traced) Name() string         { return c.inner.Name() }
func (c *traced) Kind() transport.Kind { return c.inner.Kind() }
func (c *traced) Close() error         { return c.inner.Close() }

func (c *traced) Up(ctx context.Context) error {
	c.started.Store(true)
	p := c.t.p
	name := c.inner.Name()

	c.t.mu.Lock()
	st := c.t.stats[name]
	st.dialed++
	endpoint := st.spec.endpoint
	c.t.mu.Unlock()

	p.event(tagRace, "%s %-20s dialing %s", p.style(styleMagenta, "▸"), name, endpoint)
	start := time.Now()
	err := c.inner.Up(ctx)
	took := time.Since(start)

	c.t.mu.Lock()
	defer c.t.mu.Unlock()
	switch {
	case err == nil:
		what := "handshake complete"
		if c.inner.Kind() == transport.KindStream {
			what = "probe authenticated"
		}
		p.event(tagRace, "%s %-20s %s in %s", p.ok("✓"), name, what, ms(took))
	case errors.Is(err, context.Canceled):
		st.abandoned++
		p.event(tagRace, "%s %-20s abandoned after %s: another candidate won (not counted as a failure)",
			p.dim("·"), name, ms(took))
	case errors.Is(err, transport.ErrHandshakeTimeout) || errors.Is(err, context.DeadlineExceeded):
		st.timedOut++
		p.event(tagRace, "%s %-20s timed out after %s: %v", p.bad("✗"), name, ms(took), err)
	default:
		st.failed++
		p.event(tagRace, "%s %-20s failed after %s: %v", p.bad("✗"), name, ms(took), err)
	}
	return err
}

// tracedPipe is a traced packet transport.
type tracedPipe struct {
	*traced
	pipe transport.PacketPipe
}

func (c *tracedPipe) WritePacket(b []byte) error       { return c.pipe.WritePacket(b) }
func (c *tracedPipe) ReadPacket(b []byte) (int, error) { return c.pipe.ReadPacket(b) }
func (c *tracedPipe) MTU() int                         { return c.pipe.MTU() }

// tracedDialer is a traced stream transport. Its dials are narrated too: they
// are the moment the engine's userspace stack has turned a TCP flow from the
// phone into a proxied connection, which is otherwise invisible.
type tracedDialer struct {
	*traced
	dialer transport.StreamDialer
}

func (c *tracedDialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	c.t.p.event(tagStack, "netstack terminated a TCP flow to %s; dialing it via %s", dst, c.Name())
	return c.dialer.DialTCP(ctx, dst)
}

func (c *tracedDialer) DialUDP(ctx context.Context, dst netip.AddrPort) (transport.UDPSession, error) {
	c.t.p.debug(tagStack, "netstack opening a UDP association to %s via %s", dst, c.Name())
	return c.dialer.DialUDP(ctx, dst)
}

var (
	_ transport.PacketPipe   = (*tracedPipe)(nil)
	_ transport.StreamDialer = (*tracedDialer)(nil)
)

// stateWatcher prints the engine's state transitions and lets the demo wait
// for them.
type stateWatcher struct {
	p  *printer
	t  *tracer
	ch chan engine.Change
}

func newStateWatcher(p *printer, t *tracer) *stateWatcher {
	return &stateWatcher{p: p, t: t, ch: make(chan engine.Change, 64)}
}

// observe is the engine's OnStateChange callback. It runs on the engine's
// supervisor goroutine and must not block, hence the buffered, lossy send:
// the demo only ever waits for a handful of transitions.
func (w *stateWatcher) observe(c engine.Change) {
	if c.To == engine.StateConnected {
		w.t.onConnected(c.Transport)
	}
	arrow := fmt.Sprintf("%s → %s", c.From, w.p.style(stateStyle(c.To), c.To.String()))
	switch {
	case c.To == engine.StateConnected:
		w.p.event(tagState, "%s via %s", arrow, w.p.bold(c.Transport))
	case c.Err != nil:
		w.p.event(tagState, "%s (%s: %v)", arrow, c.Reason, c.Err)
	default:
		w.p.event(tagState, "%s (%s)", arrow, c.Reason)
	}
	select {
	case w.ch <- c:
	default:
	}
}

func stateStyle(s engine.State) string {
	switch s {
	case engine.StateConnected:
		return styleGreen + styleBold
	case engine.StateReconnecting, engine.StateConnecting:
		return styleYellow
	case engine.StateDisconnected, engine.StateDisconnecting:
		return styleDim
	default:
		return ""
	}
}

// awaitConnected waits for the next transition into StateConnected.
func (w *stateWatcher) awaitConnected(ctx context.Context, within time.Duration) (engine.Change, error) {
	timer := time.NewTimer(within)
	defer timer.Stop()
	for {
		select {
		case c := <-w.ch:
			if c.To == engine.StateConnected {
				return c, nil
			}
			if c.To == engine.StateDisconnected {
				return c, fmt.Errorf("engine gave up: %v", c)
			}
		case <-timer.C:
			return engine.Change{}, fmt.Errorf("not connected within %s", within)
		case <-ctx.Done():
			return engine.Change{}, ctx.Err()
		}
	}
}
