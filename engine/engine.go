// Package engine owns the tunnel file descriptor and everything that happens
// to the packets crossing it.
//
// The engine is the only component that knows about all the others, and its
// job is deliberately narrow: hold the fd, pick a transport, move packets, and
// re-establish when the network moves under it. Protocol specifics live in
// package transport, TCP termination in package netstack, name resolution in
// package dnsproxy. Keeping the engine ignorant of all three is what makes the
// transports swappable at runtime without re-plumbing the fd (see
// transport/wireguard/virtualtun.go for the inversion that buys that).
//
// The data path, for a packet transport such as WireGuard:
//
//	tun fd ──► read ──► DNS intercept? ──► transport.WritePacket
//	tun fd ◄── write ◄──────────────────── transport.ReadPacket
//
// and for a stream transport such as Shadowsocks:
//
//	tun fd ──► read ──► netstack.DeliverInbound ──► TCP/UDP forwarder ──► proxy
//	tun fd ◄── write ◄── netstack.ReadOutbound  ◄──────────────────────── proxy
//
// Both shapes run under the same supervisor, the same state machine, the same
// backoff and the same metrics, which is the point.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameerhamza2/tunnelcore/dnsproxy"
	"github.com/ameerhamza2/tunnelcore/metrics"
	"github.com/ameerhamza2/tunnelcore/netstack"
	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport"
)

// Engine errors.
var (
	ErrAlreadyRunning = errors.New("engine: already running")
	ErrNotRunning     = errors.New("engine: not running")
	ErrNoTun          = errors.New("engine: no tunnel device configured")
	ErrNoProvider     = errors.New("engine: no transport provider configured")
	ErrStopped        = errors.New("engine: stopped")
)

// TunDevice is the OS tunnel interface.
//
// It is an interface rather than a concrete fd so that the whole engine can be
// exercised in a unit test with an in-memory device — which is what makes the
// reconnect and network-change behaviour testable at all, since neither can be
// provoked on demand against a real interface.
type TunDevice interface {
	// ReadPacket blocks until one IP packet is available from the OS and
	// copies it into b.
	ReadPacket(b []byte) (int, error)

	// WritePacket delivers one IP packet to the OS. It must not retain p.
	WritePacket(p []byte) error

	// MTU reports the interface MTU.
	MTU() int

	// Close releases the device. It MUST unblock any ReadPacket currently
	// blocked in another goroutine — the engine's shutdown path depends on
	// it, because a blocking read on a tunnel with no traffic cannot be
	// interrupted any other way.
	//
	// The engine takes ownership of the device: Stop closes it, and the
	// device must not be used afterwards.
	Close() error
}

// TransportProvider supplies the candidates for a connection attempt.
//
// It is called fresh on every attempt rather than once at startup, and that
// matters: between a failure and a retry the control plane may have marked a
// server unhealthy, issued a new peer, or returned a different region, and the
// retry should use the new list. A provider that caches internally is free to,
// but the engine will not cache on its behalf.
type TransportProvider interface {
	Candidates(ctx context.Context) ([]transport.Transport, error)
}

// ProviderFunc adapts a function to TransportProvider.
type ProviderFunc func(ctx context.Context) ([]transport.Transport, error)

func (f ProviderFunc) Candidates(ctx context.Context) ([]transport.Transport, error) {
	return f(ctx)
}

// Config configures an Engine.
type Config struct {
	// Tun is the OS tunnel device.
	Tun TunDevice

	// Provider supplies transport candidates per attempt.
	Provider TransportProvider

	// TunnelAddresses are the addresses assigned to the tunnel interface.
	// Needed by the userspace stack for stream transports.
	TunnelAddresses []netip.Prefix

	// DNSUpstreams are the resolvers the in-tunnel proxy queries. Empty
	// disables the DNS proxy, which is only appropriate for a packet
	// transport whose peer already handles DNS.
	DNSUpstreams []netip.AddrPort

	// DNSPolicy optionally filters names.
	DNSPolicy dnsproxy.Policy

	// Metrics is the collector. Nil installs a private one, reachable through
	// Snapshot.
	Metrics *metrics.Collector

	// Backoff controls reconnect pacing. Nil selects the defaults.
	Backoff *Backoff

	// RaceStagger and RaceTimeout are passed through to the transport racer.
	RaceStagger time.Duration
	RaceTimeout time.Duration

	// OnStateChange, if non-nil, observes every state transition.
	OnStateChange func(Change)

	// MaxReconnectAttempts bounds consecutive failed reconnects before the
	// engine gives up and enters StateDisconnected. Zero means unlimited,
	// which is the right default for a VPN: a phone in a tunnel or on a plane
	// should still be connected when it comes out.
	//
	// A session that comes up and dies again before StableSessionDuration
	// counts as a failed attempt too; see StableSessionDuration.
	MaxReconnectAttempts int

	// StableSessionDuration is how long a session must stay up before the
	// engine treats the transport as healthy again and resets its reconnect
	// attempt counter. Zero selects DefaultStableSessionDuration.
	//
	// Without it, "the handshake succeeded" is taken as proof of health, and a
	// flapping transport — one that completes Up and dies milliseconds later,
	// which is what a server shedding load or a middlebox killing the flow
	// after the first packets looks like — is reconnected at the first-retry
	// delay forever: the counter resets on every connect, so neither the
	// backoff nor MaxReconnectAttempts ever engages.
	StableSessionDuration time.Duration

	// StreamFailureThreshold is the number of consecutive failed dials through
	// a stream transport, with no successful TCP dial in between and all
	// within StreamFailureWindow, after which the engine declares the session
	// dead and fails over. Zero selects DefaultStreamFailureThreshold;
	// negative disables the count (a dial reporting transport.ErrClosed still
	// fails the session immediately).
	//
	// A stream transport has no data path of its own to die on: every flow is
	// an independent dial, so a Shadowsocks server that has gone away shows up
	// only as each new connection failing. Without this the engine reports
	// Connected over a tunnel that carries nothing, indefinitely.
	StreamFailureThreshold int

	// StreamFailureWindow bounds how far apart the failures counted by
	// StreamFailureThreshold may be. Zero selects DefaultStreamFailureWindow.
	// It keeps a handful of unrelated failures spread over an hour — a flaky
	// moment on the radio, say — from adding up to a failover.
	StreamFailureWindow time.Duration
}

// Defaults for the Config fields that have them.
const (
	// DefaultStableSessionDuration is long enough that a transport which
	// survives it is carrying real traffic, and short enough that a user who
	// had a working tunnel for a minute is not penalised for an earlier bad
	// patch.
	DefaultStableSessionDuration = 30 * time.Second

	// DefaultStreamFailureThreshold is small because each failed dial is an
	// app connection the user saw fail; five is enough to rule out one
	// unreachable destination or a single dropped SYN.
	DefaultStreamFailureThreshold = 5

	// DefaultStreamFailureWindow is generous because an idle phone dials
	// rarely, and a window shorter than the gap between dials would mean a
	// dead server is never detected on exactly the devices least likely to
	// notice on their own.
	DefaultStreamFailureWindow = 60 * time.Second
)

// Engine supervises one tunnel.
type Engine struct {
	cfg     Config
	state   *machine
	backoff *Backoff
	coll    *metrics.Collector

	mu sync.Mutex
	// running guards Start/Stop. The data-path goroutines read the fields
	// below only between a successful Start and the corresponding Stop.
	running bool
	cancel  context.CancelFunc
	// wg tracks the engine-lifetime goroutines: the supervisor and the tunnel
	// reader. Per-session goroutines are tracked by session.wg so that a
	// reconnect can wait for the previous session to unwind completely before
	// starting the next.
	wg sync.WaitGroup

	// session holds the live session's resources, replaced on each connect.
	sessionMu sync.Mutex
	session   *session

	// networkChanged is signalled by NetworkChanged. Buffered with depth one
	// and sent non-blockingly, which coalesces a burst of OS notifications
	// into a single reconnect — Android emits several per wifi-to-cellular
	// handover and reconnecting once per notification would thrash.
	networkChanged chan struct{}

	// sink is the current session's outbound packet sink, published
	// atomically. The tunnel reader loads it per packet; a nil value means
	// "between sessions", and packets read in that window are dropped and
	// counted rather than queued. Dropping is correct: a tunnel is a datagram
	// path, so the endpoints' own congestion control handles it, whereas
	// queueing across a reconnect delivers seconds-stale packets to a
	// different exit node than the one the flow started on.
	sink atomic.Pointer[func(p []byte) error]

	reconnects       atomic.Uint64
	droppedNoSession atomic.Uint64
	packetsIn        atomic.Uint64
	packetsOut       atomic.Uint64
	bytesIn          atomic.Uint64
	bytesOut         atomic.Uint64
	readErrors       atomic.Uint64

	// flushed records the counter values last folded into the collector, so
	// Snapshot folds in deltas and the atomics above stay cumulative. The
	// indices are bytesOut, bytesIn, packetsOut, packetsIn, droppedNoSession.
	flushMu sync.Mutex
	flushed [5]uint64
}

// session is one established tunnel: a transport plus whatever is layered on
// it, and the goroutine carrying inbound packets back to the tunnel.
//
// Note what a session does *not* own: the tunnel reader. See
// Engine.runTunReader for why that lives one level up.
type session struct {
	tr       transport.Transport
	stack    *netstack.Stack
	resolver *dnsproxy.Resolver

	// sink accepts one outbound IP packet read off the tunnel. It is
	// whichever of the two data-path shapes this transport needs, resolved
	// once at session setup so the hot path does no type switching.
	sink func(p []byte) error

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// failed is closed by any data-path goroutine that hits a fatal error, to
	// wake the supervisor.
	failed    chan struct{}
	failOnce  sync.Once
	failErr   error
	failErrMu sync.Mutex

	// stackDropsFlushed is the stack's DroppedInbound value last folded into
	// the collector. It lives on the session, not the engine, because each
	// session builds a fresh stack whose counters start at zero. Guarded by
	// Engine.flushMu.
	stackDropsFlushed uint64
	// stackOutDropsFlushed is the same for the stack's DroppedOutbound.
	stackOutDropsFlushed uint64
}

func (s *session) fail(err error) {
	s.failOnce.Do(func() {
		s.failErrMu.Lock()
		s.failErr = err
		s.failErrMu.Unlock()
		close(s.failed)
	})
}

func (s *session) failure() error {
	s.failErrMu.Lock()
	defer s.failErrMu.Unlock()
	return s.failErr
}

func (s *session) close() {
	s.cancel()
	if s.stack != nil {
		_ = s.stack.Close()
	}
	if s.resolver != nil {
		_ = s.resolver.Close()
	}
	if s.tr != nil {
		_ = s.tr.Close()
	}
	s.wg.Wait()
}

// New builds an Engine.
func New(cfg Config) (*Engine, error) {
	if cfg.Tun == nil {
		return nil, ErrNoTun
	}
	if cfg.Provider == nil {
		return nil, ErrNoProvider
	}

	coll := cfg.Metrics
	if coll == nil {
		coll = metrics.New()
	}
	bo := cfg.Backoff
	if bo == nil {
		bo = NewBackoff()
	}

	e := &Engine{
		cfg:            cfg,
		state:          newMachine(),
		backoff:        bo,
		coll:           coll,
		networkChanged: make(chan struct{}, 1),
	}
	if cfg.OnStateChange != nil {
		e.state.observe(cfg.OnStateChange)
	}
	return e, nil
}

// State returns the current connection state.
func (e *Engine) State() State { return e.state.current() }

// LastChange returns the most recent state transition.
func (e *Engine) LastChange() Change { return e.state.lastChange() }

// Observe registers a state-change callback.
func (e *Engine) Observe(fn func(Change)) { e.state.observe(fn) }

// Start brings the tunnel up and keeps it up until Stop.
//
// It returns as soon as the supervisor is running, not when the tunnel is
// established: on a mobile client the first connect can take seconds and the
// UI needs to render "Connecting" meanwhile. Callers that need to wait should
// observe state changes.
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return ErrAlreadyRunning
	}
	if e.state.current().IsTerminal() {
		e.mu.Unlock()
		return ErrStopped
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.running = true
	e.mu.Unlock()

	e.wg.Add(2)
	go func() {
		defer e.wg.Done()
		e.runTunReader(ctx)
	}()
	go func() {
		defer e.wg.Done()
		e.supervise(ctx)
	}()
	return nil
}

// runTunReader drains the tunnel for the engine's entire lifetime and hands
// each packet to whichever session is current.
//
// This deliberately does not belong to a session, for two reasons.
//
// The first is a deadlock. ReadPacket on a tunnel with no traffic blocks
// indefinitely, and a context cancellation cannot interrupt it — the only
// thing that can is closing the device. A reader owned by a session would
// therefore make session teardown wait for a packet that may never arrive, so
// every reconnect would hang until the user happened to generate traffic.
//
// The second is behavioural, and it is the better argument. During a reconnect
// the OS keeps writing packets into the tunnel. If nothing is draining it, the
// queue backs up and the OS starts reporting the interface as congested to
// every app on the device — so a two-second reconnect presents as every app
// stalling, not just the ones with live connections. Draining continuously and
// dropping what cannot be forwarded is what a physical interface does when a
// link flaps, and it is what applications are built to tolerate.
func (e *Engine) runTunReader(ctx context.Context) {
	buf := make([]byte, e.cfg.Tun.MTU())
	for {
		n, err := e.cfg.Tun.ReadPacket(buf)
		if err != nil {
			// Either the device was closed by Stop, or the OS tore the
			// interface down. Neither is recoverable from here.
			return
		}
		if ctx.Err() != nil {
			return
		}
		if n == 0 {
			continue
		}

		sinkPtr := e.sink.Load()
		if sinkPtr == nil {
			e.droppedNoSession.Add(1)
			continue
		}
		e.countOutbound(buf[:n])
		if err := (*sinkPtr)(buf[:n]); err != nil {
			// The sink reports its own failure to the supervisor through the
			// session; the reader just keeps draining.
			continue
		}
	}
}

// Stop tears the tunnel down and waits for everything to unwind.
//
// Waiting is the contract that makes Stop usable from a mobile lifecycle
// callback: when Stop returns, no goroutine is still touching the tun fd, so
// the OS layer is free to close it. Returning early would race the OS closing
// the fd against the engine writing to it.
func (e *Engine) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		// Idempotent: Stop on a stopped engine is not an error, because the
		// mobile lifecycle legitimately calls it more than once.
		return nil
	}
	e.running = false
	cancel := e.cancel
	e.cancel = nil
	e.mu.Unlock()

	e.state.transition(StateDisconnecting, ReasonUserRequested, "", nil)
	cancel()

	// Closing the device is what unblocks the tunnel reader. Cancellation
	// alone cannot: ReadPacket on an idle tunnel blocks until a packet
	// arrives, and on a quiet network that is never.
	_ = e.cfg.Tun.Close()
	e.wg.Wait()

	e.sessionMu.Lock()
	s := e.session
	e.session = nil
	e.sessionMu.Unlock()
	if s != nil {
		s.close()
		e.flushSessionDrops(s)
	}

	e.coll.SessionEnded()
	e.state.transition(StateDisconnected, ReasonUserRequested, "", nil)
	return nil
}

// NetworkChanged tells the engine the device's network has changed.
//
// The mobile layer calls this from its connectivity callback. Signalling is
// non-blocking onto a depth-one channel, which coalesces the burst of
// notifications an OS emits during a single handover into one reconnect.
//
// A reconnect rather than a continuation is correct even though WireGuard can
// in principle roam: the local address has changed, so the existing socket is
// bound to an address that no longer exists, and on Android the old socket is
// not even protected from the VPN route any more — writing to it would send
// tunnel traffic back into the tunnel.
func (e *Engine) NetworkChanged() {
	select {
	case e.networkChanged <- struct{}{}:
	default: // a reconnect is already pending; coalesce
	}
}

// Snapshot returns current metrics.
func (e *Engine) Snapshot() metrics.Snapshot {
	// Fold the engine's own counters in before snapshotting, so a caller sees
	// traffic that has happened rather than traffic that has been flushed.
	//
	// Only the delta since the previous flush is folded in. An earlier version
	// Swap(0)'d the counters instead, which double-booked them: Stats reads
	// the same atomics, so every Snapshot silently reset the packet counts
	// Stats reports. The mobile StatsJSON calls Snapshot then Stats, so the
	// app always showed packets_in/packets_out as roughly zero.
	//
	// Drops are folded the same way. Before they were, Collector.Dropped had
	// no caller at all, so the uploaded snapshot reported zero drops however
	// much traffic a slow reconnect had shed — the "silently shedding traffic"
	// case the metric exists to expose.
	e.sessionMu.Lock()
	s := e.session
	e.sessionMu.Unlock()

	e.flushMu.Lock()
	cur := [5]uint64{e.bytesOut.Load(), e.bytesIn.Load(), e.packetsOut.Load(), e.packetsIn.Load(), e.droppedNoSession.Load()}
	var d [5]uint64
	for i := range cur {
		d[i] = cur[i] - e.flushed[i]
	}
	e.flushed = cur
	e.coll.TunnelTraffic(d[0], d[1], d[2], d[3])
	stackIn, stackOut := e.stackDropsDeltaLocked(s)
	if drops := d[4] + stackOut; drops > 0 || stackIn > 0 {
		e.coll.Dropped(stackIn, drops)
	}
	e.flushMu.Unlock()
	return e.coll.Snapshot()
}

// stackDropsDeltaLocked returns the session stack's drops not yet folded into
// the collector, in the collector's terms (towards the device, towards the
// network), and marks them folded. e.flushMu must be held.
//
// Note the naming flip. Packets read off the tunnel with no session to take
// them, and packets the userspace stack refused, are on the device-to-network
// path, which the collector calls outbound (the direction BytesUp counts); the
// stack calls the latter "inbound" because, from its side, they are arriving.
// Likewise the stack's outbound drops — packets for the apps that its queue
// to the tunnel writer had no room for — are the collector's inbound.
func (e *Engine) stackDropsDeltaLocked(s *session) (toDevice, toNetwork uint64) {
	if s == nil || s.stack == nil {
		return 0, 0
	}
	st := s.stack.Stats()
	toNetwork = st.DroppedInbound - s.stackDropsFlushed
	s.stackDropsFlushed = st.DroppedInbound
	toDevice = st.DroppedOutbound - s.stackOutDropsFlushed
	s.stackOutDropsFlushed = st.DroppedOutbound
	return toDevice, toNetwork
}

// flushSessionDrops folds a finished session's last stack drops into the
// collector. Without this, drops since the last Snapshot would be lost with
// the stack, since the next session's stack starts counting from zero.
func (e *Engine) flushSessionDrops(s *session) {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()
	if in, out := e.stackDropsDeltaLocked(s); in > 0 || out > 0 {
		e.coll.Dropped(in, out)
	}
}

// supervise is the engine's main loop: connect, run, reconnect.
func (e *Engine) supervise(ctx context.Context) {
	// attempt counts consecutive failures: connects that failed, and sessions
	// that died before proving themselves stable. It is reset only by a
	// session that stayed up for StableSessionDuration, or by a network
	// change, never by a bare successful connect — see StableSessionDuration
	// for the flapping transport that a reset-on-connect never backs off.
	attempt := 0
	first := true
	// retryReason labels the transition into the next attempt. It is
	// ReasonRetry unless a network change cut a backoff short, so a support
	// log shows why the engine retried early.
	retryReason := ReasonRetry

	for {
		if ctx.Err() != nil {
			return
		}

		reason := ReasonStarted
		target := StateConnecting
		if !first {
			reason = retryReason
			target = StateReconnecting
		}
		retryReason = ReasonRetry
		if _, ok := e.state.transition(target, reason, "", nil); !ok && !first {
			// The state machine refused, which means a Stop is in progress.
			return
		}

		// Discard any network change signalled before this attempt began. The
		// connect about to happen already runs on the current network, so the
		// signal is satisfied; left pending, it would be read by runSession
		// the instant the new session came up and tear down a perfectly good
		// tunnel. A change that arrives *during* connect is kept, and that is
		// right: the race may have bound sockets to the network that just
		// went away.
		select {
		case <-e.networkChanged:
		default:
		}

		sess, err := e.connect(ctx)
		first = false
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			attempt++
			if e.cfg.MaxReconnectAttempts > 0 && attempt >= e.cfg.MaxReconnectAttempts {
				e.state.transition(StateDisconnected, ReasonNoCandidates, "", err)
				return
			}
			delay := e.backoff.Delay(attempt - 1)
			e.state.transition(StateReconnecting, ReasonHandshakeFail, "", err)
			if !e.backoffSleep(ctx, delay, &attempt, &retryReason) {
				return
			}
			continue
		}

		e.sessionMu.Lock()
		e.session = sess
		e.sessionMu.Unlock()

		// Publishing the sink is what opens the outbound path. It happens
		// after the session is fully built, so the tunnel reader can never
		// hand a packet to a half-constructed stack.
		e.sink.Store(&sess.sink)

		e.coll.SessionStarted(sess.tr.Name())
		e.state.transition(StateConnected, ReasonStarted, sess.tr.Name(), nil)

		// Run until something ends the session.
		upAt := time.Now()
		reconnectReason := e.runSession(ctx, sess)
		uptime := time.Since(upAt)

		// Retract the sink before tearing anything down, so no packet is
		// written into a closing stack or a closed transport.
		e.sink.Store(nil)

		e.sessionMu.Lock()
		e.session = nil
		e.sessionMu.Unlock()
		sess.close()
		e.flushSessionDrops(sess)

		// End the session in the collector now, not only on Stop. Otherwise
		// SessionDuration keeps growing through the whole reconnect — and
		// through a give-up into StateDisconnected — reporting a tunnel that
		// is not there.
		e.coll.SessionEnded()

		if ctx.Err() != nil {
			return
		}
		e.reconnects.Add(1)

		var delay time.Duration
		switch {
		case reconnectReason == ReasonNetworkChanged:
			// A network change is not a failure, so it is not backed off and
			// not counted: the radio has just come up on a new network and the
			// right move is to connect immediately. Backing off here is what
			// makes a VPN take several seconds to recover from walking out of
			// wifi range. The failure history belongs to the old network, so
			// it is dropped too.
			attempt = 0
			continue

		case uptime >= e.stableSessionDuration():
			// The transport carried a real session, so this failure starts a
			// fresh run: one short, jittered pause and no strike against it.
			attempt = 0
			delay = e.backoff.Delay(0)

		default:
			// The session died before proving itself. Treat it exactly like a
			// failed connect, so a flapping transport is backed off and, if a
			// limit is configured, eventually given up on.
			attempt++
			if e.cfg.MaxReconnectAttempts > 0 && attempt >= e.cfg.MaxReconnectAttempts {
				e.state.transition(StateDisconnected, ReasonTransportFail, sess.tr.Name(), sess.failure())
				return
			}
			delay = e.backoff.Delay(attempt - 1)
		}
		if !e.backoffSleep(ctx, delay, &attempt, &retryReason) {
			return
		}
	}
}

func (e *Engine) stableSessionDuration() time.Duration {
	if e.cfg.StableSessionDuration > 0 {
		return e.cfg.StableSessionDuration
	}
	return DefaultStableSessionDuration
}

// backoffSleep waits out a reconnect delay, returning false if the engine is
// stopping.
//
// A network change ends the wait early and resets the attempt counter. The
// backoff exists to stop hammering a server that is failing; a network change
// means the reason for the failures has very likely just gone — this is the
// phone walking back into wifi range — and sitting out a 30-second ceiling
// regardless is how a VPN ends up "Reconnecting" long after the network
// recovered. Consuming the signal here also matters: left pending, it would
// tear down the session this retry is about to establish.
func (e *Engine) backoffSleep(ctx context.Context, d time.Duration, attempt *int, reason *Reason) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-e.networkChanged:
		*attempt = 0
		*reason = ReasonNetworkChanged
		return true
	}
}

// connect races the provider's candidates and builds a session around the
// winner.
func (e *Engine) connect(ctx context.Context) (*session, error) {
	candidates, err := e.cfg.Provider.Candidates(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine: fetching candidates: %w", err)
	}
	if len(candidates) == 0 {
		return nil, transport.ErrNoCandidates
	}

	racer := &transport.Racer{
		Candidates: candidates,
		Stagger:    e.cfg.RaceStagger,
		Timeout:    e.cfg.RaceTimeout,
		OnResult:   e.recordRaceResult,
	}
	winner, err := racer.Race(ctx)
	if err != nil {
		return nil, err
	}

	sessCtx, sessCancel := context.WithCancel(ctx)
	sess := &session{
		tr:     winner,
		ctx:    sessCtx,
		cancel: sessCancel,
		failed: make(chan struct{}),
	}

	if err := e.buildDataPath(sess); err != nil {
		sessCancel()
		_ = winner.Close()
		return nil, err
	}
	return sess, nil
}

// buildDataPath wires the session's packet plumbing according to the winning
// transport's kind.
func (e *Engine) buildDataPath(sess *session) error {
	switch tr := sess.tr.(type) {
	case transport.PacketPipe:
		e.startPacketPath(sess, tr)
		return nil

	case transport.StreamDialer:
		// Every dial — app flows and DNS alike — goes through the health
		// tracker, because for a stream transport the dials are the only
		// evidence the server is still there. See healthDialer.
		dialer := &healthDialer{StreamDialer: tr, h: e.newStreamHealth(sess)}

		resolver, err := e.newResolver(dialer)
		if err != nil {
			return err
		}
		sess.resolver = resolver

		var dnsHandler netstack.DNSHandler
		if resolver != nil {
			dnsHandler = resolver
		}
		stack, err := netstack.New(netstack.Config{
			Dialer:         dialer,
			MTU:            e.cfg.Tun.MTU(),
			LocalAddresses: e.cfg.TunnelAddresses,
			DNS:            dnsHandler,
			OnFlow:         e.recordFlow,
		})
		if err != nil {
			return err
		}
		sess.stack = stack
		e.startStreamPath(sess, stack)
		return nil

	default:
		return fmt.Errorf("engine: transport %s reports kind %s but implements neither PacketPipe nor StreamDialer",
			sess.tr.Name(), sess.tr.Kind())
	}
}

func (e *Engine) newResolver(tr transport.StreamDialer) (*dnsproxy.Resolver, error) {
	if len(e.cfg.DNSUpstreams) == 0 {
		return nil, nil
	}
	return dnsproxy.New(dnsproxy.Config{
		Transport: &dnsTransportAdapter{d: tr},
		Upstreams: e.cfg.DNSUpstreams,
		Policy:    e.cfg.DNSPolicy,
		OnQuery: func(_ string, _ uint16, blocked, _ bool, _ error) {
			e.coll.DNSQuery(blocked)
		},
	})
}

// dnsTransportAdapter narrows a StreamDialer to the subset dnsproxy needs.
//
// The adapter exists so that package dnsproxy does not import package
// transport, which keeps the DNS proxy testable against a dialer that can
// reach exactly one loopback resolver and nothing else — the fixture the
// fail-closed leak test depends on.
type dnsTransportAdapter struct{ d transport.StreamDialer }

func (a *dnsTransportAdapter) DialUDP(ctx context.Context, dst netip.AddrPort) (dnsproxy.UDPSession, error) {
	return a.d.DialUDP(ctx, dst)
}

func (a *dnsTransportAdapter) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return a.d.DialTCP(ctx, dst)
}

// healthDialer is a StreamDialer that reports every dial's outcome to a
// streamHealth, which fails the session once the transport is evidently dead.
//
// This is the stream path's equivalent of the packet path's ReadPacket loop.
// A packet transport has one long-lived read that errors when the transport
// dies; a stream transport has nothing long-lived at all — each flow is its
// own dial, and a dead Shadowsocks server shows up only as each new dial
// failing, one app connection at a time. Those errors used to reach recordFlow
// and nowhere else, so the session never failed, the state stayed Connected,
// and the engine never failed over to a candidate that worked.
type healthDialer struct {
	transport.StreamDialer
	h *streamHealth
}

func (d *healthDialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	c, err := d.StreamDialer.DialTCP(ctx, dst)
	d.h.observe(ctx, err, true)
	return c, err
}

func (d *healthDialer) DialUDP(ctx context.Context, dst netip.AddrPort) (transport.UDPSession, error) {
	s, err := d.StreamDialer.DialUDP(ctx, dst)
	d.h.observe(ctx, err, false)
	return s, err
}

// streamHealth counts consecutive dial failures through one session's stream
// transport.
type streamHealth struct {
	threshold int
	window    time.Duration
	now       func() time.Time
	// dead is called, possibly more than once and from any flow goroutine,
	// when the transport is judged dead. session.fail is idempotent.
	dead func(error)

	mu          sync.Mutex
	consecutive int
	streakStart time.Time
}

func (e *Engine) newStreamHealth(sess *session) *streamHealth {
	threshold := e.cfg.StreamFailureThreshold
	if threshold == 0 {
		threshold = DefaultStreamFailureThreshold
	}
	window := e.cfg.StreamFailureWindow
	if window <= 0 {
		window = DefaultStreamFailureWindow
	}
	return &streamHealth{
		threshold: threshold,
		window:    window,
		now:       time.Now,
		dead: func(err error) {
			// A dial failing because the session is being torn down is not a
			// verdict on the transport.
			if sess.ctx.Err() == nil {
				sess.fail(err)
			}
		},
	}
}

// observe records one dial outcome. proves says whether a success on this
// kind of dial actually demonstrates the server is reachable.
//
// Only a TCP dial does. Shadowsocks's DialUDP opens a local socket and
// exchanges nothing with the server, so it succeeds against a server that is
// long gone; letting it reset the count would mean a phone's steady stream of
// DNS-over-UDP lookups keeps a dead tunnel "healthy" forever. A failed UDP
// dial, on the other hand, is still evidence and is counted.
func (h *streamHealth) observe(ctx context.Context, err error, proves bool) {
	if err == nil {
		if proves {
			h.mu.Lock()
			h.consecutive = 0
			h.mu.Unlock()
		}
		return
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		// The app or the stack gave up on the dial; the transport did nothing
		// wrong. A deadline, by contrast, is counted: a server that cannot
		// complete a TCP connect within the dial timeout is the commonest way
		// a dead one presents.
		return
	case errors.Is(err, transport.ErrUnsupportedFlow):
		// A capability, not a health signal: a transport that cannot carry
		// UDP refuses every UDP dial while TCP works perfectly.
		return
	case errors.Is(err, transport.ErrClosed):
		// The transport says outright it will carry nothing more. No point
		// waiting for N more apps to find out the hard way.
		h.dead(fmt.Errorf("engine: stream transport closed: %w", err))
		return
	}
	if h.threshold < 0 {
		return
	}

	h.mu.Lock()
	now := h.now()
	if h.consecutive == 0 || now.Sub(h.streakStart) > h.window {
		// Start a new streak: failures further apart than the window are
		// unrelated bad luck, not one outage.
		h.consecutive = 0
		h.streakStart = now
	}
	h.consecutive++
	n := h.consecutive
	h.mu.Unlock()

	if n >= h.threshold {
		h.dead(fmt.Errorf("engine: %d consecutive dials through the stream transport failed, last: %w", n, err))
	}
}

// startPacketPath sets the outbound sink and starts the inbound loop for a
// packet transport.
func (e *Engine) startPacketPath(sess *session, pipe transport.PacketPipe) {
	sess.sink = pipe.WritePacket

	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		// Headroom above the tunnel MTU: the peer sizes its packets to its own
		// MTU, which may exceed ours, and a short buffer would silently
		// truncate a packet into a corrupt one.
		buf := make([]byte, e.cfg.Tun.MTU()+128)
		for {
			n, err := pipe.ReadPacket(buf)
			if err != nil {
				// The only benign reason for a read to fail is that we are
				// tearing the session down, and the session context is the
				// authority on that — not the error value.
				//
				// Treating transport.ErrClosed as benign here instead was a
				// real bug: a transport that dies by closing itself is the
				// normal way a transport dies, and suppressing it left the
				// supervisor waiting forever on a session whose data path had
				// already exited. The engine reported StateConnected over a
				// tunnel that carried nothing, indefinitely, which for a
				// privacy product means the UI says "protected" while traffic
				// goes nowhere and the user never finds out.
				if sess.ctx.Err() == nil {
					sess.fail(fmt.Errorf("engine: reading from %s: %w", pipe.Name(), err))
				}
				return
			}
			if n == 0 {
				continue
			}
			e.countInbound(n)
			if err := e.cfg.Tun.WritePacket(buf[:n]); err != nil {
				if sess.ctx.Err() == nil {
					sess.fail(fmt.Errorf("engine: writing to the tunnel: %w", err))
				}
				return
			}
		}
	}()
}

// startStreamPath sets the outbound sink to the userspace stack and starts the
// inbound loop.
func (e *Engine) startStreamPath(sess *session, stack *netstack.Stack) {
	sess.sink = func(p []byte) error {
		if err := stack.DeliverInbound(p); err != nil {
			if errors.Is(err, netstack.ErrClosed) {
				return err
			}
			// A single rejected packet is not a session failure. One
			// misbehaving app sending oversize or malformed packets must not
			// tear down every other app's connections, so this is counted and
			// swallowed.
			e.readErrors.Add(1)
			e.coll.ParseError()
			return nil
		}
		return nil
	}

	sess.wg.Add(1)
	go func() {
		defer sess.wg.Done()
		buf := make([]byte, e.cfg.Tun.MTU())
		for {
			n, err := stack.ReadOutbound(buf)
			if err != nil {
				// As in startPacketPath: the session context decides whether
				// this is a teardown or a death. A stack that closed itself
				// while the session is still live is a failure, and
				// suppressing it would leave the engine reporting Connected
				// over a dead tunnel.
				if sess.ctx.Err() == nil {
					sess.fail(fmt.Errorf("engine: reading from the userspace stack: %w", err))
				}
				return
			}
			if n == 0 {
				continue
			}
			e.countInbound(n)
			if err := e.cfg.Tun.WritePacket(buf[:n]); err != nil {
				if sess.ctx.Err() == nil {
					sess.fail(fmt.Errorf("engine: writing to the tunnel: %w", err))
				}
				return
			}
		}
	}()
}

// runSession blocks until the session should end, and reports why.
func (e *Engine) runSession(ctx context.Context, sess *session) Reason {
	select {
	case <-ctx.Done():
		return ReasonUserRequested
	case <-e.networkChanged:
		e.state.transition(StateReconnecting, ReasonNetworkChanged, sess.tr.Name(), nil)
		return ReasonNetworkChanged
	case <-sess.failed:
		err := sess.failure()
		e.state.transition(StateReconnecting, ReasonTransportFail, sess.tr.Name(), err)
		return ReasonTransportFail
	}
}

func (e *Engine) countOutbound(p []byte) {
	e.packetsOut.Add(1)
	e.bytesOut.Add(uint64(len(p)))

	// Parsing on the hot path is not free, so it earns its place: this is
	// where a malformed packet from a local app is counted rather than
	// discovered later as an unexplained stack error.
	if _, err := packet.Parse(p); err != nil {
		if !errors.Is(err, packet.ErrUnsupportedProto) && !errors.Is(err, packet.ErrFragmented) {
			e.coll.ParseError()
		}
	}
}

func (e *Engine) countInbound(n int) {
	e.packetsIn.Add(1)
	e.bytesIn.Add(uint64(n))
}

func (e *Engine) recordRaceResult(res transport.Result) {
	if res.Won {
		return
	}
	outcome := metrics.OutcomeSuccess
	switch {
	case res.Err == nil:
	case errors.Is(res.Err, transport.ErrHandshakeTimeout),
		errors.Is(res.Err, context.DeadlineExceeded):
		// A candidate still in Up when the race's own deadline fires returns
		// the context's error, not the transport's timeout sentinel. It is the
		// same event — nothing answered — and it is the outcome that means
		// "probably blocked". Booking it as Refused, as the default case did,
		// would turn a censorship signal into a misconfiguration signal.
		outcome = metrics.OutcomeTimeout
	// TODO: OutcomeAuthFailed is never produced. Shadowsocks reports a key
	// mismatch as shadowsocks.ErrProbeFailed with the AEAD error flattened into
	// the message, so it cannot be told apart from any other probe failure,
	// and matching on a transport package here would undo the engine's
	// ignorance of transports anyway. It needs a transport.ErrAuthFailed
	// sentinel that each transport wraps.
	case errors.Is(res.Err, context.Canceled):
		outcome = metrics.OutcomeCancelled
	case errors.Is(res.Err, transport.ErrClosed):
		outcome = metrics.OutcomeError
	default:
		outcome = metrics.OutcomeRefused
	}
	e.coll.Attempt(res.Name, outcome, res.Latency)
}

func (e *Engine) recordFlow(ev netstack.FlowEvent) {
	e.coll.Flow(ev.Err != nil)
}

// Stats reports engine-level counters not covered by the metrics collector.
type Stats struct {
	Reconnects uint64
	PacketsIn  uint64
	PacketsOut uint64
	ReadErrors uint64
	// DroppedNoSession counts packets read off the tunnel while the engine was
	// between sessions. A steadily rising value means reconnects are taking
	// long enough to drop real traffic.
	DroppedNoSession uint64
	// RejectedTransitions counts state changes the transition table refused.
	// Non-zero is not necessarily a bug — a disconnect arriving mid-handshake
	// produces one — but a growing value means events are arriving in an order
	// the engine does not model.
	RejectedTransitions uint64
	ActiveTransport     string
	State               State
}

// Stats returns a snapshot of the engine's counters.
func (e *Engine) Stats() Stats {
	e.sessionMu.Lock()
	var active string
	if e.session != nil {
		active = e.session.tr.Name()
	}
	e.sessionMu.Unlock()

	return Stats{
		Reconnects:          e.reconnects.Load(),
		PacketsIn:           e.packetsIn.Load(),
		PacketsOut:          e.packetsOut.Load(),
		ReadErrors:          e.readErrors.Load(),
		DroppedNoSession:    e.droppedNoSession.Load(),
		RejectedTransitions: e.state.rejectedTransitions(),
		ActiveTransport:     active,
		State:               e.state.current(),
	}
}
