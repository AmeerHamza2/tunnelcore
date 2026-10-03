// Package mobile is the gomobile-bound API: the only surface Kotlin and Swift
// see.
//
// Everything exported here is constrained to what gomobile can translate into
// a Java or Objective-C type, which is a much smaller set than Go's: signed
// integers, float64, string, bool, []byte, error, and pointers to structs or
// interfaces declared in this package. No maps. No slices of anything but
// bytes. No generics, no variadics, no embedded types, no channels, no
// time.Duration, no uint of any width.
//
// Those restrictions are why this package looks the way it does — JSON strings
// for structured input and output, milliseconds as int, interfaces for
// callbacks — and why it exists at all rather than binding package engine
// directly. Keeping the whole bound surface in one small file also means the
// generated Kotlin and Swift APIs change only when somebody edits this file,
// so the mobile engineers are never surprised by a refactor two packages down.
//
// Threading contract, which the mobile side must honour: every method is safe
// to call from any thread, and Start returns immediately rather than blocking
// until the tunnel is up. Listener callbacks arrive on a Go goroutine, which
// on Android is *not* the main thread — a listener that touches UI must post
// to the main looper itself. Callbacks are serialised, in order, on one
// goroutine per Start that is separate from the engine's, so a listener may
// call any Tunnel method, Stop included.
package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameerhamza2/tunnelcore/dnsproxy"
	"github.com/ameerhamza2/tunnelcore/engine"
	"github.com/ameerhamza2/tunnelcore/metrics"
	"github.com/ameerhamza2/tunnelcore/transport"
	"github.com/ameerhamza2/tunnelcore/transport/protect"
	"github.com/ameerhamza2/tunnelcore/transport/shadowsocks"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// Errors surfaced to the mobile layer.
var (
	ErrTunnelRunning = errors.New("mobile: tunnel is already running")
	ErrBadFD         = errors.New("mobile: tunnel file descriptor is not valid")
)

// StateListener receives tunnel state changes.
//
// Implemented in Kotlin or Swift and passed in. All parameters are strings
// because gomobile cannot express an enum or a nullable error across the
// boundary; errMsg is empty when there is no error.
type StateListener interface {
	// OnStateChange is called for transitions, one call at a time, on a
	// dedicated callback goroutine. It may call back into the Tunnel —
	// including Stop — but should still return promptly: while it runs,
	// later changes queue, and if the queue overflows the oldest queued
	// intermediate states are dropped. The final state of a session
	// ("disconnected") is always delivered.
	OnStateChange(state string, reason string, transportName string, errMsg string)
}

// SocketProtector excludes one of the engine's sockets from the VPN route.
//
// On Android, implement it as a call to VpnService.protect(fd) and install it
// with SetSocketProtector before Start. Without it — and without excluding the
// app from its own VPN via addDisallowedApplication — the engine's connection
// to the exit node is routed into the tunnel it is trying to build, and the
// tunnel never comes up. iOS needs no protector: sockets opened inside an
// NEPacketTunnelProvider bypass the tunnel automatically.
//
// Protect returns false if the platform refused. The engine then fails the
// connection attempt rather than use an unprotected socket.
type SocketProtector interface {
	Protect(fd int) bool
}

// Tunnel is the handle the mobile app holds.
type Tunnel struct {
	mu        sync.Mutex
	eng       *engine.Engine
	tun       engine.TunDevice
	listener  StateListener
	protector SocketProtector
	coll      *metrics.Collector

	// pump delivers the running engine's state changes to the listener; see
	// callbackPump. One per Start, closed by Stop.
	pump *callbackPump

	// last is the most recently stopped engine, kept so StatsJSON after Stop
	// reports the finished session's totals instead of zeros — "how much did
	// that session use" is asked exactly when it has just ended.
	last *engine.Engine

	// cfgJSON is stored rather than the parsed config so that Start
	// re-parses on every call. That matters for a restart after Stop: an app
	// may update the configuration in between with SetConfig, and re-parsing
	// is both cheaper and less error-prone than diffing two parsed configs.
	cfgJSON string
}

// NewTunnel validates a configuration and returns a handle.
//
// No network or file-descriptor work happens here, so an app can construct
// this early and surface a configuration error to the user before asking the
// OS for VPN permission — which is a much better experience than being
// granted permission and then failing.
func NewTunnel(configJSON string) (*Tunnel, error) {
	if _, err := parseConfig(configJSON); err != nil {
		return nil, err
	}
	return &Tunnel{coll: metrics.New(), cfgJSON: configJSON}, nil
}

// SetConfig replaces the configuration used by the next Start. It validates
// first and leaves the old configuration in place on error. A running tunnel
// is unaffected until it is stopped and started again.
func (t *Tunnel) SetConfig(configJSON string) error {
	if _, err := parseConfig(configJSON); err != nil {
		return err
	}
	t.mu.Lock()
	t.cfgJSON = configJSON
	t.mu.Unlock()
	return nil
}

// SetSocketProtector installs the Android socket protector. Passing nil
// removes it. It takes effect at the next connection attempt.
func (t *Tunnel) SetSocketProtector(p SocketProtector) {
	t.mu.Lock()
	t.protector = p
	t.mu.Unlock()
}

// SetStateListener installs the state-change listener. Passing nil removes it.
func (t *Tunnel) SetStateListener(l StateListener) {
	t.mu.Lock()
	t.listener = l
	t.mu.Unlock()
}

// Start begins connecting over the given tunnel file descriptor.
//
// On Android, fd is the result of ParcelFileDescriptor.detachFd() on the
// descriptor VpnService.Builder.establish() returned. On iOS it is the
// equivalent from NEPacketTunnelProvider.
//
// Ownership of the descriptor transfers to the engine: Stop closes it, and the
// caller must not close it itself. detachFd rather than getFd matters for the
// same reason — two owners closing one descriptor is a use-after-close that
// manifests as the tunnel dying at a random later moment.
//
// Start returns as soon as the supervisor is running, not when the tunnel is
// established: a first connect can take seconds and the UI needs to render
// "Connecting" meanwhile. Watch the listener for StateConnected.
//
// Ownership transfers even on failure: if Start returns an error, the
// descriptor has already been closed. One rule with no exceptions is what
// stops the mobile side from either leaking the fd on an error path or
// closing it twice on a success path.
func (t *Tunnel) Start(fd int) (err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if fd < 0 {
		return fmt.Errorf("%w: %d", ErrBadFD, fd)
	}
	owned := true // until newFDTun takes it over
	defer func() {
		if err != nil && owned {
			_ = closeFD(fd)
		}
	}()

	if t.eng != nil {
		return ErrTunnelRunning
	}

	cfg, err := parseConfig(t.cfgJSON)
	if err != nil {
		return err
	}
	addrs, err := cfg.tunnelPrefixes()
	if err != nil {
		return err
	}
	upstreams, err := cfg.dnsUpstreams()
	if err != nil {
		return err
	}

	mtu := cfg.mtu()

	dev, err := newFDTun(fd, mtu)
	if err != nil {
		return err
	}
	owned = false // dev.Close is now the only way the fd gets closed

	var policy dnsproxy.Policy
	if len(cfg.BlockedDomains) > 0 {
		policy = newDenyList(cfg.BlockedDomains)
	}

	pump := newCallbackPump(t.currentListener)

	eng, err := engine.New(engine.Config{
		Tun:             dev,
		Provider:        &configProvider{cfg: cfg, mtu: mtu, protect: t.protectFunc},
		TunnelAddresses: addrs,
		DNSUpstreams:    upstreams,
		DNSPolicy:       policy,
		Metrics:         t.coll,
		RaceStagger:     msDuration(cfg.RaceStaggerMS),
		RaceTimeout:     msDuration(cfg.RaceTimeoutMS),
		OnStateChange:   pump.post,
	})
	if err != nil {
		_ = dev.Close()
		pump.closeAndDrain()
		return err
	}

	if err := eng.Start(); err != nil {
		_ = dev.Close()
		pump.closeAndDrain()
		return err
	}
	t.eng = eng
	t.tun = dev
	t.pump = pump
	t.last = nil
	return nil
}

// Stop tears the tunnel down and closes the file descriptor.
//
// It blocks until nothing is touching the descriptor any more, which is what
// makes it safe to call from a VpnService.onDestroy or a
// stopTunnel(with:completionHandler:). It is idempotent.
//
// When it returns, every state change of the session — "disconnected" last —
// has been delivered to the listener, with one exception: when Stop is called
// while a listener callback is running (typically from inside that callback),
// it does not wait for delivery, because the goroutine it would wait for is
// the one calling it. The remaining changes then follow as soon as that
// callback returns.
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	eng := t.eng
	pump := t.pump
	t.eng = nil
	t.tun = nil
	t.pump = nil
	if eng != nil {
		t.last = eng
	}
	t.mu.Unlock()

	if eng == nil {
		return nil
	}
	err := eng.Stop()
	// Only after eng.Stop: it emits "disconnecting" and "disconnected", and
	// both must be queued before the pump is closed or they would be lost.
	pump.closeAndDrain()
	return err
}

// State returns the current state as one of "idle", "connecting",
// "connected", "reconnecting", "disconnecting", "disconnected".
func (t *Tunnel) State() string {
	t.mu.Lock()
	eng := t.eng
	t.mu.Unlock()
	if eng == nil {
		return engine.StateIdle.String()
	}
	return eng.State().String()
}

// IsUp reports whether the tunnel is actually carrying traffic.
//
// This is deliberately stricter than "not disconnected": only the connected
// state counts. During a reconnect there is no transport, and a UI that shows
// a shield icon for "reconnecting" is telling the user they are protected when
// they are not.
func (t *Tunnel) IsUp() bool {
	t.mu.Lock()
	eng := t.eng
	t.mu.Unlock()
	return eng != nil && eng.State().IsUp()
}

// NetworkChanged tells the engine the device's network has changed.
//
// Call this from the platform connectivity callback — Android's
// ConnectivityManager.NetworkCallback, or the iOS equivalent. Calling it more
// often than necessary is safe and cheap: notifications are coalesced, so the
// several callbacks an OS emits during one wifi-to-cellular handover produce
// one reconnect.
func (t *Tunnel) NetworkChanged() {
	t.mu.Lock()
	eng := t.eng
	t.mu.Unlock()
	if eng != nil {
		eng.NetworkChanged()
	}
}

// StatsJSON returns current metrics as a JSON object.
//
// JSON because gomobile cannot return a struct with a map or a slice field,
// and the metric set is exactly that shape. The contents are all aggregates:
// there is no destination, hostname, or per-flow record in here, by design —
// see package metrics.
//
// After Stop it reports the finished session's totals with state
// "disconnected", until the next successful Start.
func (t *Tunnel) StatsJSON() string {
	t.mu.Lock()
	eng := t.eng
	stopped := false
	if eng == nil && t.last != nil {
		eng, stopped = t.last, true
	}
	t.mu.Unlock()

	var out statsJSON
	if eng != nil {
		snap := eng.Snapshot()
		st := eng.Stats()
		state := st.State.String()
		if stopped {
			// A Stop still in progress has the engine in "disconnecting";
			// from the app's side the tunnel is already gone.
			state = engine.StateDisconnected.String()
		}
		out = statsJSON{
			State:              state,
			ActiveTransport:    st.ActiveTransport,
			Reconnects:         st.Reconnects,
			PacketsIn:          st.PacketsIn,
			PacketsOut:         st.PacketsOut,
			DroppedNoSession:   st.DroppedNoSession,
			BytesUp:            snap.BytesUp,
			BytesDown:          snap.BytesDown,
			FlowsOpened:        snap.FlowsOpened,
			FlowsFailed:        snap.FlowsFailed,
			DNSQueries:         snap.DNSQueries,
			DNSBlocked:         snap.DNSBlocked,
			SessionSeconds:     int64(snap.SessionDuration.Seconds()),
			OverallSuccessRate: finiteOrNegative(snap.OverallSuccessRate),
		}
		for _, ts := range snap.Transports {
			out.Transports = append(out.Transports, transportStatsJSON{
				Name:        ts.Name,
				Attempts:    ts.Attempts,
				Successes:   ts.Successes,
				SuccessRate: finiteOrNegative(ts.SuccessRate),
				P50MS:       ts.LatencyP50.Milliseconds(),
				P95MS:       ts.LatencyP95.Milliseconds(),
				P99MS:       ts.LatencyP99.Milliseconds(),
			})
		}
	} else {
		out.State = engine.StateIdle.String()
		out.OverallSuccessRate = -1
	}

	b, err := json.Marshal(out)
	if err != nil {
		// Marshalling a struct of scalars cannot fail, but returning valid
		// JSON unconditionally means the mobile side never has to handle a
		// parse error here.
		return `{"error":"marshal failed"}`
	}
	return string(b)
}

type statsJSON struct {
	State            string `json:"state"`
	ActiveTransport  string `json:"active_transport"`
	Reconnects       uint64 `json:"reconnects"`
	PacketsIn        uint64 `json:"packets_in"`
	PacketsOut       uint64 `json:"packets_out"`
	DroppedNoSession uint64 `json:"dropped_no_session"`
	BytesUp          uint64 `json:"bytes_up"`
	BytesDown        uint64 `json:"bytes_down"`
	FlowsOpened      uint64 `json:"flows_opened"`
	FlowsFailed      uint64 `json:"flows_failed"`
	DNSQueries       uint64 `json:"dns_queries"`
	DNSBlocked       uint64 `json:"dns_blocked"`
	SessionSeconds   int64  `json:"session_seconds"`
	// OverallSuccessRate is -1 when there is no data, because JSON cannot
	// carry NaN and "no data" must stay distinguishable from "nothing works".
	OverallSuccessRate float64              `json:"overall_success_rate"`
	Transports         []transportStatsJSON `json:"transports,omitempty"`
}

type transportStatsJSON struct {
	Name        string  `json:"name"`
	Attempts    uint64  `json:"attempts"`
	Successes   uint64  `json:"successes"`
	SuccessRate float64 `json:"success_rate"`
	P50MS       int64   `json:"p50_ms"`
	P95MS       int64   `json:"p95_ms"`
	P99MS       int64   `json:"p99_ms"`
}

// GeneratePrivateKey returns a new WireGuard private key, base64-encoded.
//
// This is the most security-relevant function in the package, and the reason
// it lives on the client at all. The app calls it once, stores the result in
// the platform keystore (Android Keystore or the iOS Keychain), and registers
// only the *public* half with the control plane. The private key never leaves
// the device and the server never holds it, so a breach of the control-plane
// database cannot decrypt any user's past or future traffic.
//
// Any API where the server generates the pair and sends the private half down
// is a finding, not a shortcut — see docs/DUE_DILIGENCE_GAPS.md.
func GeneratePrivateKey() (string, error) {
	k, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	return k.Base64(), nil
}

// PublicKeyFor derives the base64 public key for a base64 private key, so the
// app can register a device without ever sending the private half.
func PublicKeyFor(privateKeyBase64 string) (string, error) {
	k, err := wireguard.ParseKey(privateKeyBase64)
	if err != nil {
		return "", err
	}
	return k.PublicKey().Base64(), nil
}

// SupportedCiphers returns the Shadowsocks cipher names this build accepts, as
// a comma-separated list. A comma-separated string rather than a slice because
// gomobile cannot bind []string.
func SupportedCiphers() string {
	return strings.Join(shadowsocks.SupportedMethods(), ",")
}

// Version returns the engine version, which a support bundle should include.
func Version() string { return version }

// version is set at build time with -ldflags "-X ...mobile.version=...".
var version = "dev"

// --- internals ---

// defaultTunnelMTU is used when the config does not specify one.
const defaultTunnelMTU = 1420

// protectFunc reads the current protector at call time, so a protector
// installed or replaced while the engine is reconnecting is picked up by the
// next attempt.
func (t *Tunnel) protectFunc() protect.Func {
	t.mu.Lock()
	p := t.protector
	t.mu.Unlock()
	if p == nil {
		return nil
	}
	return protect.FromBool(p.Protect)
}

func (t *Tunnel) currentListener() StateListener {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.listener
}

// callbackQueueDepth bounds the state changes waiting for a slow listener.
// A session produces a handful of changes per reconnect, so 64 is only
// reached by a listener that is stuck, and then dropping its oldest
// backlog is better than growing without bound.
const callbackQueueDepth = 64

// callbackPump delivers engine state changes to the listener on its own
// goroutine.
//
// The engine calls its observer synchronously, from whichever goroutine made
// the transition — the supervisor, or the caller of Stop. Calling the
// listener directly from there meant a listener that reacted to
// "disconnected" by calling Tunnel.Stop (the obvious thing for a UI to do on
// a give-up) deadlocked: Stop waits for the supervisor, which was waiting for
// the listener to return. It also let a slow listener stall the data path.
//
// So post never blocks: it enqueues, and if the queue is full it drops the
// oldest entry. The newest change always gets in, so the final state of a
// session is never the one dropped.
type callbackPump struct {
	listener func() StateListener

	mu     sync.Mutex
	ch     chan engine.Change
	closed bool

	done chan struct{}
	// gid is the delivery goroutine's id; see closeAndDrain.
	gid atomic.Uint64
}

func newCallbackPump(listener func() StateListener) *callbackPump {
	p := &callbackPump{
		listener: listener,
		ch:       make(chan engine.Change, callbackQueueDepth),
		done:     make(chan struct{}),
	}
	go p.run()
	return p
}

// post queues c for delivery. It never blocks, and drops c only after close.
func (p *callbackPump) post(c engine.Change) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	for {
		select {
		case p.ch <- c:
			return
		default:
		}
		// Full: make room by discarding the oldest. The consumer may take
		// one concurrently, in which case there is nothing to discard and
		// the retry succeeds anyway.
		select {
		case <-p.ch:
		default:
		}
	}
}

func (p *callbackPump) run() {
	defer close(p.done)
	p.gid.Store(goroutineID())
	for c := range p.ch {
		// Read at delivery time, so SetStateListener takes effect for
		// changes already queued.
		l := p.listener()
		if l == nil {
			continue
		}
		var msg string
		if c.Err != nil {
			msg = c.Err.Error()
		}
		l.OnStateChange(c.To.String(), string(c.Reason), c.Transport, msg)
	}
}

// closeAndDrain stops accepting changes and waits until everything already
// queued has been delivered — unless it is called on the delivery goroutine
// itself, i.e. Stop from inside OnStateChange. (A gomobile call back into Go
// from within a callback runs on the goroutine that made the callback, so
// the identity check is exact.) Waiting there would wait for ourselves, so it
// returns and the pump finishes delivering once the callback returns.
func (p *callbackPump) closeAndDrain() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.ch)
	}
	p.mu.Unlock()
	if goroutineID() == p.gid.Load() {
		return
	}
	<-p.done
}

// goroutineID returns the current goroutine's id, parsed from the header
// runtime.Stack writes ("goroutine 123 [running]:").
//
// Go deliberately has no API for this, and nothing here uses it as
// goroutine-local storage; it answers exactly one question — "am I the
// delivery goroutine?" — on the Stop path, which is rare enough that the
// cost of formatting a stack header does not matter.
func goroutineID() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	if i := bytes.IndexByte(b, ' '); i > 0 {
		b = b[:i]
	}
	id, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// configProvider builds fresh transport instances for each connection attempt.
//
// Fresh instances rather than reused ones: a Transport that has been closed
// stays closed by contract, so reusing the same objects across a reconnect
// would hand the racer a list of permanently-dead candidates.
type configProvider struct {
	cfg     *config
	mtu     int
	protect func() protect.Func
}

func (p *configProvider) Candidates(ctx context.Context) ([]transport.Transport, error) {
	out := make([]transport.Transport, 0, len(p.cfg.Servers))
	var prot protect.Func
	if p.protect != nil {
		prot = p.protect()
	}
	var firstErr error

	for i := range p.cfg.Servers {
		s := &p.cfg.Servers[i]
		var (
			tr  transport.Transport
			err error
		)
		switch s.Protocol {
		case protoWireGuard:
			var wcfg wireguard.Config
			wcfg, err = s.wireguardConfig(p.mtu)
			wcfg.Protect = prot
			if err == nil {
				tr, err = wireguard.New(wcfg)
			}
		case protoShadowsocks:
			var scfg shadowsocks.Config
			scfg, err = s.shadowsocksConfig()
			scfg.Protect = prot
			if err == nil {
				tr, err = shadowsocks.New(scfg)
			}
		default:
			err = fmt.Errorf("%w: %q", ErrUnknownProto, s.Protocol)
		}

		if err != nil {
			// One malformed server entry must not disable the others: a
			// control plane that ships a bad record for one region should
			// cost that region, not the whole product.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, tr)
	}

	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, ErrNoServers
	}
	return out, nil
}

// denyList is a dnsproxy.Policy backed by an exact-match set plus suffix
// matching, so blocking "doubleclick.net" also blocks its subdomains.
type denyList struct {
	exact    map[string]struct{}
	suffixes []string
}

func newDenyList(names []string) *denyList {
	d := &denyList{exact: make(map[string]struct{}, len(names))}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		d.exact[n] = struct{}{}
		d.suffixes = append(d.suffixes, "."+n)
	}
	return d
}

func (d *denyList) Allow(name string, _ uint16) bool {
	if _, blocked := d.exact[name]; blocked {
		return false
	}
	for _, suffix := range d.suffixes {
		if strings.HasSuffix(name, suffix) {
			return false
		}
	}
	return true
}

func msDuration(ms int) time.Duration {
	if ms <= 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

// finiteOrNegative maps NaN to -1 so the value survives JSON, which has no
// representation for NaN.
func finiteOrNegative(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return -1
	}
	return v
}

func stringReader(s string) io.Reader { return strings.NewReader(s) }
