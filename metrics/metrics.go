// Package metrics collects the handful of numbers that actually tell you
// whether a consumer VPN is working.
//
// The three that matter, and why:
//
//	Connection success rate   The fraction of connection attempts that reach a
//	                          completed handshake, sliced by transport and
//	                          region. This is the number that tells you a
//	                          protocol has been blocked on a network before
//	                          your support queue does. A drop for Shadowsocks
//	                          while WireGuard holds is a DPI signature update;
//	                          the reverse is usually a routing problem.
//
//	Handshake latency         Not for vanity — for the racer. The stagger and
//	                          timeout constants in package transport are only
//	                          defensible against a measured distribution, and
//	                          the p99 is what decides whether a user gives up
//	                          before the tunnel comes up.
//
//	Tunnel throughput and     Drops here distinguish "the VPN is slow" from
//	drops                     "the VPN is silently shedding traffic", which
//	                          look identical to a user and have completely
//	                          different causes.
//
// Everything here is in-process and aggregate. That is a privacy requirement,
// not a simplification: this is a privacy product, so the engine records
// counters and histograms, never per-flow records, never destination
// addresses, and never anything that could reconstruct a user's browsing. The
// Snapshot a client uploads contains no field that identifies a person or a
// site. See docs/DUE_DILIGENCE_GAPS.md for the retention policy this is
// designed to satisfy.
package metrics

import (
	"maps"
	"math"
	"sort"
	"sync"
	"time"
)

// Outcome classifies one connection attempt.
type Outcome string

const (
	// OutcomeSuccess means a handshake completed and the transport is usable.
	OutcomeSuccess Outcome = "success"
	// OutcomeTimeout means the transport never responded. On a restrictive
	// network this is the overwhelmingly common failure, and it is the one
	// that means "probably blocked".
	OutcomeTimeout Outcome = "timeout"
	// OutcomeRefused means something actively rejected the attempt, which
	// usually means a misconfigured or decommissioned server rather than
	// censorship.
	OutcomeRefused Outcome = "refused"
	// OutcomeAuthFailed means credentials were rejected: a rotated key or
	// password that clients were not updated for.
	OutcomeAuthFailed Outcome = "auth_failed"
	// OutcomeCancelled means the attempt was abandoned because another
	// candidate won the race, or the user disconnected. These are explicitly
	// *not* counted in the success rate denominator; see Attempt.
	OutcomeCancelled Outcome = "cancelled"
	// OutcomeError is anything else.
	OutcomeError Outcome = "error"
)

// transportStats accumulates per-transport counters.
type transportStats struct {
	attempts  uint64
	successes uint64
	outcomes  map[Outcome]uint64
	latency   *histogram
}

func newTransportStats() *transportStats {
	return &transportStats{
		outcomes: make(map[Outcome]uint64),
		latency:  newHistogram(),
	}
}

// Collector is the engine's metrics sink. It is safe for concurrent use.
type Collector struct {
	mu sync.Mutex

	byTransport map[string]*transportStats

	// Tunnel counters.
	bytesUp         uint64
	bytesDown       uint64
	packetsUp       uint64
	packetsDown     uint64
	droppedInbound  uint64
	droppedOutbound uint64
	parseErrors     uint64

	// Flow counters.
	flowsOpened uint64
	flowsFailed uint64
	dnsQueries  uint64
	dnsBlocked  uint64

	// Session state.
	sessionStart  time.Time
	reconnects    uint64
	lastTransport string
	// hadSession records that some session has started, so that the next
	// SessionStarted counts as a reconnect even when SessionEnded came in
	// between — which, now that the engine ends each session as it goes down
	// rather than only on Stop, is every reconnect.
	hadSession bool

	now func() time.Time
}

// New returns an empty Collector.
func New() *Collector {
	return &Collector{
		byTransport: make(map[string]*transportStats),
		now:         time.Now,
	}
}

// Attempt records one connection attempt.
//
// Cancelled attempts are recorded in the outcome breakdown but excluded from
// both the numerator and the denominator of the success rate. This is the
// difference between a metric that means something and one that does not: the
// racer deliberately starts candidates it intends to abandon, so counting
// abandonment as failure would peg a perfectly healthy client racing three
// candidates at a 33% success rate permanently, and the number would stop
// being an alarm.
func (c *Collector) Attempt(transport string, outcome Outcome, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ts, ok := c.byTransport[transport]
	if !ok {
		ts = newTransportStats()
		c.byTransport[transport] = ts
	}
	ts.outcomes[outcome]++

	if outcome == OutcomeCancelled {
		return
	}
	ts.attempts++
	if outcome == OutcomeSuccess {
		ts.successes++
		// Only successful handshakes go into the latency histogram. Mixing in
		// timeouts would make the p99 a restatement of the timeout constant
		// rather than a measurement of the network.
		ts.latency.observe(latency)
	}
}

// SessionStarted marks a tunnel coming up on the named transport.
func (c *Collector) SessionStarted(transport string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hadSession {
		c.reconnects++
	}
	c.hadSession = true
	c.sessionStart = c.now()
	c.lastTransport = transport
}

// SessionEnded marks the tunnel going down: SessionDuration reads zero and
// ActiveTransport empty until the next SessionStarted.
//
// The engine calls this whenever a session ends, not only on Stop. When it
// was only called on Stop, a dropped tunnel kept reporting a growing
// SessionDuration on its old transport for the whole reconnect — and forever
// after a give-up — so a snapshot taken mid-outage described a healthy tunnel.
// It is idempotent.
func (c *Collector) SessionEnded() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionStart = time.Time{}
	c.lastTransport = ""
}

// TunnelTraffic records bytes and packets moved in each direction.
func (c *Collector) TunnelTraffic(up, down uint64, packetsUp, packetsDown uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytesUp += up
	c.bytesDown += down
	c.packetsUp += packetsUp
	c.packetsDown += packetsDown
}

// Dropped records packets discarded rather than forwarded: because a queue
// was full, because no session existed to take them, or because the
// userspace stack refused them. Outbound is the device-to-network direction
// (the one BytesUp counts), inbound the reverse.
func (c *Collector) Dropped(inbound, outbound uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.droppedInbound += inbound
	c.droppedOutbound += outbound
}

// ParseError records a packet the parser rejected.
func (c *Collector) ParseError() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.parseErrors++
}

// Flow records one proxied flow's outcome.
func (c *Collector) Flow(failed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.flowsOpened++
	if failed {
		c.flowsFailed++
	}
}

// DNSQuery records a query answered inside the tunnel. blocked reports
// whether policy refused it.
func (c *Collector) DNSQuery(blocked bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dnsQueries++
	if blocked {
		c.dnsBlocked++
	}
}

// TransportSnapshot is the per-transport view.
type TransportSnapshot struct {
	Name      string
	Attempts  uint64
	Successes uint64
	// SuccessRate is in [0,1], or NaN when there have been no countable
	// attempts. NaN rather than zero on purpose: "no data" and "nothing has
	// ever worked" are different alerts, and a zero would fire the wrong one.
	SuccessRate float64
	Outcomes    map[Outcome]uint64

	LatencyP50 time.Duration
	LatencyP95 time.Duration
	LatencyP99 time.Duration
}

// Snapshot is a point-in-time view of every counter.
//
// This is the shape that gets uploaded. Every field is an aggregate; there is
// deliberately no destination, no address, no hostname and no timestamp finer
// than the session duration.
type Snapshot struct {
	Transports []TransportSnapshot

	BytesUp         uint64
	BytesDown       uint64
	PacketsUp       uint64
	PacketsDown     uint64
	DroppedInbound  uint64
	DroppedOutbound uint64
	ParseErrors     uint64

	FlowsOpened uint64
	FlowsFailed uint64
	DNSQueries  uint64
	DNSBlocked  uint64

	Reconnects      uint64
	SessionDuration time.Duration
	ActiveTransport string

	// OverallSuccessRate aggregates across transports, which is the headline
	// number. NaN when there is no data; see TransportSnapshot.SuccessRate.
	OverallSuccessRate float64
}

// Snapshot returns the current values.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := Snapshot{
		BytesUp:         c.bytesUp,
		BytesDown:       c.bytesDown,
		PacketsUp:       c.packetsUp,
		PacketsDown:     c.packetsDown,
		DroppedInbound:  c.droppedInbound,
		DroppedOutbound: c.droppedOutbound,
		ParseErrors:     c.parseErrors,
		FlowsOpened:     c.flowsOpened,
		FlowsFailed:     c.flowsFailed,
		DNSQueries:      c.dnsQueries,
		DNSBlocked:      c.dnsBlocked,
		Reconnects:      c.reconnects,
		ActiveTransport: c.lastTransport,
	}
	if !c.sessionStart.IsZero() {
		s.SessionDuration = c.now().Sub(c.sessionStart)
	}

	var totalAttempts, totalSuccesses uint64
	names := make([]string, 0, len(c.byTransport))
	for name := range c.byTransport {
		names = append(names, name)
	}
	sort.Strings(names) // stable output, so a diff of two snapshots is readable

	for _, name := range names {
		ts := c.byTransport[name]
		snap := TransportSnapshot{
			Name:        name,
			Attempts:    ts.attempts,
			Successes:   ts.successes,
			SuccessRate: rate(ts.successes, ts.attempts),
			Outcomes:    maps.Clone(ts.outcomes),
			LatencyP50:  ts.latency.quantile(0.50),
			LatencyP95:  ts.latency.quantile(0.95),
			LatencyP99:  ts.latency.quantile(0.99),
		}
		s.Transports = append(s.Transports, snap)
		totalAttempts += ts.attempts
		totalSuccesses += ts.successes
	}
	s.OverallSuccessRate = rate(totalSuccesses, totalAttempts)
	return s
}

func rate(successes, attempts uint64) float64 {
	if attempts == 0 {
		return math.NaN()
	}
	return float64(successes) / float64(attempts)
}

// Reset clears every counter, which the engine does after a successful upload
// so that a snapshot is a delta rather than a lifetime total.
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.byTransport = make(map[string]*transportStats)
	c.bytesUp, c.bytesDown = 0, 0
	c.packetsUp, c.packetsDown = 0, 0
	c.droppedInbound, c.droppedOutbound = 0, 0
	c.parseErrors = 0
	c.flowsOpened, c.flowsFailed = 0, 0
	c.dnsQueries, c.dnsBlocked = 0, 0
	c.reconnects = 0
	// sessionStart and lastTransport survive: the session is still running,
	// and zeroing them would make the next snapshot report a zero-length
	// session on an up tunnel. hadSession survives too, or the first
	// reconnect after an upload would go uncounted.
}
