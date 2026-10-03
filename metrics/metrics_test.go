package metrics

import (
	"fmt"
	"math"
	"sync"
	"testing"
	"time"
)

func TestSuccessRate(t *testing.T) {
	c := New()
	c.Attempt("wireguard/fra-01", OutcomeSuccess, 80*time.Millisecond)
	c.Attempt("wireguard/fra-01", OutcomeSuccess, 95*time.Millisecond)
	c.Attempt("wireguard/fra-01", OutcomeTimeout, 5*time.Second)
	c.Attempt("wireguard/fra-01", OutcomeRefused, 10*time.Millisecond)

	s := c.Snapshot()
	if len(s.Transports) != 1 {
		t.Fatalf("got %d transports, want 1", len(s.Transports))
	}
	ts := s.Transports[0]
	if ts.Attempts != 4 {
		t.Errorf("Attempts = %d, want 4", ts.Attempts)
	}
	if ts.Successes != 2 {
		t.Errorf("Successes = %d, want 2", ts.Successes)
	}
	if ts.SuccessRate != 0.5 {
		t.Errorf("SuccessRate = %v, want 0.5", ts.SuccessRate)
	}
	if ts.Outcomes[OutcomeTimeout] != 1 || ts.Outcomes[OutcomeRefused] != 1 {
		t.Errorf("outcome breakdown = %v", ts.Outcomes)
	}
}

// TestCancelledAttemptsExcludedFromSuccessRate is the property that makes the
// metric usable at all. The racer deliberately starts candidates it intends to
// abandon, so counting abandonment as failure would peg a healthy client
// racing three candidates at 33% forever and the alarm would never mean
// anything.
func TestCancelledAttemptsExcludedFromSuccessRate(t *testing.T) {
	c := New()
	c.Attempt("wg", OutcomeSuccess, 50*time.Millisecond)
	c.Attempt("ss", OutcomeCancelled, 20*time.Millisecond)
	c.Attempt("ss2", OutcomeCancelled, 20*time.Millisecond)

	s := c.Snapshot()
	if s.OverallSuccessRate != 1.0 {
		t.Errorf("OverallSuccessRate = %v, want 1.0; cancelled candidates were counted as failures",
			s.OverallSuccessRate)
	}

	// The cancellations are still visible in the breakdown — they are useful
	// for understanding racer behaviour, just not for the rate.
	for _, ts := range s.Transports {
		if ts.Name == "ss" {
			if ts.Outcomes[OutcomeCancelled] != 1 {
				t.Error("the cancellation was not recorded in the outcome breakdown")
			}
			if ts.Attempts != 0 {
				t.Errorf("a cancelled candidate contributed %d to Attempts, want 0", ts.Attempts)
			}
		}
	}
}

// TestNoDataIsNaNNotZero: "no data" and "nothing has ever worked" are
// different alerts, and reporting zero for the former fires the wrong one.
func TestNoDataIsNaNNotZero(t *testing.T) {
	c := New()
	s := c.Snapshot()
	if !math.IsNaN(s.OverallSuccessRate) {
		t.Errorf("OverallSuccessRate with no data = %v, want NaN", s.OverallSuccessRate)
	}

	c.Attempt("wg", OutcomeCancelled, time.Millisecond)
	s = c.Snapshot()
	if !math.IsNaN(s.Transports[0].SuccessRate) {
		t.Errorf("SuccessRate with only cancellations = %v, want NaN", s.Transports[0].SuccessRate)
	}
}

// TestLatencyHistogramOnlyRecordsSuccesses: mixing timeouts in would make the
// p99 a restatement of the timeout constant rather than a measurement.
func TestLatencyHistogramOnlyRecordsSuccesses(t *testing.T) {
	c := New()
	for i := 0; i < 10; i++ {
		c.Attempt("wg", OutcomeSuccess, 100*time.Millisecond)
	}
	c.Attempt("wg", OutcomeTimeout, 30*time.Second)

	s := c.Snapshot()
	if p99 := s.Transports[0].LatencyP99; p99 > time.Second {
		t.Errorf("LatencyP99 = %s; the 30s timeout was folded into the histogram", p99)
	}
}

func TestOverallSuccessRateAggregates(t *testing.T) {
	c := New()
	c.Attempt("a", OutcomeSuccess, time.Millisecond)
	c.Attempt("a", OutcomeTimeout, time.Millisecond)
	c.Attempt("b", OutcomeSuccess, time.Millisecond)
	c.Attempt("b", OutcomeSuccess, time.Millisecond)

	s := c.Snapshot()
	if want := 0.75; s.OverallSuccessRate != want {
		t.Errorf("OverallSuccessRate = %v, want %v", s.OverallSuccessRate, want)
	}
}

func TestSnapshotTransportOrderIsStable(t *testing.T) {
	c := New()
	for _, name := range []string{"zulu", "alpha", "mike"} {
		c.Attempt(name, OutcomeSuccess, time.Millisecond)
	}
	s := c.Snapshot()
	want := []string{"alpha", "mike", "zulu"}
	for i, ts := range s.Transports {
		if ts.Name != want[i] {
			t.Errorf("Transports[%d] = %q, want %q; unsorted output makes two snapshots undiffable",
				i, ts.Name, want[i])
		}
	}
}

func TestSessionTracking(t *testing.T) {
	c := New()
	base := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var now time.Time
	now = base
	c.now = func() time.Time { return now }

	c.SessionStarted("wireguard/fra-01")
	now = base.Add(90 * time.Second)

	s := c.Snapshot()
	if s.SessionDuration != 90*time.Second {
		t.Errorf("SessionDuration = %s, want 90s", s.SessionDuration)
	}
	if s.ActiveTransport != "wireguard/fra-01" {
		t.Errorf("ActiveTransport = %q", s.ActiveTransport)
	}
	if s.Reconnects != 0 {
		t.Errorf("Reconnects = %d on a first session, want 0", s.Reconnects)
	}

	// A second SessionStarted without an intervening end is a reconnect.
	c.SessionStarted("shadowsocks/sgp-01")
	if s := c.Snapshot(); s.Reconnects != 1 {
		t.Errorf("Reconnects = %d after a second start, want 1", s.Reconnects)
	}

	c.SessionEnded()
	if s := c.Snapshot(); s.SessionDuration != 0 {
		t.Errorf("SessionDuration = %s after SessionEnded, want 0", s.SessionDuration)
	}
}

// TestSessionEndedBetweenSessions pins the sequence the engine now produces on
// every reconnect — start, end, start — rather than only start, start. The
// reconnect must still be counted, and the gap between sessions must read as
// no session at all.
func TestSessionEndedBetweenSessions(t *testing.T) {
	c := New()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }

	c.SessionStarted("wireguard/fra-01")
	now = now.Add(time.Minute)
	c.SessionEnded()
	now = now.Add(time.Minute) // reconnecting

	s := c.Snapshot()
	if s.SessionDuration != 0 || s.ActiveTransport != "" {
		t.Errorf("between sessions: SessionDuration = %s, ActiveTransport = %q; want 0 and empty",
			s.SessionDuration, s.ActiveTransport)
	}

	c.Reset() // an upload mid-reconnect must not forget that a session existed
	c.SessionStarted("shadowsocks/sgp-01")
	if s := c.Snapshot(); s.Reconnects != 1 {
		t.Errorf("Reconnects = %d after start, end, start; want 1", s.Reconnects)
	}
	c.SessionEnded()
	c.SessionEnded() // idempotent: the engine's Stop ends a session already ended
	if s := c.Snapshot(); s.Reconnects != 1 || s.SessionDuration != 0 {
		t.Errorf("after a double SessionEnded: Reconnects = %d, SessionDuration = %s", s.Reconnects, s.SessionDuration)
	}
}

func TestTrafficAndDropCounters(t *testing.T) {
	c := New()
	c.TunnelTraffic(1000, 5000, 10, 40)
	c.TunnelTraffic(500, 2500, 5, 20)
	c.Dropped(3, 7)
	c.ParseError()
	c.ParseError()
	c.Flow(false)
	c.Flow(true)
	c.DNSQuery(false)
	c.DNSQuery(true)

	s := c.Snapshot()
	checks := map[string][2]uint64{
		"BytesUp":         {s.BytesUp, 1500},
		"BytesDown":       {s.BytesDown, 7500},
		"PacketsUp":       {s.PacketsUp, 15},
		"PacketsDown":     {s.PacketsDown, 60},
		"DroppedInbound":  {s.DroppedInbound, 3},
		"DroppedOutbound": {s.DroppedOutbound, 7},
		"ParseErrors":     {s.ParseErrors, 2},
		"FlowsOpened":     {s.FlowsOpened, 2},
		"FlowsFailed":     {s.FlowsFailed, 1},
		"DNSQueries":      {s.DNSQueries, 2},
		"DNSBlocked":      {s.DNSBlocked, 1},
	}
	for name, v := range checks {
		if v[0] != v[1] {
			t.Errorf("%s = %d, want %d", name, v[0], v[1])
		}
	}
}

// TestResetKeepsSessionState: a snapshot is a delta, so counters reset — but
// zeroing the session start would make the next snapshot report a zero-length
// session on a tunnel that is still up.
func TestResetKeepsSessionState(t *testing.T) {
	c := New()
	c.SessionStarted("wg")
	c.Attempt("wg", OutcomeSuccess, time.Millisecond)
	c.TunnelTraffic(100, 200, 1, 2)

	time.Sleep(10 * time.Millisecond)
	c.Reset()

	s := c.Snapshot()
	if s.BytesUp != 0 || len(s.Transports) != 0 {
		t.Error("Reset did not clear the counters")
	}
	if s.ActiveTransport != "wg" {
		t.Errorf("ActiveTransport = %q after Reset, want it preserved", s.ActiveTransport)
	}
	if s.SessionDuration == 0 {
		t.Error("SessionDuration = 0 after Reset on a live session; the session start was cleared")
	}
}

// TestSnapshotOutcomeMapIsACopy: handing out the live map would let a caller
// mutate the collector's state, and would race with the next Attempt.
func TestSnapshotOutcomeMapIsACopy(t *testing.T) {
	c := New()
	c.Attempt("wg", OutcomeSuccess, time.Millisecond)

	s := c.Snapshot()
	s.Transports[0].Outcomes[OutcomeTimeout] = 999

	s2 := c.Snapshot()
	if s2.Transports[0].Outcomes[OutcomeTimeout] != 0 {
		t.Error("Snapshot handed out the collector's live outcome map")
	}
}

// TestConcurrentCollection is the only concurrency contract this package has:
// the engine calls into it from the tunnel reader, the writer, every flow
// goroutine and the racer simultaneously.
func TestConcurrentCollection(t *testing.T) {
	c := New()
	const workers = 32
	const each = 200

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			name := fmt.Sprintf("transport-%d", w%4)
			for i := 0; i < each; i++ {
				switch i % 5 {
				case 0:
					c.Attempt(name, OutcomeSuccess, time.Duration(i)*time.Millisecond)
				case 1:
					c.Attempt(name, OutcomeTimeout, time.Second)
				case 2:
					c.TunnelTraffic(100, 200, 1, 2)
				case 3:
					c.Flow(i%7 == 0)
				case 4:
					_ = c.Snapshot()
				}
			}
		}(w)
	}
	wg.Wait()

	s := c.Snapshot()
	var attempts uint64
	for _, ts := range s.Transports {
		attempts += ts.Attempts
	}
	// Each worker records 40 successes and 40 timeouts across `each`
	// iterations.
	if want := uint64(workers * each / 5 * 2); attempts != want {
		t.Errorf("total attempts = %d, want %d", attempts, want)
	}
}

// --- histogram ---

func TestHistogramQuantiles(t *testing.T) {
	h := newHistogram()
	// 100 observations: 90 at 50ms, 9 at 500ms, 1 at 5s.
	for i := 0; i < 90; i++ {
		h.observe(50 * time.Millisecond)
	}
	for i := 0; i < 9; i++ {
		h.observe(500 * time.Millisecond)
	}
	h.observe(5 * time.Second)

	if p50 := h.quantile(0.50); p50 != 50*time.Millisecond {
		t.Errorf("p50 = %s, want 50ms", p50)
	}
	if p95 := h.quantile(0.95); p95 != 500*time.Millisecond {
		t.Errorf("p95 = %s, want 500ms", p95)
	}
	if p99 := h.quantile(0.99); p99 != 500*time.Millisecond {
		t.Errorf("p99 = %s, want 500ms", p99)
	}
	if max := h.quantile(1.0); max != 5*time.Second {
		t.Errorf("p100 = %s, want 5s", max)
	}
}

func TestHistogramEmpty(t *testing.T) {
	h := newHistogram()
	if got := h.quantile(0.5); got != 0 {
		t.Errorf("quantile on an empty histogram = %s, want 0", got)
	}
	if got := h.mean(); got != 0 {
		t.Errorf("mean on an empty histogram = %s, want 0", got)
	}
}

// TestHistogramOverflowBucketReportsMax: returning "+Inf" for a p99 is useless
// on a dashboard, so the overflow bucket reports the observed maximum.
func TestHistogramOverflowBucketReportsMax(t *testing.T) {
	h := newHistogram()
	h.observe(45 * time.Second) // past the last bound

	if got := h.quantile(0.99); got != 45*time.Second {
		t.Errorf("p99 = %s, want the observed max of 45s", got)
	}
}

// TestHistogramIgnoresNegativeDurations: on mobile, the OS corrects the clock
// after a suspend and a naive elapsed-time calculation goes negative.
// Admitting those would corrupt the sum and the mean.
func TestHistogramIgnoresNegativeDurations(t *testing.T) {
	h := newHistogram()
	h.observe(100 * time.Millisecond)
	h.observe(-5 * time.Second)

	if h.total != 1 {
		t.Errorf("total = %d, want 1; the negative observation was admitted", h.total)
	}
	if mean := h.mean(); mean != 100*time.Millisecond {
		t.Errorf("mean = %s, want 100ms", mean)
	}
}

func TestHistogramMeanIsExact(t *testing.T) {
	h := newHistogram()
	h.observe(100 * time.Millisecond)
	h.observe(200 * time.Millisecond)
	h.observe(300 * time.Millisecond)

	if got, want := h.mean(), 200*time.Millisecond; got != want {
		t.Errorf("mean = %s, want %s", got, want)
	}
}

// TestHistogramMemoryIsConstant is the reason for fixed buckets rather than a
// reservoir: this runs on a phone and must not grow with the observation
// count.
func TestHistogramMemoryIsConstant(t *testing.T) {
	h := newHistogram()
	for i := 0; i < 1_000_000; i++ {
		h.observe(time.Duration(i%2000) * time.Millisecond)
	}
	if h.total != 1_000_000 {
		t.Errorf("total = %d, want 1000000", h.total)
	}
	// The struct is fixed-size by construction; this asserts the bucket count
	// has not been made dynamic by a later change.
	if got, want := len(h.counts), len(histogramBounds)+1; got != want {
		t.Errorf("bucket count = %d, want %d", got, want)
	}
}

func BenchmarkAttempt(b *testing.B) {
	c := New()
	b.ReportAllocs()
	for b.Loop() {
		c.Attempt("wireguard/fra-01", OutcomeSuccess, 85*time.Millisecond)
	}
}

func BenchmarkAttemptConcurrent(b *testing.B) {
	c := New()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Attempt("wireguard/fra-01", OutcomeSuccess, 85*time.Millisecond)
		}
	})
}

func BenchmarkSnapshot(b *testing.B) {
	c := New()
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("transport-%d", i)
		for j := 0; j < 100; j++ {
			c.Attempt(name, OutcomeSuccess, time.Duration(j)*time.Millisecond)
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Snapshot()
	}
}

func BenchmarkHistogramObserve(b *testing.B) {
	h := newHistogram()
	b.ReportAllocs()
	for b.Loop() {
		h.observe(85 * time.Millisecond)
	}
}
