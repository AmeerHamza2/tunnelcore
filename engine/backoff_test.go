package engine

import (
	"math"
	"testing"
	"time"
)

func TestBackoffCeilingGrowsExponentiallyAndClamps(t *testing.T) {
	b := &Backoff{Base: 100 * time.Millisecond, Max: 2 * time.Second}

	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1600 * time.Millisecond,
		2 * time.Second, // clamped
		2 * time.Second,
		2 * time.Second,
	}
	for attempt, w := range want {
		if got := b.Ceiling(attempt); got != w {
			t.Errorf("Ceiling(%d) = %s, want %s", attempt, got, w)
		}
	}
}

// TestBackoffDelayIsFullJitter is the property that matters operationally.
//
// Without jitter, every client displaced by a server or region failure waits
// the same delay and retries in lockstep, so the replacement server receives
// the entire population as a single synchronised spike, sheds load, and the
// still-synchronised clients do it again at the next interval — the outage
// lasts as long as the retry pattern. Full jitter spreads them over the whole
// window, so the replacement sees a ramp.
//
// This asserts the distribution is actually uniform over [0, ceiling] rather
// than clustered near it, which is what "exponential backoff with a bit of
// jitter" usually produces.
func TestBackoffDelayIsFullJitter(t *testing.T) {
	b := &Backoff{Base: time.Second, Max: time.Second}

	const samples = 4000
	var (
		buckets [4]int
		sum     time.Duration
	)
	for i := 0; i < samples; i++ {
		d := b.Delay(0)
		if d < 0 || d > time.Second {
			t.Fatalf("Delay returned %s, outside [0, 1s]", d)
		}
		sum += d
		idx := int(4 * float64(d) / float64(time.Second))
		if idx > 3 {
			idx = 3
		}
		buckets[idx]++
	}

	// Every quartile must be populated: a distribution clustered near the
	// ceiling leaves the lower quartiles empty, and that is exactly the
	// pattern that produces thundering herds.
	expected := samples / 4
	for i, count := range buckets {
		if count == 0 {
			t.Fatalf("quartile %d of the jitter distribution was never sampled; the delay is not full jitter", i)
		}
		// Generous tolerance: this is a uniformity smoke test, not a
		// statistical test.
		if count < expected/2 || count > expected*2 {
			t.Errorf("quartile %d had %d samples, want roughly %d", i, count, expected)
		}
	}

	mean := sum / samples
	wantMean := 500 * time.Millisecond
	if diff := mean - wantMean; diff > 60*time.Millisecond || diff < -60*time.Millisecond {
		t.Errorf("mean delay = %s, want roughly %s", mean, wantMean)
	}
}

func TestBackoffDelayNeverExceedsCeiling(t *testing.T) {
	b := NewBackoff()
	for attempt := 0; attempt < 40; attempt++ {
		ceiling := b.Ceiling(attempt)
		for i := 0; i < 200; i++ {
			if d := b.Delay(attempt); d > ceiling {
				t.Fatalf("Delay(%d) = %s, above its ceiling of %s", attempt, d, ceiling)
			}
		}
	}
}

// TestBackoffHandlesExtremeAttemptCounts: a phone in airplane mode for an hour
// reaches a high attempt count, and a naive `base << attempt` overflows into a
// negative duration, which makes the retry fire immediately and turns a
// backoff into a hot loop.
func TestBackoffHandlesExtremeAttemptCounts(t *testing.T) {
	b := &Backoff{Base: time.Second, Max: 30 * time.Second}

	for _, attempt := range []int{-5, 0, 20, 63, 64, 1000, math.MaxInt32} {
		ceiling := b.Ceiling(attempt)
		if ceiling <= 0 {
			t.Errorf("Ceiling(%d) = %s, want a positive duration", attempt, ceiling)
		}
		if ceiling > 30*time.Second {
			t.Errorf("Ceiling(%d) = %s, above Max", attempt, ceiling)
		}
		d := b.Delay(attempt)
		if d < 0 {
			t.Errorf("Delay(%d) = %s, which would make the retry fire immediately", attempt, d)
		}
	}
}

func TestBackoffDefaults(t *testing.T) {
	b := &Backoff{} // zero value must behave sensibly
	if got := b.Ceiling(0); got != DefaultBackoffBase {
		t.Errorf("Ceiling(0) with a zero Backoff = %s, want %s", got, DefaultBackoffBase)
	}

	// Walk far enough that the clamp must engage.
	if got := b.Ceiling(30); got != DefaultBackoffMax {
		t.Errorf("Ceiling(30) = %s, want %s", got, DefaultBackoffMax)
	}
}

func TestNewBackoff(t *testing.T) {
	b := NewBackoff()
	if b.Base != DefaultBackoffBase || b.Max != DefaultBackoffMax {
		t.Errorf("NewBackoff = {%s, %s}, want {%s, %s}", b.Base, b.Max, DefaultBackoffBase, DefaultBackoffMax)
	}
	if b.rng == nil {
		t.Error("NewBackoff left rng nil")
	}
}

func TestBackoffExpectedDelay(t *testing.T) {
	b := &Backoff{Base: time.Second, Max: time.Minute}
	if got, want := b.ExpectedDelay(0), 500*time.Millisecond; got != want {
		t.Errorf("ExpectedDelay(0) = %s, want %s", got, want)
	}
	if got, want := b.ExpectedDelay(2), 2*time.Second; got != want {
		t.Errorf("ExpectedDelay(2) = %s, want %s", got, want)
	}
}

func TestBackoffAttemptsToReachMax(t *testing.T) {
	tests := []struct {
		base, max time.Duration
		want      int
	}{
		{time.Second, time.Second, 0},
		{time.Second, 2 * time.Second, 1},
		{time.Second, 8 * time.Second, 3},
		{500 * time.Millisecond, 30 * time.Second, 6},
	}
	for _, tt := range tests {
		b := &Backoff{Base: tt.base, Max: tt.max}
		if got := b.attemptsToReachMax(); got != tt.want {
			t.Errorf("attemptsToReachMax for base=%s max=%s = %d, want %d",
				tt.base, tt.max, got, tt.want)
		}
	}
}

// TestBackoffDeterministicWithInjectedRNG confirms the seam tests use.
func TestBackoffDeterministicWithInjectedRNG(t *testing.T) {
	b := &Backoff{
		Base: time.Second,
		Max:  time.Minute,
		rng:  func(n int64) int64 { return n - 1 }, // always the ceiling
	}
	if got, want := b.Delay(0), time.Second; got != want {
		t.Errorf("Delay(0) = %s, want %s", got, want)
	}
	if got, want := b.Delay(3), 8*time.Second; got != want {
		t.Errorf("Delay(3) = %s, want %s", got, want)
	}
}

func BenchmarkBackoffDelay(b *testing.B) {
	bo := NewBackoff()
	b.ReportAllocs()
	for b.Loop() {
		_ = bo.Delay(5)
	}
}
