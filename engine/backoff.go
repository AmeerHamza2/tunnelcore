package engine

import (
	"math"
	"math/rand/v2"
	"time"
)

// Backoff computes retry delays with exponential growth and full jitter.
//
// The jitter is the part that matters, and it is not a refinement. Consider
// what happens without it when an exit node or a whole region goes down: every
// client that was connected there fails at the same moment, waits exactly the
// same first delay, and retries in lockstep. The replacement server receives
// the entire displaced population as a single synchronised spike, falls over
// or sheds load, and the clients — still synchronised — back off together and
// do it again at the next interval. The outage lasts as long as the retry
// pattern does.
//
// Full jitter (a uniform draw from [0, base * 2^attempt]) spreads the same
// clients across the whole window, so the replacement sees a ramp rather than
// a wall. It costs a random number per retry and is the single highest-value
// line of code in this file.
type Backoff struct {
	// Base is the first delay. Zero selects DefaultBackoffBase.
	Base time.Duration
	// Max caps the delay. Zero selects DefaultBackoffMax.
	Max time.Duration

	// rng is injectable so tests are deterministic.
	rng func(n int64) int64
}

// Backoff defaults.
//
// Base is short because the overwhelmingly common reason a mobile reconnect
// fails is that the radio has not finished switching networks yet, and that
// resolves in well under a second — waiting longer just means the user stares
// at "Reconnecting" for no reason.
//
// Max is capped at 30 seconds rather than minutes because a phone's network
// comes and goes constantly: a client that has backed off to five minutes will
// sit disconnected long after the network recovered, and the user's next
// action is to force-quit the app, which is worse for the server than the
// retry would have been.
const (
	DefaultBackoffBase = 500 * time.Millisecond
	DefaultBackoffMax  = 30 * time.Second

	// maxAttemptShift bounds the exponent so the shift cannot overflow,
	// independent of the Max clamp. 2^20 * 500ms is already days.
	maxAttemptShift = 20
)

// NewBackoff returns a Backoff with the default parameters.
func NewBackoff() *Backoff {
	return &Backoff{
		Base: DefaultBackoffBase,
		Max:  DefaultBackoffMax,
		rng:  rand.Int64N,
	}
}

func (b *Backoff) base() time.Duration {
	if b.Base <= 0 {
		return DefaultBackoffBase
	}
	return b.Base
}

func (b *Backoff) max() time.Duration {
	if b.Max <= 0 {
		return DefaultBackoffMax
	}
	return b.Max
}

// Delay returns the delay before the given attempt, which is zero-based: the
// first retry is attempt 0.
func (b *Backoff) Delay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > maxAttemptShift {
		attempt = maxAttemptShift
	}

	ceiling := b.base() << uint(attempt)
	if ceiling > b.max() || ceiling <= 0 { // <= 0 catches any overflow
		ceiling = b.max()
	}

	rng := b.rng
	if rng == nil {
		rng = rand.Int64N
	}
	// Full jitter: uniform over [0, ceiling]. Not "ceiling plus or minus a
	// bit", which keeps clients clustered around the exponential curve and
	// only blurs the edges of the spike.
	return time.Duration(rng(int64(ceiling) + 1))
}

// Ceiling returns the un-jittered upper bound for an attempt, which is what a
// UI should show as "retrying in up to N seconds".
func (b *Backoff) Ceiling(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > maxAttemptShift {
		attempt = maxAttemptShift
	}
	ceiling := b.base() << uint(attempt)
	if ceiling > b.max() || ceiling <= 0 {
		ceiling = b.max()
	}
	return ceiling
}

// ExpectedDelay is the mean of the jittered distribution, provided for
// capacity planning: given N clients reconnecting, this is roughly how long
// the ramp lasts.
func (b *Backoff) ExpectedDelay(attempt int) time.Duration {
	return b.Ceiling(attempt) / 2
}

// attemptsToReachMax reports how many attempts it takes for the ceiling to hit
// Max, which is the number a runbook wants when asking "how long until clients
// stop hammering us".
func (b *Backoff) attemptsToReachMax() int {
	ratio := float64(b.max()) / float64(b.base())
	if ratio <= 1 {
		return 0
	}
	return int(math.Ceil(math.Log2(ratio)))
}
