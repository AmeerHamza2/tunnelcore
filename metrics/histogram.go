package metrics

import (
	"math"
	"sort"
	"time"
)

// histogram is a fixed-bucket latency histogram.
//
// Buckets rather than a reservoir sample or a t-digest, for one reason that
// decides it: this runs on a phone, and the whole point of the structure is to
// cost a constant, tiny amount of memory no matter how many observations
// arrive. A reservoir would be more accurate and would also mean holding
// samples; an exact quantile would mean holding everything. Sixteen uint64
// counters hold a day of reconnects.
//
// The quantiles it reports are therefore approximate, bounded by the bucket
// width they land in. That is fine for the purpose — the question these answer
// is "did p99 handshake latency just double", which bucket boundaries capture
// perfectly well, and the engine's timing constants are chosen in units of
// hundreds of milliseconds anyway.
type histogram struct {
	// bounds are the inclusive upper edges of each bucket.
	counts [len(histogramBounds) + 1]uint64
	total  uint64
	// sum lets Mean be reported without a second pass, and is exact.
	sum time.Duration
	min time.Duration
	max time.Duration
}

// histogramBounds are chosen around handshake latency on a mobile link.
//
// They are dense between 50ms and 1s because that is where a healthy
// handshake lives and where a regression needs resolution, and coarse past
// that because the only question above 2s is "how bad", not "how much worse".
var histogramBounds = [...]time.Duration{
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	75 * time.Millisecond,
	100 * time.Millisecond,
	150 * time.Millisecond,
	200 * time.Millisecond,
	300 * time.Millisecond,
	500 * time.Millisecond,
	750 * time.Millisecond,
	1 * time.Second,
	1500 * time.Millisecond,
	2 * time.Second,
	5 * time.Second,
	10 * time.Second,
}

func newHistogram() *histogram { return &histogram{} }

func (h *histogram) observe(d time.Duration) {
	if d < 0 {
		// A negative duration means a clock that went backwards, which on
		// mobile happens when the OS corrects time after a suspend. Dropping
		// it is better than letting it distort the sum.
		return
	}
	i := sort.Search(len(histogramBounds), func(i int) bool {
		return d <= histogramBounds[i]
	})
	h.counts[i]++
	h.total++
	h.sum += d
	if h.total == 1 || d < h.min {
		h.min = d
	}
	if d > h.max {
		h.max = d
	}
}

// quantile returns the approximate q-quantile, or 0 when there is no data.
//
// The value returned is the upper bound of the bucket the quantile falls in,
// except in the overflow bucket where the observed maximum is returned instead
// — reporting "+Inf" for a p99 is useless to anyone reading a dashboard.
func (h *histogram) quantile(q float64) time.Duration {
	if h.total == 0 {
		return 0
	}
	if q <= 0 {
		return h.min
	}
	if q >= 1 {
		return h.max
	}

	target := uint64(math.Ceil(q * float64(h.total)))
	var cumulative uint64
	for i, count := range h.counts {
		cumulative += count
		if cumulative >= target {
			if i >= len(histogramBounds) {
				return h.max
			}
			return histogramBounds[i]
		}
	}
	return h.max
}

// mean is exact, unlike the quantiles.
func (h *histogram) mean() time.Duration {
	if h.total == 0 {
		return 0
	}
	return h.sum / time.Duration(h.total)
}
