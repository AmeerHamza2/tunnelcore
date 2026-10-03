package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DefaultStagger is the delay between starting consecutive candidates in a
// race.
//
// Starting every candidate at once is the obvious implementation and the wrong
// one on a phone. Each candidate is a real handshake: a radio wakeup, battery,
// mobile data the user may be paying for, and load on a server that will not
// be used. Staggering means the preferred candidate usually wins before the
// second one has even started, so the common case costs exactly one handshake,
// while a blocked or dead first choice still fails over in a quarter of a
// second rather than after a full timeout.
//
// 250ms is chosen against handshake latency rather than ping: it is longer
// than a healthy WireGuard handshake on a 4G link (typically 80–150ms) and
// shorter than a user notices.
const DefaultStagger = 250 * time.Millisecond

// DefaultRaceTimeout bounds a whole race.
//
// Ten seconds is past the point where a user has decided the app is broken, so
// it is a backstop rather than a target: the per-candidate failures are what
// should end a race, and a race that actually runs to this limit means every
// candidate is blackholed, which is itself the signal the engine needs.
const DefaultRaceTimeout = 10 * time.Second

// Race errors.
var (
	ErrNoCandidates = errors.New("transport: no candidates to race")
	ErrAllFailed    = errors.New("transport: every candidate failed")
)

// Result reports how one candidate fared in a race.
//
// These feed connection success rate, which is the metric that tells you a
// protocol has been blocked on a network before your users do. Aggregated per
// transport and per region, a success rate that drops for Shadowsocks while
// WireGuard holds steady is a DPI signature update; the reverse is usually a
// routing problem.
type Result struct {
	Name string
	Kind Kind
	// Latency is how long Up took, successfully or not.
	Latency time.Duration
	// Started is when this candidate was launched, relative to the race
	// start, which makes the stagger visible in traces.
	Started time.Duration
	Err     error
	// Won reports whether this candidate was the one returned.
	Won bool
}

// Succeeded reports whether this candidate came up.
func (r Result) Succeeded() bool { return r.Err == nil }

// Racer brings up candidate transports concurrently and keeps the first one
// that works.
type Racer struct {
	// Candidates are tried in order, with Stagger between each start. Put the
	// preferred transport first: on a healthy network it wins and nothing
	// else is ever dialed.
	Candidates []Transport

	// Stagger is the delay between consecutive starts. Zero selects
	// DefaultStagger; negative starts everything at once, which is only
	// appropriate when latency matters more than battery.
	Stagger time.Duration

	// Timeout bounds the whole race. Zero selects DefaultRaceTimeout.
	Timeout time.Duration

	// OnResult, if non-nil, is called once per candidate as it finishes. It
	// may be called from several goroutines and must not block.
	OnResult func(Result)
}

// Race returns the first candidate to come up, having closed all the others.
//
// The winner is returned already up and ready to carry traffic. Every loser is
// closed before Race returns, so a caller that handles the error path by
// retrying does not accumulate half-open sockets — which over a day of network
// flapping on a mobile device is the difference between a stable client and one
// that dies of file-descriptor exhaustion.
func (r *Racer) Race(ctx context.Context) (Transport, error) {
	if len(r.Candidates) == 0 {
		return nil, ErrNoCandidates
	}

	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultRaceTimeout
	}
	raceCtx, cancelRace := context.WithTimeout(ctx, timeout)
	defer cancelRace()

	stagger := r.Stagger
	if stagger == 0 {
		stagger = DefaultStagger
	}
	if stagger < 0 {
		stagger = 0
	}

	// Every goroutine sends exactly one outcome, including the ones that never
	// get to start. That invariant is what keeps collection simple: the
	// channel is buffered to the candidate count, so no sender ever blocks and
	// no goroutine can be stranded, and the collector just reads N times.
	type outcome struct {
		t       Transport
		result  Result
		skipped bool
	}
	outcomes := make(chan outcome, len(r.Candidates))

	start := time.Now()
	for i, candidate := range r.Candidates {
		go func(i int, c Transport) {
			// Stagger. A candidate whose turn never comes because an earlier
			// one already won exits here without touching the network, which
			// is the entire point of staggering.
			if delay := time.Duration(i) * stagger; delay > 0 {
				select {
				case <-time.After(delay):
				case <-raceCtx.Done():
					outcomes <- outcome{t: c, skipped: true}
					return
				}
			}

			launched := time.Since(start)
			upStart := time.Now()
			err := c.Up(raceCtx)
			res := Result{
				Name:    c.Name(),
				Kind:    c.Kind(),
				Latency: time.Since(upStart),
				Started: launched,
				Err:     err,
			}

			// A candidate cancelled because somebody else won is not a failure
			// of that candidate, and reporting it as one would make connection
			// success rate meaningless: every race would record N-1 failures
			// by construction, and a healthy network would look broken.
			if err != nil && errors.Is(err, context.Canceled) {
				outcomes <- outcome{t: c, skipped: true}
				return
			}

			if r.OnResult != nil {
				r.OnResult(res)
			}
			outcomes <- outcome{t: c, result: res}
		}(i, candidate)
	}

	var (
		winner   Transport
		failures []Result
	)
	for range r.Candidates {
		o := <-outcomes
		switch {
		case o.skipped:
			// Nothing to report and nothing to count.
		case o.result.Succeeded() && winner == nil:
			winner = o.t
			// Cancel immediately so the stragglers stop dialing. They will
			// still report, which is how we know they have unwound.
			cancelRace()
		default:
			if !o.result.Succeeded() {
				failures = append(failures, o.result)
			}
		}
	}

	// Collection is complete, so every goroutine has finished and no socket is
	// still being opened behind our back. Close everything that is not the
	// winner. Close is required to be idempotent, so candidates that already
	// closed themselves are safe to close again.
	r.closeAllExcept(winner)

	if winner == nil {
		if len(failures) == 0 {
			// Every candidate was cancelled or never started, which only
			// happens when the race itself ran out of time.
			return nil, fmt.Errorf("%w: race timed out after %s", ErrAllFailed, timeout)
		}
		return nil, aggregateError(failures)
	}

	if r.OnResult != nil {
		r.OnResult(Result{Name: winner.Name(), Kind: winner.Kind(), Won: true})
	}
	return winner, nil
}

// closeAllExcept closes every candidate except keep.
//
// Close is required to be idempotent (see Transport.Close), which is what
// makes this safe to call over candidates that were already closed on the
// failure path.
func (r *Racer) closeAllExcept(keep Transport) {
	for _, c := range r.Candidates {
		if c != keep {
			_ = c.Close()
		}
	}
}

func aggregateError(failures []Result) error {
	if len(failures) == 0 {
		return ErrAllFailed
	}
	var sb strings.Builder
	for i, f := range failures {
		if i > 0 {
			sb.WriteString("; ")
		}
		fmt.Fprintf(&sb, "%s (%s) after %s: %v", f.Name, f.Kind, f.Latency.Round(time.Millisecond), f.Err)
	}
	// Both errors are wrapped, not just rendered into the message. Callers
	// match on each for different reasons, and a sentinel that only appears in
	// the text is invisible to errors.Is:
	//
	//   ErrAllFailed      — the engine's "every server is unusable, re-fetch
	//                       the server list" path
	//   failures[0].Err   — the retry policy, which branches on the cause: a
	//                       handshake timeout is worth retrying elsewhere, a
	//                       closed transport is not.
	//
	// A plain fmt.Errorf with two %w verbs would also print failures[0].Err a
	// second time at the end of a message that already contains it, so the
	// text is built once and the wrapping is done by raceError instead.
	return &raceError{
		msg:  ErrAllFailed.Error() + ": " + sb.String(),
		errs: []error{ErrAllFailed, failures[0].Err},
	}
}

// raceError carries a pre-rendered message and the errors it wraps, so the
// message and the errors.Is chain can be chosen independently.
type raceError struct {
	msg  string
	errs []error
}

func (e *raceError) Error() string   { return e.msg }
func (e *raceError) Unwrap() []error { return e.errs }
