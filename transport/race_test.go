package transport

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubTransport is a Transport whose Up behaviour each test dictates.
type stubTransport struct {
	name  string
	kind  Kind
	delay time.Duration
	err   error

	upCalls    atomic.Int32
	closeCalls atomic.Int32
	// startedAt records when Up was entered, so tests can assert on stagger.
	mu        sync.Mutex
	startedAt time.Time
}

func newStub(name string, delay time.Duration, err error) *stubTransport {
	return &stubTransport{name: name, kind: KindPacket, delay: delay, err: err}
}

func (s *stubTransport) Name() string { return s.name }
func (s *stubTransport) Kind() Kind   { return s.kind }

func (s *stubTransport) Up(ctx context.Context) error {
	s.upCalls.Add(1)
	s.mu.Lock()
	s.startedAt = time.Now()
	s.mu.Unlock()

	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.err
}

func (s *stubTransport) Close() error {
	s.closeCalls.Add(1)
	return nil
}

func (s *stubTransport) started() bool { return s.upCalls.Load() > 0 }

func (s *stubTransport) startTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startedAt
}

var _ Transport = (*stubTransport)(nil)

func TestRaceNoCandidates(t *testing.T) {
	r := &Racer{}
	if _, err := r.Race(context.Background()); !errors.Is(err, ErrNoCandidates) {
		t.Errorf("Race with no candidates = %v, want ErrNoCandidates", err)
	}
}

func TestRaceFirstCandidateWins(t *testing.T) {
	fast := newStub("fast", 10*time.Millisecond, nil)
	slow := newStub("slow", 5*time.Second, nil)

	r := &Racer{Candidates: []Transport{fast, slow}, Stagger: 200 * time.Millisecond}
	got, err := r.Race(context.Background())
	if err != nil {
		t.Fatalf("Race: %v", err)
	}
	if got != Transport(fast) {
		t.Errorf("winner = %s, want fast", got.Name())
	}

	// This is the behaviour that justifies staggering: the second candidate
	// should never have been dialed at all, because the first won inside the
	// stagger window.
	if slow.started() {
		t.Error("the second candidate was dialed even though the first won within the stagger window")
	}
	if fast.closeCalls.Load() != 0 {
		t.Errorf("the winner was closed %d times, want 0", fast.closeCalls.Load())
	}
}

func TestRaceFailsOverToSecond(t *testing.T) {
	broken := newStub("broken", 0, ErrHandshakeTimeout)
	working := newStub("working", 10*time.Millisecond, nil)

	r := &Racer{Candidates: []Transport{broken, working}, Stagger: 20 * time.Millisecond}
	got, err := r.Race(context.Background())
	if err != nil {
		t.Fatalf("Race: %v", err)
	}
	if got != Transport(working) {
		t.Errorf("winner = %s, want working", got.Name())
	}
	if broken.closeCalls.Load() == 0 {
		t.Error("the failed candidate was never closed; a retry loop would leak its socket")
	}
}

func TestRaceAllFail(t *testing.T) {
	a := newStub("a", 0, ErrHandshakeTimeout)
	b := newStub("b", 0, errors.New("connection refused"))

	r := &Racer{Candidates: []Transport{a, b}, Stagger: time.Millisecond}
	_, err := r.Race(context.Background())
	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("Race = %v, want ErrAllFailed", err)
	}
	// The aggregate must preserve the first underlying cause, because the
	// engine's retry policy branches on it.
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Errorf("Race error does not wrap the first candidate's cause: %v", err)
	}
	// Both names should appear so an operator can see what was tried.
	msg := err.Error()
	for _, name := range []string{"a", "b"} {
		if !contains(msg, name) {
			t.Errorf("error message %q does not mention candidate %q", msg, name)
		}
	}
	if a.closeCalls.Load() == 0 || b.closeCalls.Load() == 0 {
		t.Error("not every failed candidate was closed")
	}
}

// TestRaceClosesLosers is the resource-leak property. A mobile client races on
// every network change; a single leaked socket per race exhausts the fd table
// over a day.
func TestRaceClosesLosers(t *testing.T) {
	winner := newStub("winner", 10*time.Millisecond, nil)
	laggards := []*stubTransport{
		newStub("lag1", 2*time.Second, nil),
		newStub("lag2", 2*time.Second, nil),
		newStub("lag3", 2*time.Second, nil),
	}

	candidates := []Transport{winner}
	for _, l := range laggards {
		candidates = append(candidates, l)
	}

	// Stagger 0 means everything starts at once, so every laggard really does
	// get into Up and has to be unwound.
	r := &Racer{Candidates: candidates, Stagger: -1}
	got, err := r.Race(context.Background())
	if err != nil {
		t.Fatalf("Race: %v", err)
	}
	if got != Transport(winner) {
		t.Fatalf("winner = %s, want winner", got.Name())
	}

	for _, l := range laggards {
		if l.closeCalls.Load() == 0 {
			t.Errorf("laggard %s was not closed", l.name)
		}
	}
	if winner.closeCalls.Load() != 0 {
		t.Error("the winner was closed")
	}
}

// TestRaceReturnsAfterLosersUnwind checks that Race does not return while a
// candidate is still inside Up. Returning early would leave a socket being
// opened after the caller believes the race is over.
func TestRaceReturnsAfterLosersUnwind(t *testing.T) {
	var inFlight atomic.Int32

	tracking := &trackingTransport{
		name:     "tracking",
		inFlight: &inFlight,
		delay:    500 * time.Millisecond,
	}
	winner := newStub("winner", 5*time.Millisecond, nil)

	r := &Racer{Candidates: []Transport{winner, tracking}, Stagger: -1}
	if _, err := r.Race(context.Background()); err != nil {
		t.Fatalf("Race: %v", err)
	}

	if n := inFlight.Load(); n != 0 {
		t.Errorf("%d candidate(s) still inside Up when Race returned", n)
	}
}

type trackingTransport struct {
	name     string
	inFlight *atomic.Int32
	delay    time.Duration
}

func (t *trackingTransport) Name() string { return t.name }
func (t *trackingTransport) Kind() Kind   { return KindStream }
func (t *trackingTransport) Up(ctx context.Context) error {
	t.inFlight.Add(1)
	defer t.inFlight.Add(-1)
	select {
	case <-time.After(t.delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (t *trackingTransport) Close() error { return nil }

// TestRaceCancelledCandidatesAreNotCountedAsFailures is what keeps connection
// success rate meaningful. If losers were reported as failures, a healthy
// network racing three candidates would show a 33% success rate forever.
func TestRaceCancelledCandidatesAreNotCountedAsFailures(t *testing.T) {
	winner := newStub("winner", 5*time.Millisecond, nil)
	losers := []Transport{
		newStub("loser1", time.Second, nil),
		newStub("loser2", time.Second, nil),
	}

	var mu sync.Mutex
	var results []Result
	r := &Racer{
		Candidates: append([]Transport{winner}, losers...),
		Stagger:    -1,
		OnResult: func(res Result) {
			mu.Lock()
			results = append(results, res)
			mu.Unlock()
		},
	}
	if _, err := r.Race(context.Background()); err != nil {
		t.Fatalf("Race: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	var failures, wins int
	for _, res := range results {
		if res.Won {
			wins++
			continue
		}
		if !res.Succeeded() {
			failures++
			t.Logf("reported failure: %s: %v", res.Name, res.Err)
		}
	}
	if failures != 0 {
		t.Errorf("%d cancelled candidate(s) were reported as failures; success rate would be understated", failures)
	}
	if wins != 1 {
		t.Errorf("%d winners reported, want 1", wins)
	}
}

func TestRaceTimeout(t *testing.T) {
	slow := newStub("slow1", 5*time.Second, nil)
	slower := newStub("slow2", 5*time.Second, nil)

	r := &Racer{
		Candidates: []Transport{slow, slower},
		Stagger:    -1,
		Timeout:    150 * time.Millisecond,
	}

	start := time.Now()
	_, err := r.Race(context.Background())
	elapsed := time.Since(start)

	if !errors.Is(err, ErrAllFailed) {
		t.Errorf("Race = %v, want ErrAllFailed", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Race took %s to honour a 150ms timeout", elapsed)
	}
}

func TestRaceHonoursParentContext(t *testing.T) {
	slow := newStub("slow", 5*time.Second, nil)
	r := &Racer{Candidates: []Transport{slow}, Stagger: -1}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if _, err := r.Race(ctx); err == nil {
		t.Error("Race = nil after the parent context was cancelled, want an error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Race took %s to notice parent cancellation", elapsed)
	}
}

// TestRaceStaggerIsObserved pins the actual timing behaviour rather than just
// asserting a candidate did not start.
func TestRaceStaggerIsObserved(t *testing.T) {
	const stagger = 120 * time.Millisecond

	// Both fail, so every candidate runs and every start time is recorded.
	a := newStub("a", 0, errors.New("nope"))
	b := newStub("b", 0, errors.New("nope"))
	c := newStub("c", 0, errors.New("nope"))

	r := &Racer{Candidates: []Transport{a, b, c}, Stagger: stagger}
	if _, err := r.Race(context.Background()); !errors.Is(err, ErrAllFailed) {
		t.Fatalf("Race = %v, want ErrAllFailed", err)
	}

	gapAB := b.startTime().Sub(a.startTime())
	gapBC := c.startTime().Sub(b.startTime())

	// Allow generous slack: this asserts the stagger exists, not that the
	// scheduler is precise.
	for name, gap := range map[string]time.Duration{"a->b": gapAB, "b->c": gapBC} {
		if gap < stagger/2 {
			t.Errorf("gap %s was %s, want at least ~%s", name, gap, stagger/2)
		}
	}
}

func TestRaceSingleCandidate(t *testing.T) {
	only := newStub("only", 5*time.Millisecond, nil)
	r := &Racer{Candidates: []Transport{only}}
	got, err := r.Race(context.Background())
	if err != nil {
		t.Fatalf("Race: %v", err)
	}
	if got != Transport(only) {
		t.Errorf("winner = %s, want only", got.Name())
	}
}

func TestResultSucceeded(t *testing.T) {
	if !(Result{}).Succeeded() {
		t.Error("a zero Result should report success")
	}
	if (Result{Err: errors.New("x")}).Succeeded() {
		t.Error("a Result with an error should not report success")
	}
}

func TestKindString(t *testing.T) {
	tests := map[Kind]string{
		KindPacket: "packet",
		KindStream: "stream",
		Kind(99):   "kind?",
	}
	for k, want := range tests {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d).String() = %q, want %q", int(k), got, want)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// TestRaceAllFailMessageHasEachCauseOnce: the aggregate wraps the first cause
// for errors.Is, and an earlier version did that by appending it with %w,
// which printed it a second time after the per-candidate list.
func TestRaceAllFailMessageHasEachCauseOnce(t *testing.T) {
	a := newStub("a", 0, errors.New("first-cause-marker"))
	r := &Racer{Candidates: []Transport{a}, Stagger: time.Millisecond}
	_, err := r.Race(context.Background())
	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("Race = %v, want ErrAllFailed", err)
	}
	if !errors.Is(err, a.err) {
		t.Fatalf("Race error does not wrap the candidate's cause: %v", err)
	}
	if n := strings.Count(err.Error(), "first-cause-marker"); n != 1 {
		t.Fatalf("cause appears %d times in %q, want 1", n, err.Error())
	}
}
