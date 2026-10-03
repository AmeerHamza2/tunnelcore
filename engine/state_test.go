package engine

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport"
)

func TestStateString(t *testing.T) {
	tests := map[State]string{
		StateIdle:          "idle",
		StateConnecting:    "connecting",
		StateConnected:     "connected",
		StateReconnecting:  "reconnecting",
		StateDisconnecting: "disconnecting",
		StateDisconnected:  "disconnected",
		State(99):          "state(99)",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

// TestOnlyConnectedIsUp pins a distinction that is easy to get wrong and
// dangerous when wrong: during a reconnect there is no transport, so a caller
// that treats reconnecting as "up" will write into a closed transport and —
// much worse — may tell the user they are protected when they are not.
func TestOnlyConnectedIsUp(t *testing.T) {
	up := map[State]bool{
		StateIdle:          false,
		StateConnecting:    false,
		StateConnected:     true,
		StateReconnecting:  false,
		StateDisconnecting: false,
		StateDisconnected:  false,
	}
	for s, want := range up {
		if got := s.IsUp(); got != want {
			t.Errorf("%s.IsUp() = %v, want %v", s, got, want)
		}
	}
}

func TestTerminalState(t *testing.T) {
	if !StateDisconnected.IsTerminal() {
		t.Error("disconnected should be terminal")
	}
	for _, s := range []State{StateIdle, StateConnecting, StateConnected, StateReconnecting, StateDisconnecting} {
		if s.IsTerminal() {
			t.Errorf("%s should not be terminal", s)
		}
	}
}

func TestTransitionTable(t *testing.T) {
	allowed := []struct{ from, to State }{
		{StateIdle, StateConnecting},
		{StateConnecting, StateConnected},
		{StateConnecting, StateReconnecting},
		{StateConnecting, StateDisconnecting},
		{StateConnected, StateReconnecting},
		{StateConnected, StateDisconnecting},
		{StateReconnecting, StateConnected},
		{StateReconnecting, StateReconnecting},
		{StateDisconnecting, StateDisconnected},
	}
	for _, tc := range allowed {
		if !CanTransition(tc.from, tc.to) {
			t.Errorf("%s -> %s should be allowed", tc.from, tc.to)
		}
	}

	forbidden := []struct {
		from, to State
		why      string
	}{
		{StateIdle, StateConnected, "cannot be connected without connecting"},
		{StateDisconnected, StateConnecting, "terminal state must have no exits"},
		{StateDisconnected, StateConnected, "terminal state must have no exits"},
		{StateConnected, StateConnecting, "an established tunnel re-establishes via reconnecting, so the backoff applies and the UI distinguishes the two"},
		{StateConnected, StateIdle, "there is no path back to idle"},
		{StateDisconnecting, StateConnected, "a shutdown in progress cannot become connected"},
	}
	for _, tc := range forbidden {
		if CanTransition(tc.from, tc.to) {
			t.Errorf("%s -> %s should be forbidden: %s", tc.from, tc.to, tc.why)
		}
	}
}

func TestMachineRejectsIllegalTransitions(t *testing.T) {
	m := newMachine()

	if _, ok := m.transition(StateConnected, ReasonStarted, "", nil); ok {
		t.Error("idle -> connected was accepted")
	}
	if m.current() != StateIdle {
		t.Errorf("state changed to %s on a rejected transition", m.current())
	}
	if m.rejectedTransitions() != 1 {
		t.Errorf("rejectedTransitions = %d, want 1", m.rejectedTransitions())
	}

	if _, ok := m.transition(StateConnecting, ReasonStarted, "", nil); !ok {
		t.Fatal("idle -> connecting was rejected")
	}
	if m.current() != StateConnecting {
		t.Errorf("state = %s, want connecting", m.current())
	}
}

func TestMachineNotifiesObservers(t *testing.T) {
	m := newMachine()

	var mu sync.Mutex
	var seen []Change
	m.observe(func(c Change) {
		mu.Lock()
		seen = append(seen, c)
		mu.Unlock()
	})

	m.transition(StateConnecting, ReasonStarted, "", nil)
	m.transition(StateConnected, ReasonStarted, "wg/fra-01", nil)
	// Rejected: must not notify.
	m.transition(StateIdle, ReasonUserRequested, "", nil)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("observer fired %d times, want 2 (rejected transitions must not notify)", len(seen))
	}
	if seen[1].Transport != "wg/fra-01" {
		t.Errorf("Change.Transport = %q, want wg/fra-01", seen[1].Transport)
	}
	if seen[1].At.IsZero() {
		t.Error("Change.At was not set")
	}
}

// TestObserverCanCallBackIntoTheMachine is why observers are invoked without
// the lock held. The obvious observer is the mobile layer, which on reaching
// StateConnected turns around and asks for the current state to render it;
// holding the lock across the callback would deadlock on exactly that.
func TestObserverCanCallBackIntoTheMachine(t *testing.T) {
	m := newMachine()

	done := make(chan State, 1)
	m.observe(func(Change) {
		done <- m.current() // re-entrant read
	})

	go m.transition(StateConnecting, ReasonStarted, "", nil)

	select {
	case got := <-done:
		if got != StateConnecting {
			t.Errorf("re-entrant read saw %s, want connecting", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deadlocked: the observer was invoked with the lock held")
	}
}

func TestChangeString(t *testing.T) {
	c := Change{
		From:      StateConnected,
		To:        StateReconnecting,
		Reason:    ReasonTransportFail,
		Transport: "wg/fra-01",
		Err:       errors.New("handshake timed out"),
	}
	want := "connected -> reconnecting (transport_failed) via wg/fra-01: handshake timed out"
	if got := c.String(); got != want {
		t.Errorf("Change.String() = %q, want %q", got, want)
	}
}

func TestConcurrentTransitions(t *testing.T) {
	m := newMachine()
	m.transition(StateConnecting, ReasonStarted, "", nil)

	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				switch i % 4 {
				case 0:
					m.transition(StateConnected, ReasonStarted, "wg", nil)
				case 1:
					m.transition(StateReconnecting, ReasonRetry, "wg", nil)
				case 2:
					_ = m.current()
				case 3:
					_ = m.lastChange()
				}
			}
		}(w)
	}
	wg.Wait()

	// The only invariant worth asserting is that the machine ended in a state
	// reachable from the transitions attempted.
	switch m.current() {
	case StateConnected, StateReconnecting:
	default:
		t.Errorf("final state = %s, want connected or reconnecting", m.current())
	}
}

// TestNeverReportsConnectedOverADeadTransport is the regression test for the
// worst bug found while building this engine.
//
// The inbound data-path loop treated transport.ErrClosed as a benign reason to
// exit, because that is what teardown looks like. But a transport that dies by
// closing itself is the *normal* way a transport dies — and suppressing it
// left the supervisor blocked forever on a session whose data path had already
// gone. The engine sat in StateConnected over a tunnel carrying nothing,
// indefinitely, never reconnecting. For a privacy product that is the worst
// possible failure: the UI says "protected", nothing works, and the user has
// no way to know.
//
// The fix was to let the session context, not the error value, decide whether
// an exit is expected.
func TestNeverReportsConnectedOverADeadTransport(t *testing.T) {
	tun := newFakeTun(testMTU)

	// A provider that hands out one working transport and then only dead
	// ones, so the engine cannot paper over the failure by reconnecting.
	var handed int
	var mu sync.Mutex
	var live *fakePipe

	e := newTestEngine(t, tun, Config{
		Backoff: &Backoff{Base: 10 * time.Millisecond, Max: 20 * time.Millisecond},
	}, func() []transport.Transport {
		mu.Lock()
		defer mu.Unlock()
		handed++
		if handed == 1 {
			live = newFakePipe("wg-live")
			return []transport.Transport{live}
		}
		dead := newFakePipe("wg-dead")
		dead.upErr = transport.ErrHandshakeTimeout
		return []transport.Transport{dead}
	})

	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
		t.Fatal("never connected")
	}

	// Kill the transport the way a real one dies: it closes itself.
	mu.Lock()
	victim := live
	mu.Unlock()
	_ = victim.Close()

	// The engine must leave StateConnected. It will then fail to reconnect,
	// which is fine — the point is that it must not claim to be connected
	// over a transport that is gone.
	if !waitFor(5*time.Second, func() bool { return e.State() != StateConnected }) {
		t.Fatalf("engine still reports %s after its transport closed itself: "+
			"the UI would say \"protected\" over a dead tunnel", e.State())
	}
}
