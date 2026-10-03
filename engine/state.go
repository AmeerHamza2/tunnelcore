package engine

import (
	"fmt"
	"sync"
	"time"
)

// State is the engine's connection state.
//
// This is modelled as an explicit state machine with validated transitions
// rather than a couple of booleans, and that choice is load-bearing. A mobile
// VPN is driven by events that arrive concurrently and in any order: the user
// taps disconnect while a handshake is in flight, the radio switches from wifi
// to cellular during a reconnect, the OS suspends the process mid-race, a
// transport dies at the same moment the user switches servers. With flags,
// each new event multiplies the number of reachable combinations and the bugs
// are of the form "the UI says Connected but there is no tunnel" — which on a
// privacy product means the user believes they are protected when they are
// not.
//
// With one state variable and a transition table, an impossible combination
// cannot be represented, and an unexpected event is a rejected transition
// (logged, counted) rather than silent corruption.
type State int

const (
	// StateIdle is the initial state: nothing has been started.
	StateIdle State = iota
	// StateConnecting means a transport race is in progress.
	StateConnecting
	// StateConnected means a tunnel is up and carrying traffic.
	StateConnected
	// StateReconnecting means the tunnel dropped or the network changed and
	// the engine is re-establishing. This is distinct from StateConnecting
	// because the UI should say "Reconnecting", not "Connecting", and because
	// reconnects are backed off while a first connect is not.
	StateReconnecting
	// StateDisconnecting means a shutdown is in progress.
	StateDisconnecting
	// StateDisconnected is the terminal state after Stop.
	StateDisconnected
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateReconnecting:
		return "reconnecting"
	case StateDisconnecting:
		return "disconnecting"
	case StateDisconnected:
		return "disconnected"
	default:
		return fmt.Sprintf("state(%d)", int(s))
	}
}

// IsUp reports whether the tunnel is carrying traffic.
//
// Only StateConnected qualifies. Reconnecting is deliberately *not* up: during
// a reconnect there is no transport, and a caller that treats reconnecting as
// up will write packets into a closed transport and, worse, may report
// "protected" to the user.
func (s State) IsUp() bool { return s == StateConnected }

// IsTerminal reports whether no further transitions are possible.
func (s State) IsTerminal() bool { return s == StateDisconnected }

// Reason explains why a transition happened. It is attached to every state
// change so that a support log answers "why did the tunnel drop" without
// needing packet captures.
type Reason string

const (
	ReasonUserRequested  Reason = "user_requested"
	ReasonNetworkChanged Reason = "network_changed"
	ReasonTransportFail  Reason = "transport_failed"
	ReasonHandshakeFail  Reason = "handshake_failed"
	ReasonNoCandidates   Reason = "no_candidates"
	ReasonTunnelClosed   Reason = "tunnel_closed"
	ReasonServerSwitched Reason = "server_switched"
	ReasonRetry          Reason = "retry"
	ReasonStarted        Reason = "started"
)

// transitions is the set of permitted state changes.
//
// Everything not listed is rejected. Two entries are worth noting because they
// look redundant and are not:
//
//   - Connecting -> Reconnecting, for the case where the network changes while
//     the very first connect is still racing.
//   - Connected -> Connecting is absent on purpose: an established tunnel that
//     needs re-establishing goes through Reconnecting, so the backoff applies
//     and the UI distinguishes the two.
var transitions = map[State][]State{
	StateIdle:          {StateConnecting, StateDisconnected},
	StateConnecting:    {StateConnected, StateReconnecting, StateDisconnecting, StateDisconnected},
	StateConnected:     {StateReconnecting, StateDisconnecting},
	StateReconnecting:  {StateConnected, StateReconnecting, StateDisconnecting, StateDisconnected},
	StateDisconnecting: {StateDisconnected},
	StateDisconnected:  {},
}

// CanTransition reports whether from -> to is permitted.
func CanTransition(from, to State) bool {
	for _, allowed := range transitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// Change describes one state transition.
type Change struct {
	From      State
	To        State
	Reason    Reason
	Transport string
	// Err is the error that caused the transition, if any.
	Err error
	At  time.Time
}

func (c Change) String() string {
	s := fmt.Sprintf("%s -> %s (%s)", c.From, c.To, c.Reason)
	if c.Transport != "" {
		s += " via " + c.Transport
	}
	if c.Err != nil {
		s += ": " + c.Err.Error()
	}
	return s
}

// machine holds the engine's state and notifies observers of changes.
type machine struct {
	mu       sync.RWMutex
	state    State
	last     Change
	rejected uint64

	observers []func(Change)
	now       func() time.Time
}

func newMachine() *machine {
	return &machine{state: StateIdle, now: time.Now}
}

// observe registers a callback for state changes.
//
// Callbacks are invoked without the lock held, so an observer may call back
// into the engine. That is not hypothetical: the obvious observer is the
// mobile layer, which on reaching StateConnected turns around and asks the
// engine for its configuration to show the user. Holding the lock across the
// callback would deadlock on exactly that.
func (m *machine) observe(fn func(Change)) {
	m.mu.Lock()
	m.observers = append(m.observers, fn)
	m.mu.Unlock()
}

// transition attempts a state change, returning whether it was permitted.
func (m *machine) transition(to State, reason Reason, transport string, err error) (Change, bool) {
	m.mu.Lock()
	from := m.state
	if !CanTransition(from, to) {
		m.rejected++
		m.mu.Unlock()
		return Change{From: from, To: to, Reason: reason}, false
	}
	change := Change{
		From:      from,
		To:        to,
		Reason:    reason,
		Transport: transport,
		Err:       err,
		At:        m.now(),
	}
	m.state = to
	m.last = change
	observers := make([]func(Change), len(m.observers))
	copy(observers, m.observers)
	m.mu.Unlock()

	for _, fn := range observers {
		fn(change)
	}
	return change, true
}

func (m *machine) current() State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *machine) lastChange() Change {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}

// rejectedTransitions counts attempts that the table refused.
//
// A non-zero value is not necessarily a bug — a disconnect arriving while a
// handshake is in flight legitimately produces one — but a *growing* value
// means events are arriving in an order the engine does not model, which is
// exactly the signal that would otherwise be invisible.
func (m *machine) rejectedTransitions() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rejected
}
