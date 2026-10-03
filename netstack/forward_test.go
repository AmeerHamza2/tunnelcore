package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport"
)

// TestStackTCPEstablishedFlowsDoNotHoldInFlightSlots is the regression test
// for completing forwarder requests only when a flow ended. gVisor counts a
// request as in flight until Complete and silently drops SYNs beyond the
// limit, so holding requests open made the half-open limit a cap on
// established connections: connection limit+1 hung in SYN_SENT. The limit is
// lowered here so the test opens a handful of connections rather than 513.
func TestStackTCPEstablishedFlowsDoNotHoldInFlightSlots(t *testing.T) {
	const inFlight = 4
	dialer := newFakeDialer()
	dialer.onTCP = echoServer(t)

	ns := newTestStack(t, Config{Dialer: dialer, tcpMaxInFlight: inFlight})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	// Every connection stays open for the whole test.
	for i := 0; i < inFlight*3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := peer.dialTCP(ctx, remoteHTTP)
		cancel()
		if err != nil {
			t.Fatalf("connection %d (in-flight limit %d) failed with the earlier ones still open: %v",
				i+1, inFlight, err)
		}
		defer conn.Close()
		echoRoundTrip(t, conn, "ping")
	}
}

// TestStackTCPFlowCapResets checks that MaxTCPFlows bounds established flows
// with a prompt reset, and that a slot is reusable once a flow ends.
func TestStackTCPFlowCapResets(t *testing.T) {
	const maxFlows = 3
	dialer := newFakeDialer()
	dialer.onTCP = echoServer(t)

	ns := newTestStack(t, Config{Dialer: dialer, MaxTCPFlows: maxFlows})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	var held []net.Conn
	for i := 0; i < maxFlows; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := peer.dialTCP(ctx, remoteHTTP)
		cancel()
		if err != nil {
			t.Fatalf("connection %d within the cap: %v", i+1, err)
		}
		defer conn.Close()
		echoRoundTrip(t, conn, "hold")
		held = append(held, conn)
	}

	// Over the cap: must be refused, and promptly — a reset, not a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := peer.dialTCP(ctx, remoteHTTP)
	cancel()
	if err == nil {
		_ = conn.Close()
		t.Fatalf("connection %d succeeded with MaxTCPFlows=%d", maxFlows+1, maxFlows)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("connection over the cap timed out (%v); want a reset", err)
	}
	if got := ns.Stats().RejectedFlows; got != 1 {
		t.Errorf("Stats.RejectedFlows = %d, want 1", got)
	}

	// Ending one flow frees its slot.
	_ = held[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := peer.dialTCP(ctx, remoteHTTP)
		cancel()
		if err == nil {
			defer conn.Close()
			echoRoundTrip(t, conn, "again")
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no slot was freed after closing a flow: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestStackUDPIdleFlowsAreReclaimed is the regression test for the UDP leak:
// the exit-to-app loop blocks in a session ReadFrom that has no deadline, so
// unless the flow's idle timeout closes the session, every abandoned flow
// keeps its goroutines, buffers and exit-node association forever.
func TestStackUDPIdleFlowsAreReclaimed(t *testing.T) {
	const flows = 20

	var mu sync.Mutex
	var sessions []*blockingUDPSession
	dialer := newFakeDialer()
	dialer.onUDP = func(context.Context, netip.AddrPort) (transport.UDPSession, error) {
		s := newBlockingUDPSession()
		mu.Lock()
		sessions = append(sessions, s)
		mu.Unlock()
		return s, nil
	}

	ns := newTestStack(t, Config{Dialer: dialer, udpIdleTimeout: 150 * time.Millisecond})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)
	baseline := runtime.NumGoroutine()

	for i := 0; i < flows; i++ {
		// A distinct destination per flow. The peer closes each socket at
		// once, so its next dial may reuse the same ephemeral source port;
		// to a shared destination that is the same 5-tuple as a flow the
		// stack still holds, the datagram joins that flow, and fewer than
		// `flows` dials ever happen. That made this test fail about once in
		// a hundred runs under load.
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)}), 1234)
		conn, err := peer.dialUDP(dst)
		if err != nil {
			t.Fatalf("dialUDP: %v", err)
		}
		if _, err := conn.Write([]byte("hello")); err != nil {
			t.Fatalf("writing datagram: %v", err)
		}
		_ = conn.Close() // the app abandons the flow, as apps do
	}

	waitFor(t, 5*time.Second, "every flow to be dialed", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sessions) == flows
	})
	waitFor(t, 5*time.Second, "idle flows to be reclaimed", func() bool {
		return ns.Stats().ActiveFlows == 0 && runtime.NumGoroutine() <= baseline+3
	})

	mu.Lock()
	defer mu.Unlock()
	for i, s := range sessions {
		if !s.isClosed() {
			t.Errorf("session %d was never closed after its flow went idle", i)
		}
	}
}

// TestStackUDPIdleRefreshedByDownstream guards the other half of the idle
// rule: a flow that only receives is not idle. The deadline lives on the app
// side, so it must be refreshed by exit-to-app traffic too, or tearing idle
// flows down would cut every receive-only stream after one timeout.
func TestStackUDPIdleRefreshedByDownstream(t *testing.T) {
	const idle = 200 * time.Millisecond
	dialer := newFakeDialer()
	dialer.onUDP = func(context.Context, netip.AddrPort) (transport.UDPSession, error) {
		return newTickingUDPSession(40 * time.Millisecond), nil
	}

	ns := newTestStack(t, Config{Dialer: dialer, udpIdleTimeout: idle})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	conn, err := peer.dialUDP(netip.MustParseAddrPort("8.8.8.8:1234"))
	if err != nil {
		t.Fatalf("dialUDP: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("subscribe")); err != nil {
		t.Fatalf("writing datagram: %v", err)
	}

	// Never write again; keep receiving well past several idle periods.
	end := time.Now().Add(4 * idle)
	buf := make([]byte, 64)
	for time.Now().Before(end) {
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("receive-only flow stopped delivering after %v of upstream silence: %v",
				idle, err)
		}
	}
}

// TestStackUDPFlowCap checks that MaxUDPFlows bounds proxied UDP flows.
func TestStackUDPFlowCap(t *testing.T) {
	const maxFlows = 2
	var dials atomic.Int32
	dialer := newFakeDialer()
	dialer.onUDP = func(context.Context, netip.AddrPort) (transport.UDPSession, error) {
		dials.Add(1)
		return newBlockingUDPSession(), nil
	}

	ns := newTestStack(t, Config{
		Dialer: dialer, MaxUDPFlows: maxFlows, udpIdleTimeout: 10 * time.Second,
	})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	for i := 0; i < maxFlows+1; i++ {
		conn, err := peer.dialUDP(netip.MustParseAddrPort("8.8.8.8:1234"))
		if err != nil {
			t.Fatalf("dialUDP: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("x")); err != nil {
			t.Fatalf("writing datagram: %v", err)
		}
	}

	waitFor(t, 5*time.Second, "the over-cap flow to be rejected", func() bool {
		return ns.Stats().RejectedFlows == 1
	})
	if got := dials.Load(); got != maxFlows {
		t.Errorf("transport dialed %d UDP flows, want the cap of %d", got, maxFlows)
	}
}

// TestStackDNSOverTCPInterception is the TCP counterpart of
// TestStackDNSInterception. A stub resolver retries over TCP after a
// truncated UDP answer; that retry must reach the DNS handler, never the
// transport, or it bypasses the DNS policy.
func TestStackDNSOverTCPInterception(t *testing.T) {
	dialer := newFakeDialer()
	dialer.onTCP = func(context.Context, netip.AddrPort) (net.Conn, error) {
		t.Error("DNS-over-TCP reached the transport; it should have been answered in-tunnel")
		return nil, transport.ErrUnsupportedFlow
	}

	handler := &recordingDNS{response: []byte("dns-answer")}
	ns := newTestStack(t, Config{Dialer: dialer, DNS: handler})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := peer.dialTCP(ctx, remoteDNS)
	if err != nil {
		t.Fatalf("dialTCP to %v: %v", remoteDNS, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// Two pipelined queries in one write, as RFC 7766 permits.
	query := []byte("dns-query")
	if _, err := conn.Write(append(frameDNS(query), frameDNS(query)...)); err != nil {
		t.Fatalf("writing queries: %v", err)
	}
	for i := 0; i < 2; i++ {
		resp, err := readFramedDNS(conn)
		if err != nil {
			t.Fatalf("reading response %d: %v", i+1, err)
		}
		if got, want := string(resp), "dns-answer"; got != want {
			t.Errorf("response %d = %q, want %q", i+1, got, want)
		}
	}
	if got := handler.lastQuery(); string(got) != string(query) {
		t.Errorf("handler saw query %q, want %q", got, query)
	}
	if client := handler.lastClient(); client.Addr() != tunnelAddr {
		t.Errorf("handler saw client %v, want an address of %v", client, tunnelAddr)
	}

	// A length the stack will not buffer ends the connection: there is no
	// way to resynchronise a length-prefixed stream after it.
	var bad [2]byte
	binary.BigEndian.PutUint16(bad[:], maxTCPDNSQuery+1)
	if _, err := conn.Write(bad[:]); err != nil {
		t.Fatalf("writing oversize length: %v", err)
	}
	if _, err := io.ReadAll(conn); err != nil {
		t.Errorf("after an oversize length the connection should close cleanly, got %v", err)
	}
}

// TestStackDNSOverTCPDeclinedIsProxied checks the fall-through: a handler
// that declines the first query gets the connection proxied unchanged,
// including the message already read to offer it to the handler.
func TestStackDNSOverTCPDeclinedIsProxied(t *testing.T) {
	dialer := newFakeDialer()
	dialer.onTCP = echoServer(t)

	ns := newTestStack(t, Config{Dialer: dialer, DNS: decliningDNS{}})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := peer.dialTCP(ctx, remoteDNS)
	if err != nil {
		t.Fatalf("dialTCP: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	if _, err := conn.Write(frameDNS([]byte("abc"))); err != nil {
		t.Fatalf("writing query: %v", err)
	}
	// The echo server upper-cases, which leaves the length prefix alone.
	resp, err := readFramedDNS(conn)
	if err != nil {
		t.Fatalf("reading proxied echo: %v", err)
	}
	if got, want := string(resp), "ABC"; got != want {
		t.Errorf("proxied echo = %q, want %q", got, want)
	}
}

// --- helpers ---

func echoRoundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("reading echo: %v", err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func frameDNS(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out, uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

func readFramedDNS(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

type decliningDNS struct{}

func (decliningDNS) HandleQuery(context.Context, netip.AddrPort, []byte) ([]byte, bool, error) {
	return nil, false, nil
}

// blockingUDPSession never receives anything: ReadFrom blocks until Close,
// like a real association whose peer has gone quiet. It has no deadline
// support, which is exactly what UDPSession does not promise.
type blockingUDPSession struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newBlockingUDPSession() *blockingUDPSession {
	return &blockingUDPSession{closed: make(chan struct{})}
}

func (s *blockingUDPSession) WriteTo(b []byte, _ netip.AddrPort) (int, error) {
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

func (s *blockingUDPSession) ReadFrom([]byte) (int, netip.AddrPort, error) {
	<-s.closed
	return 0, netip.AddrPort{}, net.ErrClosed
}

func (s *blockingUDPSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *blockingUDPSession) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// tickingUDPSession delivers a datagram every interval regardless of what is
// sent to it: a receive-only stream.
type tickingUDPSession struct {
	*blockingUDPSession
	tick *time.Ticker
}

func newTickingUDPSession(interval time.Duration) *tickingUDPSession {
	return &tickingUDPSession{
		blockingUDPSession: newBlockingUDPSession(),
		tick:               time.NewTicker(interval),
	}
}

func (s *tickingUDPSession) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	select {
	case <-s.tick.C:
		return copy(b, "tick"), netip.MustParseAddrPort("1.2.3.4:9"), nil
	case <-s.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (s *tickingUDPSession) Close() error {
	s.tick.Stop()
	return s.blockingUDPSession.Close()
}

var (
	_ transport.UDPSession = (*blockingUDPSession)(nil)
	_ transport.UDPSession = (*tickingUDPSession)(nil)
)
