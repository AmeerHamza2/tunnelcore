package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
)

var (
	cloudflare = netip.MustParseAddrPort("1.1.1.1:53")
	google     = netip.MustParseAddrPort("8.8.8.8:53")
	clientAddr = netip.MustParseAddrPort("10.9.0.2:51000")
)

// --- fixtures ---

// query builds a wire-format DNS query.
func query(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 0, 32+len(name))
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // standard query, RD
	b = binary.BigEndian.AppendUint16(b, 1)      // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b
}

// answer builds a response to q with one A record carrying the given TTL.
func answer(q []byte, ttl uint32, ip netip.Addr) []byte {
	resp := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // QR, RD, RA, NOERROR
	binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT

	// Answer: name as a compression pointer to the question, type A, class
	// IN, TTL, rdlength 4, the address.
	resp = append(resp, 0xc0, 0x0c)
	resp = binary.BigEndian.AppendUint16(resp, 1) // A
	resp = binary.BigEndian.AppendUint16(resp, 1) // IN
	resp = binary.BigEndian.AppendUint32(resp, ttl)
	resp = binary.BigEndian.AppendUint16(resp, 4)
	a4 := ip.As4()
	return append(resp, a4[:]...)
}

// withRcode returns a copy of resp with the header rcode replaced.
func withRcode(resp []byte, rcode uint16) []byte {
	out := append([]byte(nil), resp...)
	flags := binary.BigEndian.Uint16(out[2:4])
	binary.BigEndian.PutUint16(out[2:4], flags&^0x000f|rcode)
	return out
}

func truncatedAnswer(q []byte) []byte {
	resp := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8380) // QR, TC, RD, RA
	return resp
}

// tunnelTransport is a Transport that records every destination it was asked
// to reach, and answers with a configurable handler.
type tunnelTransport struct {
	mu       sync.Mutex
	dialedTo []netip.AddrPort

	// onQuery answers a UDP query. Returning an error fails the attempt.
	onQuery func(upstream netip.AddrPort, q []byte) ([]byte, error)
	// onQueryMulti, if set, replaces onQuery and delivers several datagrams
	// in order, so a test can put a forged reply ahead of the genuine one.
	onQueryMulti func(upstream netip.AddrPort, q []byte) [][]byte
	// onTCPQuery answers a TCP query; nil means TCP is unavailable.
	onTCPQuery func(upstream netip.AddrPort, q []byte) ([]byte, error)

	openSessions atomic.Int32
	udpDials     atomic.Int32
	tcpDials     atomic.Int32
}

func newTunnelTransport(onQuery func(netip.AddrPort, []byte) ([]byte, error)) *tunnelTransport {
	return &tunnelTransport{onQuery: onQuery}
}

func (t *tunnelTransport) record(dst netip.AddrPort) {
	t.mu.Lock()
	t.dialedTo = append(t.dialedTo, dst)
	t.mu.Unlock()
}

func (t *tunnelTransport) destinations() []netip.AddrPort {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]netip.AddrPort(nil), t.dialedTo...)
}

func (t *tunnelTransport) DialUDP(_ context.Context, dst netip.AddrPort) (UDPSession, error) {
	t.record(dst)
	t.udpDials.Add(1)
	t.openSessions.Add(1)
	return &fakeSession{t: t, upstream: dst, replies: make(chan []byte, 4)}, nil
}

func (t *tunnelTransport) DialTCP(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	t.record(dst)
	t.tcpDials.Add(1)
	if t.onTCPQuery == nil {
		return nil, errors.New("tunnelTransport: TCP unavailable")
	}

	ours, theirs := net.Pipe()
	go func() {
		defer theirs.Close()
		var lenBuf [2]byte
		if _, err := readFull(theirs, lenBuf[:]); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(lenBuf[:]))
		q := make([]byte, size)
		if _, err := readFull(theirs, q); err != nil {
			return
		}
		resp, err := t.onTCPQuery(dst, q)
		if err != nil {
			return
		}
		framed := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(framed[0:2], uint16(len(resp)))
		copy(framed[2:], resp)
		_, _ = theirs.Write(framed)
	}()
	return ours, nil
}

type fakeSession struct {
	t        *tunnelTransport
	upstream netip.AddrPort
	replies  chan []byte

	closeOnce sync.Once
	closed    chan struct{}
	initOnce  sync.Once
}

func (s *fakeSession) init() {
	s.initOnce.Do(func() { s.closed = make(chan struct{}) })
}

func (s *fakeSession) WriteTo(b []byte, _ netip.AddrPort) (int, error) {
	s.init()
	if s.t.onQueryMulti != nil {
		for _, resp := range s.t.onQueryMulti(s.upstream, append([]byte(nil), b...)) {
			select {
			case s.replies <- resp:
			default:
			}
		}
		return len(b), nil
	}
	resp, err := s.t.onQuery(s.upstream, append([]byte(nil), b...))
	if err != nil {
		return 0, err
	}
	if resp != nil {
		select {
		case s.replies <- resp:
		default:
		}
	}
	return len(b), nil
}

func (s *fakeSession) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	s.init()
	select {
	case r := <-s.replies:
		return copy(b, r), s.upstream, nil
	case <-s.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	case <-time.After(5 * time.Second):
		return 0, netip.AddrPort{}, errors.New("fakeSession: read timed out")
	}
}

func (s *fakeSession) Close() error {
	s.init()
	s.closeOnce.Do(func() {
		close(s.closed)
		s.t.openSessions.Add(-1)
	})
	return nil
}

func newResolver(t *testing.T, cfg Config) *Resolver {
	t.Helper()
	if len(cfg.Upstreams) == 0 {
		cfg.Upstreams = []netip.AddrPort{cloudflare}
	}
	r, err := New(cfg)
	if err != nil {
		t.Fatalf("dnsproxy.New: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// --- the leak tests ---

// failingTransport is a tunnel that cannot reach anything.
//
// It stands in for the situation that produces real DNS leaks: the tunnel is
// up but the exit node is unreachable, or the transport has just been torn
// down for a reconnect, and a query arrives in that window.
type failingTransport struct {
	udpDials atomic.Int32
	tcpDials atomic.Int32
}

func (f *failingTransport) DialUDP(context.Context, netip.AddrPort) (UDPSession, error) {
	f.udpDials.Add(1)
	return nil, errors.New("tunnel unavailable")
}

func (f *failingTransport) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	f.tcpDials.Add(1)
	return nil, errors.New("tunnel unavailable")
}

// TestFailsClosedWhenTunnelUnavailable is the central anti-leak property, and
// it is a property about what the resolver *refuses* to do.
//
// A DNS leak is rarely someone deliberately dialling the system resolver. It
// is a fallback: the tunnel is slow or down, a query is failing, and somewhere
// there is a "well, try the normal resolver then" path — added for
// reliability, entirely reasonable-looking in review. The result is that
// precisely when the VPN is struggling, every name the user looks up goes to
// their ISP in cleartext, while the UI still says "connected".
//
// So this test makes the tunnel fail every single time and asserts that no
// query is ever answered positively. Every response must be a locally
// synthesised error. If anyone ever adds a fallback resolver, this test starts
// returning NOERROR with answer records and fails.
func TestFailsClosedWhenTunnelUnavailable(t *testing.T) {
	tr := &failingTransport{}

	r := newResolver(t, Config{
		Transport:    tr,
		Upstreams:    []netip.AddrPort{cloudflare, google},
		QueryTimeout: 100 * time.Millisecond,
		Policy:       denyList{"blocked.example.com": true},
	})

	cases := []struct {
		name  string
		query []byte
	}{
		{"normal query", query(1, "example.com", packet.QTypeA)},
		{"AAAA query", query(2, "example.com", packet.QTypeAAAA)},
		{"HTTPS query", query(3, "example.com", packet.QTypeHTTPS)},
		{"blocked by policy", query(4, "blocked.example.com", packet.QTypeA)},
		{"malformed", []byte{0x00, 0x01, 0x02}},
		{"empty", nil},
		{"header only", make([]byte, 12)},
		{"compression pointer in question", append(
			append([]byte(nil), query(5, "x", packet.QTypeA)[:12]...), 0xc0, 0x0c, 0, 1, 0, 1)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, handled, err := r.HandleQuery(context.Background(), clientAddr, tc.query)

			// Nothing may fall through to the generic proxy path: that would
			// send the query to whatever address the app aimed it at, which
			// on a misconfigured device is the DHCP resolver.
			if !handled {
				t.Fatal("handled = false; the query would fall through to the proxy path")
			}

			// Nothing may be silently dropped either. A dropped query makes
			// the stub resolver wait out its full timeout and then, on many
			// platforms, fall back to a resolver outside the tunnel — turning
			// a drop into the very leak this guards against.
			if err == nil && resp == nil {
				t.Fatal("query silently dropped: neither a response nor an error")
			}
			if err != nil {
				return // an error is an acceptable, non-leaking outcome
			}

			// And crucially: no positive answer. The tunnel is down, so
			// nothing could legitimately have resolved.
			if len(resp) < 12 {
				t.Fatalf("returned a %d-byte response, shorter than a DNS header", len(resp))
			}
			flags := binary.BigEndian.Uint16(resp[2:4])
			rcode := flags & 0x000f
			answers := binary.BigEndian.Uint16(resp[6:8])

			if rcode == 0 && answers > 0 {
				t.Fatalf("got NOERROR with %d answer record(s) while the tunnel was unreachable: "+
					"something resolved this name outside the tunnel", answers)
			}
			if flags&0x8000 == 0 {
				t.Error("QR bit is clear; the client will discard this as a query, not a response")
			}
		})
	}

	// After Close, the same must hold.
	_ = r.Close()
	if _, _, err := r.HandleQuery(context.Background(), clientAddr,
		query(9, "example.com", packet.QTypeA)); !errors.Is(err, ErrClosed) {
		t.Errorf("HandleQuery after Close = %v, want ErrClosed", err)
	}
}

// TestEveryPositiveAnswerCameThroughTheTunnel is the other half: when answers
// *do* come back, each one must be attributable to a dial through the tunnel
// or to the cache. An answer that appears without either is an answer that
// came from somewhere else.
func TestEveryPositiveAnswerCameThroughTheTunnel(t *testing.T) {
	var upstreamAnswers atomic.Int32
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		upstreamAnswers.Add(1)
		return answer(q, 300, netip.MustParseAddr("93.184.216.34")), nil
	})

	var cacheHits atomic.Int32
	r := newResolver(t, Config{
		Transport: tr,
		Upstreams: []netip.AddrPort{cloudflare, google},
		OnQuery: func(_ string, _ uint16, _ bool, cached bool, _ error) {
			if cached {
				cacheHits.Add(1)
			}
		},
	})

	const unique, repeats = 20, 3
	var positives int
	for i := 0; i < unique; i++ {
		name := fmt.Sprintf("host%d.example.com", i)
		for rep := 0; rep < repeats; rep++ {
			resp, _, err := r.HandleQuery(context.Background(), clientAddr,
				query(uint16(i*repeats+rep), name, packet.QTypeA))
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if binary.BigEndian.Uint16(resp[2:4])&0x000f == 0 && binary.BigEndian.Uint16(resp[6:8]) > 0 {
				positives++
			}
		}
	}

	accounted := int(upstreamAnswers.Load()) + int(cacheHits.Load())
	if positives != accounted {
		t.Errorf("%d positive answers but only %d accounted for (%d from the tunnel, %d from the cache): "+
			"%d answer(s) came from an unaccounted source",
			positives, accounted, upstreamAnswers.Load(), cacheHits.Load(), positives-accounted)
	}

	// Every destination must be one we configured, not one an app chose.
	allowed := map[netip.AddrPort]bool{cloudflare: true, google: true}
	for _, dst := range tr.destinations() {
		if !allowed[dst] {
			t.Errorf("a query was sent to %v, which is not a configured upstream", dst)
		}
	}
}

type denyList map[string]bool

func (d denyList) Allow(name string, _ uint16) bool { return !d[name] }

// --- resolution ---

func TestResolveSuccess(t *testing.T) {
	want := netip.MustParseAddr("93.184.216.34")
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(q, 300, want), nil
	})
	r := newResolver(t, Config{Transport: tr})

	q := query(0x1234, "example.com", packet.QTypeA)
	resp, handled, err := r.HandleQuery(context.Background(), clientAddr, q)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if !handled {
		t.Fatal("handled = false")
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Errorf("response transaction ID = %#x, want 0x1234", got)
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Errorf("ANCOUNT = %d, want 1", binary.BigEndian.Uint16(resp[6:8]))
	}
}

func TestPolicyBlockReturnsNXDOMAIN(t *testing.T) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		t.Error("a blocked name was sent upstream")
		return nil, errors.New("should not be reached")
	})
	r := newResolver(t, Config{
		Transport: tr,
		Policy:    denyList{"ads.example.com": true},
	})

	resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(1, "ads.example.com", packet.QTypeA))
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000f; rcode != rcodeNXDomain {
		t.Errorf("rcode = %d, want %d (NXDOMAIN)", rcode, rcodeNXDomain)
	}
	// NXDOMAIN rather than a drop: an answered failure fails the app
	// immediately, where a dropped query makes it retry for seconds.
	if binary.BigEndian.Uint16(resp[2:4])&0x8000 == 0 {
		t.Error("QR bit is not set; the client will discard this as a query, not a response")
	}
}

func TestUpstreamFailureReturnsSERVFAIL(t *testing.T) {
	tr := newTunnelTransport(func(netip.AddrPort, []byte) ([]byte, error) {
		return nil, errors.New("upstream unreachable")
	})
	r := newResolver(t, Config{
		Transport:    tr,
		QueryTimeout: 100 * time.Millisecond,
	})

	resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000f; rcode != rcodeServFail {
		t.Errorf("rcode = %d, want %d (SERVFAIL)", rcode, rcodeServFail)
	}
}

func TestMalformedQueryReturnsFORMERR(t *testing.T) {
	tr := newTunnelTransport(func(netip.AddrPort, []byte) ([]byte, error) {
		t.Error("a malformed query was sent upstream")
		return nil, nil
	})
	r := newResolver(t, Config{Transport: tr})

	// A header with QDCOUNT 1 but no question section.
	bad := make([]byte, 12)
	binary.BigEndian.PutUint16(bad[4:6], 1)

	resp, _, err := r.HandleQuery(context.Background(), clientAddr, bad)
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000f; rcode != rcodeFormErr {
		t.Errorf("rcode = %d, want %d (FORMERR)", rcode, rcodeFormErr)
	}
}

func TestOversizeQueryRejected(t *testing.T) {
	r := newResolver(t, Config{Transport: newTunnelTransport(nil)})
	_, _, err := r.HandleQuery(context.Background(), clientAddr, make([]byte, maxMessageSize+1))
	if !errors.Is(err, ErrQueryTooLarge) {
		t.Errorf("HandleQuery with an oversize query = %v, want ErrQueryTooLarge", err)
	}
}

// TestUpstreamFailoverAndReordering checks that a dead upstream is demoted
// rather than retried first on every query, which would otherwise cost every
// single lookup a full timeout.
func TestUpstreamFailoverAndReordering(t *testing.T) {
	var firstTried atomic.Int32
	tr := newTunnelTransport(func(upstream netip.AddrPort, q []byte) ([]byte, error) {
		if upstream == cloudflare {
			firstTried.Add(1)
			return nil, errors.New("dead")
		}
		return answer(q, 300, netip.MustParseAddr("8.8.8.8")), nil
	})
	r := newResolver(t, Config{
		Transport:    tr,
		Upstreams:    []netip.AddrPort{cloudflare, google},
		QueryTimeout: 200 * time.Millisecond,
		DisableCache: true,
	})

	for i := 0; i < 6; i++ {
		name := fmt.Sprintf("h%d.example.com", i)
		resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(uint16(i), name, packet.QTypeA))
		if err != nil {
			t.Fatalf("HandleQuery %d: %v", i, err)
		}
		if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000f; rcode != 0 {
			t.Fatalf("query %d got rcode %d, want NOERROR via the healthy upstream", i, rcode)
		}
	}

	// The dead upstream should have been demoted, so it is not tried on
	// every query after the first few.
	if n := firstTried.Load(); n >= 6 {
		t.Errorf("the dead upstream was tried %d times across 6 queries; it was never demoted", n)
	}
}

func TestTruncatedResponseRetriesOverTCP(t *testing.T) {
	full := netip.MustParseAddr("93.184.216.34")

	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return truncatedAnswer(q), nil
	})
	tr.onTCPQuery = func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(q, 300, full), nil
	}

	r := newResolver(t, Config{Transport: tr, DisableCache: true})

	resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if isTruncated(resp) {
		t.Error("the returned response is still truncated; the TCP retry did not happen or was discarded")
	}
	if tr.tcpDials.Load() == 0 {
		t.Error("no TCP dial was made for a truncated response")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Error("the TCP response has no answer records")
	}
}

// TestTruncatedResponseWithoutTCPStillReturnsSomething: if TCP also fails, the
// truncated UDP answer is better than SERVFAIL, because the records it does
// contain may be enough.
func TestTruncatedResponseWithoutTCPStillReturnsSomething(t *testing.T) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return truncatedAnswer(q), nil
	})
	// onTCPQuery stays nil, so TCP dials fail.

	r := newResolver(t, Config{Transport: tr, DisableCache: true})
	resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if resp == nil {
		t.Fatal("no response returned")
	}
	if rcode := binary.BigEndian.Uint16(resp[2:4]) & 0x000f; rcode == rcodeServFail {
		t.Error("got SERVFAIL; the truncated answer should have been returned instead")
	}
}

// TestSessionsAreClosed is a resource-leak assertion. One leaked UDP
// association per query exhausts the exit node's port table under load.
func TestSessionsAreClosed(t *testing.T) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(q, 300, netip.MustParseAddr("1.2.3.4")), nil
	})
	r := newResolver(t, Config{Transport: tr, DisableCache: true})

	for i := 0; i < 50; i++ {
		name := fmt.Sprintf("h%d.example.com", i)
		if _, _, err := r.HandleQuery(context.Background(), clientAddr, query(uint16(i), name, packet.QTypeA)); err != nil {
			t.Fatalf("HandleQuery %d: %v", i, err)
		}
	}

	if open := tr.openSessions.Load(); open != 0 {
		t.Errorf("%d UDP session(s) left open after 50 queries", open)
	}
}

// --- caching ---

func TestCacheServesRepeatQueries(t *testing.T) {
	var upstreamCalls atomic.Int32
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		upstreamCalls.Add(1)
		return answer(q, 300, netip.MustParseAddr("93.184.216.34")), nil
	})
	r := newResolver(t, Config{Transport: tr})

	for i := 0; i < 5; i++ {
		// Different transaction IDs, same name: a cache keyed on the whole
		// message rather than the question would miss every time.
		if _, _, err := r.HandleQuery(context.Background(), clientAddr, query(uint16(i), "example.com", packet.QTypeA)); err != nil {
			t.Fatalf("HandleQuery %d: %v", i, err)
		}
	}

	if n := upstreamCalls.Load(); n != 1 {
		t.Errorf("%d upstream calls for 5 identical questions, want 1", n)
	}
}

// TestCacheRewritesTransactionID: a cached response still carries the ID of
// the query that produced it. Returning it unchanged makes the stub resolver
// discard it as unsolicited, so the cache would silently do nothing but add
// latency.
func TestCacheRewritesTransactionID(t *testing.T) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(q, 300, netip.MustParseAddr("93.184.216.34")), nil
	})
	r := newResolver(t, Config{Transport: tr})

	if _, _, err := r.HandleQuery(context.Background(), clientAddr, query(0x1111, "example.com", packet.QTypeA)); err != nil {
		t.Fatalf("priming the cache: %v", err)
	}

	resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(0x2222, "example.com", packet.QTypeA))
	if err != nil {
		t.Fatalf("cached HandleQuery: %v", err)
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x2222 {
		t.Errorf("cached response transaction ID = %#x, want 0x2222", got)
	}
}

func TestCacheKeyIncludesQType(t *testing.T) {
	var calls atomic.Int32
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		calls.Add(1)
		return answer(q, 300, netip.MustParseAddr("1.2.3.4")), nil
	})
	r := newResolver(t, Config{Transport: tr})

	_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
	_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(2, "example.com", packet.QTypeAAAA))

	if n := calls.Load(); n != 2 {
		t.Errorf("%d upstream calls for an A and an AAAA query, want 2; the cache key ignores qtype", n)
	}
}

func TestCacheTTLClamping(t *testing.T) {
	tests := []struct {
		name    string
		ttl     uint32
		floor   time.Duration
		ceiling time.Duration
		want    time.Duration
	}{
		{"below floor", 1, 30 * time.Second, time.Hour, 30 * time.Second},
		{"within range", 300, 30 * time.Second, time.Hour, 300 * time.Second},
		{"above ceiling", 604800, 30 * time.Second, time.Minute, time.Minute},
		{"negative TTL treated as zero", 0xffffffff, 30 * time.Second, time.Hour, 30 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(tt.floor, tt.ceiling)
			q := query(1, "example.com", packet.QTypeA)
			resp := answer(q, tt.ttl, netip.MustParseAddr("1.2.3.4"))

			if got := c.clampTTL(responseTTL(resp)); got != tt.want {
				t.Errorf("clamped TTL = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCacheExpiry(t *testing.T) {
	c := newCache(10*time.Millisecond, 20*time.Millisecond)
	q := query(1, "example.com", packet.QTypeA)
	resp := answer(q, 1, netip.MustParseAddr("1.2.3.4"))

	c.put("example.com", packet.QTypeA, resp)
	if _, ok := c.get("example.com", packet.QTypeA); !ok {
		t.Fatal("entry missing immediately after put")
	}

	time.Sleep(40 * time.Millisecond)
	if _, ok := c.get("example.com", packet.QTypeA); ok {
		t.Error("expired entry was still served")
	}
	if c.size() != 0 {
		t.Errorf("cache size = %d after serving an expired entry, want 0", c.size())
	}
}

// TestCacheIsBounded is the memory-safety property: a device resolving
// aggressively must not be able to grow the cache without limit.
func TestCacheIsBounded(t *testing.T) {
	c := newCache(time.Hour, time.Hour)
	q := query(1, "x", packet.QTypeA)
	resp := answer(q, 3600, netip.MustParseAddr("1.2.3.4"))

	for i := 0; i < maxCacheEntries*3; i++ {
		c.put(fmt.Sprintf("host%d.example.com", i), packet.QTypeA, resp)
	}
	if size := c.size(); size > maxCacheEntries {
		t.Errorf("cache holds %d entries, above the %d limit", size, maxCacheEntries)
	}
}

// TestCacheIsBoundedInBytes is the regression test for the cache being
// bounded by entry count alone. Answers fetched over TCP can be up to 64 KiB
// and any web page can make the device resolve attacker-controlled names, so
// 2048 large entries pinned ~128 MiB on a device whose network extension may
// be killed at a few tens of MiB.
func TestCacheIsBoundedInBytes(t *testing.T) {
	c := newCache(time.Hour, time.Hour)
	q := query(1, "x", 16)
	big := answer(q, 3600, netip.MustParseAddr("1.2.3.4"))
	big = append(big, make([]byte, 60<<10)...) // padding past the records

	for i := 0; i < maxCacheEntries; i++ {
		c.put(fmt.Sprintf("host%d.example.com", i), 16, big)
	}
	small := answer(query(1, "y", packet.QTypeA), 3600, netip.MustParseAddr("1.2.3.4"))
	for i := 0; i < maxCacheEntries*2; i++ {
		c.put(fmt.Sprintf("s%d.example.com", i), packet.QTypeA, small)
		if i%7 == 0 {
			c.put(fmt.Sprintf("s%d.example.com", i), packet.QTypeA, small) // overwrite
		}
	}
	for i := 0; i < 64; i++ {
		med := append(append([]byte(nil), small...), make([]byte, 30<<10)...)
		c.put(fmt.Sprintf("m%d.example.com", i), packet.QTypeA, med)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	total := 0
	for k, e := range c.entries {
		total += entrySize(k.name, e.response, e.ttlOffsets)
	}
	if total != c.bytes {
		t.Errorf("byte accounting drifted: tracked %d, actual %d", c.bytes, total)
	}
	if total > maxCacheBytes {
		t.Errorf("cache holds %d bytes, above the %d limit", total, maxCacheBytes)
	}
	if len(c.entries) > maxCacheEntries {
		t.Errorf("cache holds %d entries, above the %d limit", len(c.entries), maxCacheEntries)
	}
}

func TestCacheStoresACopy(t *testing.T) {
	c := newCache(time.Minute, time.Hour)
	q := query(1, "example.com", packet.QTypeA)
	resp := answer(q, 300, netip.MustParseAddr("1.2.3.4"))

	c.put("example.com", packet.QTypeA, resp)
	// Mutate the caller's buffer. A cache that stored the slice rather than a
	// copy would now serve corrupted answers, and the buffer in question is
	// one the transport reuses.
	for i := range resp {
		resp[i] = 0xff
	}

	got, ok := c.get("example.com", packet.QTypeA)
	if !ok {
		t.Fatal("entry missing")
	}
	if got[0] == 0xff {
		t.Error("the cache stored the caller's slice rather than a copy")
	}
}

func TestDisableCache(t *testing.T) {
	var calls atomic.Int32
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		calls.Add(1)
		return answer(q, 3600, netip.MustParseAddr("1.2.3.4")), nil
	})
	r := newResolver(t, Config{Transport: tr, DisableCache: true})

	for i := 0; i < 3; i++ {
		_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(uint16(i), "example.com", packet.QTypeA))
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("%d upstream calls with the cache disabled, want 3", n)
	}
}

// --- config and hooks ---

func TestNewValidation(t *testing.T) {
	tr := newTunnelTransport(nil)

	t.Run("no transport", func(t *testing.T) {
		if _, err := New(Config{Upstreams: []netip.AddrPort{cloudflare}}); !errors.Is(err, ErrNoTransport) {
			t.Errorf("New = %v, want ErrNoTransport", err)
		}
	})
	t.Run("no upstreams", func(t *testing.T) {
		if _, err := New(Config{Transport: tr}); !errors.Is(err, ErrNoUpstreams) {
			t.Errorf("New = %v, want ErrNoUpstreams", err)
		}
	})
	t.Run("upstream without a port", func(t *testing.T) {
		_, err := New(Config{
			Transport: tr,
			Upstreams: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), 0)},
		})
		if err == nil {
			t.Error("New with a port-less upstream = nil, want an error")
		}
	})
}

// TestOnQueryHookCarriesNoClientIdentity checks a privacy constraint, not a
// feature: the metrics hook must not be usable as a per-user browsing log. It
// receives the name and qtype and nothing that identifies who asked.
func TestOnQueryHookCarriesNoClientIdentity(t *testing.T) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(q, 300, netip.MustParseAddr("1.2.3.4")), nil
	})

	type observation struct {
		name   string
		qtype  uint16
		cached bool
	}
	var mu sync.Mutex
	var seen []observation

	r := newResolver(t, Config{
		Transport: tr,
		OnQuery: func(name string, qtype uint16, _ bool, cached bool, _ error) {
			mu.Lock()
			seen = append(seen, observation{name, qtype, cached})
			mu.Unlock()
		},
	})

	_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
	_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(2, "example.com", packet.QTypeA))

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("hook fired %d times, want 2", len(seen))
	}
	if seen[0].cached {
		t.Error("the first query was reported as cached")
	}
	if !seen[1].cached {
		t.Error("the second identical query was not reported as cached")
	}
}

// --- concurrency ---

// TestConcurrentQueries runs many simultaneous lookups. The resolver is shared
// by every app on the device, so concurrent use is the normal case, not an
// edge case.
func TestConcurrentQueries(t *testing.T) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(q, 300, netip.MustParseAddr("1.2.3.4")), nil
	})
	r := newResolver(t, Config{Transport: tr})

	const (
		workers = 32
		each    = 25
	)
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				// Mix repeated and unique names so the cache is exercised
				// concurrently for both hits and misses.
				name := "shared.example.com"
				if i%3 == 0 {
					name = fmt.Sprintf("w%d-%d.example.com", w, i)
				}
				_, _, err := r.HandleQuery(context.Background(), clientAddr, query(uint16(i), name, packet.QTypeA))
				if err != nil {
					errs <- err
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent HandleQuery: %v", err)
	}
	if open := tr.openSessions.Load(); open != 0 {
		t.Errorf("%d UDP session(s) leaked under concurrent load", open)
	}
}

// --- fuzzing ---

// FuzzHandleQuery asserts the proxy never panics and never silently drops.
//
// The input is a DNS message written by an arbitrary application on the
// device. A panic here takes down the VPN process, drops the tunnel, and sends
// the user's traffic out in the clear.
func FuzzHandleQuery(f *testing.F) {
	f.Add(query(1, "example.com", packet.QTypeA))
	f.Add(query(2, "a.b.c.d.e", packet.QTypeAAAA))
	f.Add(make([]byte, 12))
	f.Add([]byte{})
	f.Add([]byte{0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c})

	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		if len(q) < 12 {
			return nil, errors.New("too short to answer")
		}
		return answer(q, 300, netip.MustParseAddr("1.2.3.4")), nil
	})
	r, err := New(Config{Transport: tr, Upstreams: []netip.AddrPort{cloudflare}})
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		resp, handled, err := r.HandleQuery(context.Background(), clientAddr, msg)
		if !handled {
			t.Fatal("handled = false; the query would fall through to the proxy path")
		}
		if err == nil && resp == nil {
			t.Fatal("query silently dropped: neither a response nor an error")
		}
		if err != nil {
			return
		}
		// Any response we synthesise or relay must at least be a valid DNS
		// header with the QR bit set, or the client discards it.
		if len(resp) < 12 {
			t.Fatalf("returned a %d-byte response, shorter than a DNS header", len(resp))
		}
		if binary.BigEndian.Uint16(resp[2:4])&0x8000 == 0 {
			t.Fatal("returned a message with the QR bit clear; a client treats this as a query, not a response")
		}
	})
}

// FuzzResponseTTL covers the one place in this package that walks past the
// question section.
func FuzzResponseTTL(f *testing.F) {
	q := query(1, "example.com", packet.QTypeA)
	f.Add(answer(q, 300, netip.MustParseAddr("1.2.3.4")))
	f.Add(q)
	f.Add(make([]byte, 12))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, msg []byte) {
		ttl := responseTTL(msg)
		if ttl < 0 {
			t.Fatalf("responseTTL returned a negative duration: %s", ttl)
		}
		if ttl > 0x7fffffff*time.Second {
			t.Fatalf("responseTTL returned %s, beyond the maximum valid TTL", ttl)
		}
	})
}

// --- benchmarks ---

func BenchmarkHandleQueryCached(b *testing.B) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(q, 3600, netip.MustParseAddr("1.2.3.4")), nil
	})
	r, err := New(Config{Transport: tr, Upstreams: []netip.AddrPort{cloudflare}})
	if err != nil {
		b.Fatal(err)
	}
	q := query(1, "example.com", packet.QTypeA)
	if _, _, err := r.HandleQuery(context.Background(), clientAddr, q); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := r.HandleQuery(context.Background(), clientAddr, q); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCacheGet(b *testing.B) {
	c := newCache(time.Minute, time.Hour)
	q := query(1, "example.com", packet.QTypeA)
	c.put("example.com", packet.QTypeA, answer(q, 300, netip.MustParseAddr("1.2.3.4")))

	b.ReportAllocs()
	for b.Loop() {
		if _, ok := c.get("example.com", packet.QTypeA); !ok {
			b.Fatal("miss")
		}
	}
}

// --- upstream reply validation ---

// TestRejectsMismatchedUpstreamReply: a reply is only accepted if it answers
// the question that was sent. Each forgery below used to be relayed and cached
// under the query's name, and the cache-hit ID rewrite then made it look like
// a valid answer to every later client.
func TestRejectsMismatchedUpstreamReply(t *testing.T) {
	poison := netip.MustParseAddr("6.6.6.6")
	genuine := netip.MustParseAddr("93.184.216.34")

	tests := []struct {
		name  string
		forge func(q []byte) []byte
	}{
		{"wrong transaction ID", func(q []byte) []byte {
			r := answer(q, 300, poison)
			binary.BigEndian.PutUint16(r[0:2], binary.BigEndian.Uint16(q[0:2])^0xffff)
			return r
		}},
		{"different name and ID", func(q []byte) []byte {
			r := answer(query(0x9999, "evil.test", packet.QTypeA), 300, poison)
			return r
		}},
		{"different name, same ID", func(q []byte) []byte {
			return answer(query(binary.BigEndian.Uint16(q[0:2]), "evil.test", packet.QTypeA), 300, poison)
		}},
		{"QR bit clear", func(q []byte) []byte {
			r := answer(q, 300, poison)
			binary.BigEndian.PutUint16(r[2:4], binary.BigEndian.Uint16(r[2:4])&^0x8000)
			return r
		}},
		{"no question section", func(q []byte) []byte {
			r := answer(q, 300, poison)
			binary.BigEndian.PutUint16(r[4:6], 0)
			return r
		}},
		{"different qtype", func(q []byte) []byte {
			r := answer(q, 300, poison)
			binary.BigEndian.PutUint16(r[len(q)-4:len(q)-2], packet.QTypeAAAA)
			return r
		}},
		{"different qclass", func(q []byte) []byte {
			r := answer(q, 300, poison)
			binary.BigEndian.PutUint16(r[len(q)-2:len(q)], 3) // CHAOS
			return r
		}},
		{"garbage", func([]byte) []byte { return []byte{1, 2, 3} }},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/alone", func(t *testing.T) {
			var forging atomic.Bool
			forging.Store(true)
			var calls atomic.Int32
			tr := newTunnelTransport(nil)
			tr.onQueryMulti = func(_ netip.AddrPort, q []byte) [][]byte {
				calls.Add(1)
				if forging.Load() {
					return [][]byte{tt.forge(q)}
				}
				return [][]byte{answer(q, 300, genuine)}
			}
			r := newResolver(t, Config{Transport: tr, QueryTimeout: 50 * time.Millisecond})

			resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(0x1234, "example.com", packet.QTypeA))
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if rc := binary.BigEndian.Uint16(resp[2:4]) & 0x000f; rc != rcodeServFail {
				t.Fatalf("rcode = %d, want SERVFAIL: the forged reply was accepted", rc)
			}

			// And nothing was cached: the next query must go upstream and
			// get the genuine answer.
			forging.Store(false)
			resp, _, err = r.HandleQuery(context.Background(), clientAddr, query(0x5678, "example.com", packet.QTypeA))
			if err != nil {
				t.Fatalf("second HandleQuery: %v", err)
			}
			if calls.Load() != 2 {
				t.Errorf("%d upstream calls, want 2: the forged reply was served from the cache", calls.Load())
			}
			if got := resp[len(resp)-4:]; netip.AddrFrom4([4]byte(got)) != genuine {
				t.Errorf("second answer = %v, want %v", got, genuine)
			}
		})

		t.Run(tt.name+"/ahead of genuine", func(t *testing.T) {
			tr := newTunnelTransport(nil)
			tr.onQueryMulti = func(_ netip.AddrPort, q []byte) [][]byte {
				return [][]byte{tt.forge(q), answer(q, 300, genuine)}
			}
			r := newResolver(t, Config{Transport: tr, QueryTimeout: time.Second})

			resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(0x1234, "example.com", packet.QTypeA))
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if got := resp[len(resp)-4:]; netip.AddrFrom4([4]byte(got)) != genuine {
				t.Errorf("answer = %v, want %v: the forged reply won the race", got, genuine)
			}
		})
	}
}

// TestTCPFallbackRejectsMismatchedReply: validation that only the UDP path
// applies is bypassed by an attacker who forces TC=1.
func TestTCPFallbackRejectsMismatchedReply(t *testing.T) {
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return truncatedAnswer(q), nil
	})
	tr.onTCPQuery = func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return answer(query(0x9999, "evil.test", packet.QTypeA), 300, netip.MustParseAddr("6.6.6.6")), nil
	}
	r := newResolver(t, Config{Transport: tr})

	resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(0x1234, "example.com", packet.QTypeA))
	if err != nil {
		t.Fatalf("HandleQuery: %v", err)
	}
	if n := binary.BigEndian.Uint16(resp[6:8]); n != 0 {
		t.Errorf("ANCOUNT = %d, want 0: the forged TCP reply was relayed", n)
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Errorf("ID = %#x, want 0x1234", got)
	}
}

// TestCacheDistinguishesDotInsideLabel: the single label "www.example.com" is
// a different name from www/example/com. Decoding both to the same string let
// an answer for one be served from the cache for the other.
func TestCacheDistinguishesDotInsideLabel(t *testing.T) {
	var calls atomic.Int32
	tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
		calls.Add(1)
		return answer(q, 300, netip.MustParseAddr("1.2.3.4")), nil
	})
	r := newResolver(t, Config{Transport: tr})

	oneLabel := append([]byte(nil), query(1, "x", packet.QTypeA)[:12]...)
	oneLabel = append(oneLabel, 15)
	oneLabel = append(oneLabel, "www.example.com"...)
	oneLabel = append(oneLabel, 0, 0, 1, 0, 1)

	_, _, _ = r.HandleQuery(context.Background(), clientAddr, oneLabel)
	_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(2, "www.example.com", packet.QTypeA))

	if n := calls.Load(); n != 2 {
		t.Errorf("%d upstream calls, want 2: the one-label name shared a cache entry with the real one", n)
	}
}

// --- what is cached, and failover on error rcodes ---

func TestErrorRcodesFailOverAndAreNotCached(t *testing.T) {
	tests := []struct {
		name  string
		rcode uint16
	}{
		{"SERVFAIL", rcodeServFail},
		{"REFUSED", rcodeRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/next upstream answers", func(t *testing.T) {
			var badCalls, goodCalls atomic.Int32
			tr := newTunnelTransport(func(upstream netip.AddrPort, q []byte) ([]byte, error) {
				if upstream == cloudflare {
					badCalls.Add(1)
					return withRcode(errorResponse(q, 0), tt.rcode), nil
				}
				goodCalls.Add(1)
				return answer(q, 300, netip.MustParseAddr("1.2.3.4")), nil
			})
			r := newResolver(t, Config{Transport: tr, Upstreams: []netip.AddrPort{cloudflare, google}})

			resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if rc := binary.BigEndian.Uint16(resp[2:4]) & 0x000f; rc != rcodeNoError {
				t.Errorf("rcode = %d, want NOERROR from the second upstream", rc)
			}
			if badCalls.Load() != 1 || goodCalls.Load() != 1 {
				t.Errorf("calls: failing upstream %d, healthy upstream %d; want 1 and 1",
					badCalls.Load(), goodCalls.Load())
			}
		})

		t.Run(tt.name+"/every upstream fails", func(t *testing.T) {
			var calls atomic.Int32
			var lastUpstreamReply atomic.Value
			tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
				calls.Add(1)
				// Keep RD set (errorResponse clears it), so the relayed
				// upstream reply is distinguishable from a synthesised one.
				r := withRcode(answer(q, 300, netip.MustParseAddr("1.2.3.4")), tt.rcode)
				binary.BigEndian.PutUint16(r[6:8], 0)
				r = r[:len(q)]
				lastUpstreamReply.Store(r)
				return r, nil
			})
			r := newResolver(t, Config{Transport: tr, Upstreams: []netip.AddrPort{cloudflare, google}})

			resp, _, err := r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if string(resp) != string(lastUpstreamReply.Load().([]byte)) {
				t.Errorf("response is not the upstream's own %s reply", tt.name)
			}
			if calls.Load() != 2 {
				t.Fatalf("%d upstream calls, want 2 (both upstreams tried)", calls.Load())
			}

			_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(2, "example.com", packet.QTypeA))
			if calls.Load() != 4 {
				t.Errorf("%d upstream calls after a repeat query, want 4: the %s reply was cached", calls.Load(), tt.name)
			}
		})
	}
}

// TestOnlyDefinitiveAnswersAreCached: a truncated reply returned because TCP
// was unavailable must not be pinned in the cache, and an NXDOMAIN must be.
func TestOnlyDefinitiveAnswersAreCached(t *testing.T) {
	tests := []struct {
		name       string
		reply      func(q []byte) []byte
		wantCached bool
	}{
		{"NOERROR", func(q []byte) []byte { return answer(q, 300, netip.MustParseAddr("1.2.3.4")) }, true},
		{"NXDOMAIN", func(q []byte) []byte { return withRcode(errorResponse(q, 0), rcodeNXDomain) }, true},
		{"truncated", truncatedAnswer, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
				calls.Add(1)
				return tt.reply(q), nil
			})
			r := newResolver(t, Config{Transport: tr})

			_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(1, "example.com", packet.QTypeA))
			_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(2, "example.com", packet.QTypeA))

			want := int32(2)
			if tt.wantCached {
				want = 1
			}
			if n := calls.Load(); n != want {
				t.Errorf("%d upstream calls for two identical queries, want %d", n, want)
			}
		})
	}
}

// TestUDPReplyFillingBufferTreatedAsTruncated: a datagram larger than the read
// buffer is cut off silently. Relaying (and caching) the cut-off bytes serves a
// corrupt message; it must be fetched over TCP instead.
func TestUDPReplyFillingBufferTreatedAsTruncated(t *testing.T) {
	big := func(q []byte) []byte {
		r := answer(q, 300, netip.MustParseAddr("1.2.3.4"))
		// Pad with additional-section bytes past the read buffer; ARCOUNT is
		// left at zero, so this is trailing data a parser ignores.
		return append(r, make([]byte, maxMessageSize+500-len(r))...)
	}

	tests := []struct {
		name    string
		tcp     bool
		wantLen int
		wantTC  bool
	}{
		{"TCP available", true, maxMessageSize + 500, false},
		{"TCP unavailable", false, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			tr := newTunnelTransport(func(_ netip.AddrPort, q []byte) ([]byte, error) {
				calls.Add(1)
				return big(q), nil
			})
			if tt.tcp {
				tr.onTCPQuery = func(_ netip.AddrPort, q []byte) ([]byte, error) { return big(q), nil }
			}
			r := newResolver(t, Config{Transport: tr})

			q := query(1, "example.com", packet.QTypeA)
			resp, _, err := r.HandleQuery(context.Background(), clientAddr, q)
			if err != nil {
				t.Fatalf("HandleQuery: %v", err)
			}
			if tr.tcpDials.Load() == 0 {
				t.Error("no TCP retry for a reply that filled the UDP buffer")
			}
			if tt.wantLen != 0 && len(resp) != tt.wantLen {
				t.Errorf("response is %d bytes, want the full %d from TCP", len(resp), tt.wantLen)
			}
			if isTruncated(resp) != tt.wantTC {
				t.Errorf("TC = %v, want %v", isTruncated(resp), tt.wantTC)
			}
			if !tt.tcp {
				_, _, _ = r.HandleQuery(context.Background(), clientAddr, query(2, "example.com", packet.QTypeA))
				if calls.Load() != 2 {
					t.Errorf("%d upstream calls, want 2: the cut-off reply was cached", calls.Load())
				}
			}
		})
	}
}

// --- TTLs ---

// rr appends a resource record whose owner is a pointer to the question name.
func rr(msg []byte, rtype uint16, ttl uint32, rdata []byte) []byte {
	msg = append(msg, 0xc0, 0x0c)
	msg = binary.BigEndian.AppendUint16(msg, rtype)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	return append(msg, rdata...)
}

// cnameChain is a response with a long-TTL CNAME in front of a short-TTL A
// record, plus an OPT record in the additional section.
func cnameChain(q []byte, cnameTTL, aTTL uint32) []byte {
	resp := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180)
	binary.BigEndian.PutUint16(resp[6:8], 2)   // ANCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 1) // ARCOUNT
	resp = rr(resp, packet.QTypeCNAME, cnameTTL, []byte{0xc0, 0x0c})
	resp = rr(resp, packet.QTypeA, aTTL, []byte{1, 2, 3, 4})
	// OPT: root name, type 41, class = UDP size, "TTL" = ext-rcode/flags
	// with the DO bit set, no rdata.
	resp = append(resp, 0)
	resp = binary.BigEndian.AppendUint16(resp, 41)
	resp = binary.BigEndian.AppendUint16(resp, 4096)
	resp = binary.BigEndian.AppendUint32(resp, 0x00008000)
	return binary.BigEndian.AppendUint16(resp, 0)
}

func TestResponseTTLUsesMinimumAcrossAnswers(t *testing.T) {
	q := query(1, "www.example.com", packet.QTypeA)
	tests := []struct {
		name string
		msg  []byte
		want time.Duration
	}{
		{"short A behind long CNAME", cnameChain(q, 3600, 60), 60 * time.Second},
		{"short CNAME before long A", cnameChain(q, 60, 3600), 60 * time.Second},
		{"negative TTL is zero", cnameChain(q, 3600, 0x80000000), 0},
		{"single answer", answer(q, 300, netip.MustParseAddr("1.2.3.4")), 300 * time.Second},
		{"no answers", q, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responseTTL(tt.msg); got != tt.want {
				t.Errorf("responseTTL = %s, want %s", got, tt.want)
			}
		})
	}
}

// answerTTLs reads the TTLs of the two answers and the OPT "TTL" of a
// cnameChain response.
func answerTTLs(t *testing.T, msg []byte) (cname, a, opt uint32) {
	t.Helper()
	offsets, answers := ttlOffsets(msg)
	if answers != 2 || len(offsets) != 2 {
		t.Fatalf("ttlOffsets = %v, %d; want two answer offsets", offsets, answers)
	}
	return binary.BigEndian.Uint32(msg[offsets[0]:]), binary.BigEndian.Uint32(msg[offsets[1]:]),
		binary.BigEndian.Uint32(msg[len(msg)-6:])
}

// TestCachedTTLsAreAged: an answer served from the cache must not advertise
// its original TTL, or a downstream cache holds it for that long again on top
// of the time it already spent here.
func TestCachedTTLsAreAged(t *testing.T) {
	q := query(1, "www.example.com", packet.QTypeA)
	tests := []struct {
		name             string
		floor, ceiling   time.Duration
		cnameTTL, aTTL   uint32
		after            time.Duration
		wantCNAME, wantA uint32
	}{
		{"decremented by elapsed time", time.Second, time.Hour, 300, 300, 100 * time.Second, 200, 200},
		// The floor keeps the entry for 30s; each record still ages from its
		// own TTL rather than being stretched to the entry's lifetime.
		{"each record aged from its own TTL", 30 * time.Second, time.Hour, 10, 1, 5 * time.Second, 5, 0},
		{"clamped to remaining lifetime under the ceiling", time.Second, time.Minute, 86400, 3600, 10 * time.Second, 50, 50},
		{"never below zero when the floor outlives the TTL", 30 * time.Second, time.Hour, 3600, 1, 10 * time.Second, 20, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(tt.floor, tt.ceiling)
			start := time.Unix(1_700_000_000, 0)
			c.now = func() time.Time { return start }
			c.put("www.example.com", packet.QTypeA, cnameChain(q, tt.cnameTTL, tt.aTTL))

			c.now = func() time.Time { return start.Add(tt.after) }
			got, ok := c.get("www.example.com", packet.QTypeA)
			if !ok {
				t.Fatal("entry missing")
			}
			cname, a, opt := answerTTLs(t, got)
			if cname != tt.wantCNAME || a != tt.wantA {
				t.Errorf("served TTLs = CNAME %d, A %d; want %d, %d", cname, a, tt.wantCNAME, tt.wantA)
			}
			if opt != 0x00008000 {
				t.Errorf("OPT ext-rcode/flags = %#x, want 0x8000: the additional section was rewritten", opt)
			}

			// The stored copy is untouched, so the next hit ages from the
			// original values rather than compounding.
			again, _ := c.get("www.example.com", packet.QTypeA)
			if c2, a2, _ := answerTTLs(t, again); c2 != cname || a2 != a {
				t.Errorf("second hit TTLs = %d, %d; want %d, %d", c2, a2, cname, a)
			}
		})
	}
}
