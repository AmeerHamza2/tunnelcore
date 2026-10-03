// Package dnsproxy answers DNS queries from inside the tunnel.
//
// This package exists because of the most common and most damaging defect in
// consumer VPNs: the DNS leak. The tunnel carries the user's traffic, the UI
// says "connected", and meanwhile every name the user looks up is still being
// resolved by the resolver their ISP or their café's router handed them over
// DHCP. The payload is encrypted and the metadata — every site visited, in
// order, with timestamps — is going to exactly the party the user installed a
// VPN to hide from. It is worse than no VPN in one specific way: the user
// believes they are protected.
//
// The fix is structural rather than careful. The tunnel advertises a resolver
// address that exists only inside the tunnel, the userspace stack hands every
// flow bound for port 53 to this package, and this package resolves the name
// over the transport. There is no code path from a DNS query to a local
// socket, so there is nothing to get wrong on a reconnect, nothing to race
// during the window where the tunnel is coming up, and nothing for a
// misconfigured route to bypass. TestNoQueryEscapesTheTunnel asserts exactly
// that: the resolver handed a direct dialer fails the test.
//
// What this package deliberately does not do is parse DNS responses' records.
// It reads the question — of the query, to apply policy and to key the cache,
// and of each reply, to check that the reply answers what was asked — and the
// fixed record headers the cache needs for TTLs, and otherwise treats the
// response as opaque bytes to be relayed. Response parsing means walking
// compression pointers through attacker-controlled data, which is where DNS
// libraries grow their CVEs; not doing it removes the whole class.
package dnsproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
)

// Errors returned by this package.
var (
	ErrNoUpstreams   = errors.New("dnsproxy: no upstream resolvers configured")
	ErrNoTransport   = errors.New("dnsproxy: no transport configured")
	ErrQueryTooLarge = errors.New("dnsproxy: query larger than the maximum DNS message size")
	ErrAllUpstreams  = errors.New("dnsproxy: every upstream failed")
	ErrClosed        = errors.New("dnsproxy: closed")

	// ErrMismatchedReply means an upstream reply did not answer the question
	// that was asked: wrong transaction ID, QR clear, or a different
	// name/type/class. Such replies are discarded, never relayed or cached.
	ErrMismatchedReply = errors.New("dnsproxy: upstream reply does not match the query")

	// ErrUpstreamRcode means an upstream answered SERVFAIL or REFUSED. That
	// is a statement about the upstream, not about the name, so the next
	// upstream is tried.
	ErrUpstreamRcode = errors.New("dnsproxy: upstream answered SERVFAIL or REFUSED")
)

const (
	// maxMessageSize bounds a DNS message. 4096 is the common EDNS0 advertised
	// size; anything larger is either a misbehaving client or an attempt to
	// make the proxy allocate.
	maxMessageSize = 4096

	// maxTCPMessageSize bounds a reply read over TCP, which is the largest
	// length the two-byte framing can declare. It is larger than
	// maxMessageSize because TCP is exactly where an answer that did not fit
	// in a UDP read is fetched from; capping it at the UDP size would make
	// the fallback fail for the only replies that need it.
	maxTCPMessageSize = 65535

	// DefaultQueryTimeout bounds one upstream query.
	//
	// Two seconds is deliberately short. A stub resolver on a phone retries
	// after about five, so an upstream that has not answered in two is not
	// going to be useful before the client has already given up — failing
	// fast and trying the next upstream beats waiting.
	DefaultQueryTimeout = 2 * time.Second

	// DefaultCacheTTLFloor and DefaultCacheTTLCeiling clamp how long an answer
	// is cached, regardless of what the record says.
	//
	// The floor exists because a one-second TTL from a CDN would make the
	// cache useless on a link where the round trip is the expensive part. The
	// ceiling exists because a record with a one-week TTL pins a stale answer
	// across the user changing networks, countries and exit nodes.
	DefaultCacheTTLFloor   = 30 * time.Second
	DefaultCacheTTLCeiling = 10 * time.Minute

	// maxCacheEntries bounds the cache. A phone resolving aggressively can
	// otherwise grow this without limit; eviction is approximate (see
	// cache.put) because an exact LRU costs a list and a lock upgrade for no
	// benefit at this size.
	maxCacheEntries = 2048

	// maxCacheBytes bounds the cache's memory, which maxCacheEntries alone
	// does not: see cache.evictLocked. 2 MiB holds the full 2048 entries at
	// a typical answer size of well under 1 KiB.
	maxCacheBytes = 2 << 20
)

// Transport is what the proxy resolves over. It is satisfied by
// transport.StreamDialer, but declared narrowly here so this package does not
// depend on the whole transport interface — and so a test can supply a dialer
// that is *only* able to reach a loopback resolver.
type Transport interface {
	// DialUDP opens a proxied UDP association to an upstream resolver.
	DialUDP(ctx context.Context, dst netip.AddrPort) (UDPSession, error)
	// DialTCP opens a proxied TCP connection, used when a response is
	// truncated and must be retried over TCP.
	DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

// UDPSession is one proxied UDP association.
type UDPSession interface {
	WriteTo(b []byte, dst netip.AddrPort) (int, error)
	ReadFrom(b []byte) (int, netip.AddrPort, error)
	Close() error
}

// Policy decides what happens to a name before it is resolved.
type Policy interface {
	// Allow reports whether name may be resolved. Returning false causes the
	// proxy to answer NXDOMAIN rather than dropping the query, because a
	// dropped query makes an app hang on a retry loop while an answered one
	// fails immediately and visibly.
	Allow(name string, qtype uint16) bool
}

// Config configures a Resolver.
type Config struct {
	// Transport carries queries to the upstream resolvers.
	Transport Transport

	// Upstreams are the resolver addresses, tried in order. These are
	// reachable only through Transport, never directly.
	Upstreams []netip.AddrPort

	// QueryTimeout bounds one upstream attempt. Zero selects
	// DefaultQueryTimeout.
	QueryTimeout time.Duration

	// Policy, if non-nil, filters names before resolution.
	Policy Policy

	// CacheTTLFloor and CacheTTLCeiling clamp cached answers. Zero selects
	// the defaults.
	CacheTTLFloor   time.Duration
	CacheTTLCeiling time.Duration

	// DisableCache turns caching off, which the harness CLI does so that
	// every query is observable.
	DisableCache bool

	// OnQuery, if non-nil, is called for each query with the outcome. It must
	// not block, and it is handed only the name and qtype — never the client
	// address, so that a metrics hook cannot be turned into a per-user
	// browsing log.
	OnQuery func(name string, qtype uint16, blocked bool, cached bool, err error)
}

// Resolver answers DNS queries over a transport.
type Resolver struct {
	cfg   Config
	cache *cache

	mu     sync.RWMutex
	closed bool

	// upstreamHealth tracks consecutive failures per upstream so a dead
	// resolver is skipped rather than retried first every time.
	upstreamFailures []int
}

// New builds a Resolver.
func New(cfg Config) (*Resolver, error) {
	if cfg.Transport == nil {
		return nil, ErrNoTransport
	}
	if len(cfg.Upstreams) == 0 {
		return nil, ErrNoUpstreams
	}
	for _, u := range cfg.Upstreams {
		if !u.IsValid() || u.Port() == 0 {
			return nil, fmt.Errorf("dnsproxy: invalid upstream %q", u)
		}
	}

	r := &Resolver{
		cfg:              cfg,
		upstreamFailures: make([]int, len(cfg.Upstreams)),
	}
	if !cfg.DisableCache {
		r.cache = newCache(r.ttlFloor(), r.ttlCeiling())
	}
	return r, nil
}

func (r *Resolver) queryTimeout() time.Duration {
	if r.cfg.QueryTimeout <= 0 {
		return DefaultQueryTimeout
	}
	return r.cfg.QueryTimeout
}

func (r *Resolver) ttlFloor() time.Duration {
	if r.cfg.CacheTTLFloor <= 0 {
		return DefaultCacheTTLFloor
	}
	return r.cfg.CacheTTLFloor
}

func (r *Resolver) ttlCeiling() time.Duration {
	if r.cfg.CacheTTLCeiling <= 0 {
		return DefaultCacheTTLCeiling
	}
	return r.cfg.CacheTTLCeiling
}

// HandleQuery implements netstack.DNSHandler.
//
// The client address is accepted because the interface supplies it, and is
// then deliberately unused beyond this function: it is not logged, not cached
// against, and not passed to OnQuery. On a multi-app device the client port is
// the closest thing to a per-app identifier the engine ever sees, and a
// privacy product has no business retaining it.
func (r *Resolver) HandleQuery(ctx context.Context, _ netip.AddrPort, query []byte) ([]byte, bool, error) {
	r.mu.RLock()
	closed := r.closed
	r.mu.RUnlock()
	if closed {
		return nil, true, ErrClosed
	}

	if len(query) > maxMessageSize {
		return nil, true, fmt.Errorf("%w: %d bytes", ErrQueryTooLarge, len(query))
	}

	q, err := packet.ParseDNSQuestion(query)
	if err != nil {
		// An unparseable query gets FORMERR rather than a drop. A drop makes
		// the stub resolver wait out its full timeout on every retry; an
		// error tells it immediately that the message was the problem.
		return formerr(query), true, nil
	}

	if r.cfg.Policy != nil && !r.cfg.Policy.Allow(q.Name, q.QType) {
		r.report(q.Name, q.QType, true, false, nil)
		return nxdomain(query), true, nil
	}

	// The cache key has no class, so only IN is cached: a CHAOS query for
	// a name must not be able to seed the answer served to IN queries.
	useCache := r.cache != nil && q.Class == classIN

	if useCache {
		if resp, ok := r.cache.get(q.Name, q.QType); ok {
			// The cached response was stored under a different transaction
			// ID; rewrite it to match this query or the stub resolver
			// discards it as unsolicited. get returns a fresh copy, so this
			// does not touch the stored entry.
			if len(resp) >= 2 {
				binary.BigEndian.PutUint16(resp[0:2], q.ID)
			}
			r.report(q.Name, q.QType, false, true, nil)
			return resp, true, nil
		}
	}

	resp, err := r.resolve(ctx, query, q)
	if err != nil {
		r.report(q.Name, q.QType, false, false, err)
		if resp != nil {
			// Every upstream answered SERVFAIL/REFUSED. Relay the last of
			// those answers rather than synthesising one: it is a genuine
			// reply and may carry extended error information.
			return resp, true, nil
		}
		// SERVFAIL rather than a dropped query, for the same reason as
		// FORMERR above.
		return servfail(query), true, nil
	}

	if useCache && cacheable(resp) {
		r.cache.put(q.Name, q.QType, resp)
	}
	r.report(q.Name, q.QType, false, false, nil)
	return resp, true, nil
}

func (r *Resolver) report(name string, qtype uint16, blocked, cached bool, err error) {
	if r.cfg.OnQuery != nil {
		r.cfg.OnQuery(name, qtype, blocked, cached, err)
	}
}

// resolve sends the query to each upstream in turn, healthiest first.
//
// On failure it may still return a response: if any upstream answered
// SERVFAIL or REFUSED, the last such answer is returned alongside the error so
// the client gets a real reply.
func (r *Resolver) resolve(ctx context.Context, query []byte, q packet.DNSQuestion) ([]byte, error) {
	order := r.upstreamOrder()
	var (
		lastErr  error
		lastResp []byte
	)

	for _, idx := range order {
		upstream := r.cfg.Upstreams[idx]
		attemptCtx, cancel := context.WithTimeout(ctx, r.queryTimeout())
		resp, err := r.queryUpstream(attemptCtx, upstream, query, q)
		cancel()

		if err == nil {
			// SERVFAIL and REFUSED describe the upstream (lame, broken
			// DNSSEC chain, ACL), not the name, so another upstream may
			// well answer. Treating them as success would also hand them to
			// the cache, pinning a transient failure for the TTL floor.
			if rc := rcode(resp); rc == rcodeServFail || rc == rcodeRefused {
				err = fmt.Errorf("%w: %s answered rcode %d", ErrUpstreamRcode, upstream, rc)
				lastResp = resp
			}
		}
		if err == nil {
			r.recordUpstream(idx, true)
			return resp, nil
		}
		r.recordUpstream(idx, false)
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrAllUpstreams
	}
	return lastResp, fmt.Errorf("%w: %w", ErrAllUpstreams, lastErr)
}

// queryUpstream performs one UDP query through the transport, falling back to
// TCP if the answer is truncated.
//
// Replies that do not answer q are discarded and reading continues until the
// attempt's deadline. Accepting the first datagram instead lets anyone who can
// get a packet onto the association — an exit node's neighbour, a NAT that
// reused the port — answer for any name: the forged reply would be cached
// under the query's name, and the cache-hit path's ID rewrite would then make
// it look valid to every later client.
func (r *Resolver) queryUpstream(ctx context.Context, upstream netip.AddrPort, query []byte, q packet.DNSQuestion) ([]byte, error) {
	session, err := r.cfg.Transport.DialUDP(ctx, upstream)
	if err != nil {
		return nil, fmt.Errorf("dialing %s through the tunnel: %w", upstream, err)
	}
	defer session.Close()

	if _, err := session.WriteTo(query, upstream); err != nil {
		return nil, fmt.Errorf("sending query to %s: %w", upstream, err)
	}

	type readResult struct {
		b   []byte
		err error
	}
	results := make(chan readResult)
	// done is closed before the session (defers run in reverse), so the
	// reader either delivers or exits; the Close then unblocks its ReadFrom.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			buf := make([]byte, maxMessageSize)
			n, _, err := session.ReadFrom(buf)
			select {
			case results <- readResult{b: buf[:n], err: err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	discarded := 0
	for {
		select {
		case <-ctx.Done():
			if discarded > 0 {
				return nil, fmt.Errorf("%w: %d from %s: %w", ErrMismatchedReply, discarded, upstream, ctx.Err())
			}
			return nil, ctx.Err()
		case res := <-results:
			if res.err != nil {
				return nil, fmt.Errorf("reading reply from %s: %w", upstream, res.err)
			}
			if !answersQuestion(res.b, q) {
				discarded++
				continue
			}
			resp := res.b

			// A reply that filled the read buffer may have been cut short
			// by it — the datagram was larger than we read — so it is
			// handled exactly like one with TC set.
			overflowed := len(resp) >= maxMessageSize

			// A truncated answer must be retried over TCP. Returning the
			// truncated message instead is a subtle and infuriating bug
			// class: most names fit in 512 bytes and work fine, so it only
			// breaks the domains with many records — which tend to be the
			// large sites.
			if overflowed || isTruncated(resp) {
				if tcpResp, terr := r.queryUpstreamTCP(ctx, upstream, query, q); terr == nil {
					return tcpResp, nil
				}
				if overflowed {
					// The bytes past the buffer are gone, so the message
					// cannot be relayed as-is. A header-and-question reply
					// with TC set tells the stub to retry over TCP itself.
					return truncatedResponse(query), nil
				}
				// If TCP also fails, the truncated UDP answer is still
				// better than nothing: a stub resolver can use the records
				// it contains. It is not cached (see cacheable).
			}
			return resp, nil
		}
	}
}

// queryUpstreamTCP retries a query over proxied TCP, which DNS frames with a
// two-byte big-endian length prefix.
func (r *Resolver) queryUpstreamTCP(ctx context.Context, upstream netip.AddrPort, query []byte, q packet.DNSQuestion) ([]byte, error) {
	conn, err := r.cfg.Transport.DialTCP(ctx, upstream)
	if err != nil {
		return nil, fmt.Errorf("dialing %s over TCP through the tunnel: %w", upstream, err)
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, fmt.Errorf("sending TCP query to %s: %w", upstream, err)
	}

	var lenBuf [2]byte
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("reading TCP reply length from %s: %w", upstream, err)
	}
	size := int(binary.BigEndian.Uint16(lenBuf[:]))
	if size == 0 || size > maxTCPMessageSize {
		return nil, fmt.Errorf("dnsproxy: %s declared a %d-byte TCP reply", upstream, size)
	}
	resp := make([]byte, size)
	if _, err := readFull(conn, resp); err != nil {
		return nil, fmt.Errorf("reading TCP reply from %s: %w", upstream, err)
	}
	// TCP is harder to spoof than UDP but not immune (the stream ends at the
	// exit node, not at the resolver), and a validation that only one path
	// applies is one an attacker simply routes around by forcing TC=1.
	if !answersQuestion(resp, q) {
		return nil, fmt.Errorf("%w: TCP reply from %s", ErrMismatchedReply, upstream)
	}
	return resp, nil
}

// answersQuestion reports whether resp is a response to the query q: same
// transaction ID, QR set, and a first question with the same name, type and
// class.
//
// The name comparison is on packet.ParseDNSQuestion's normalised form, so it
// is case-insensitive (a resolver may echo 0x20-randomised case) and
// distinguishes a dot inside a label from a label boundary. Only the question
// is parsed, consistent with this package never walking answer records it
// relays.
func answersQuestion(resp []byte, q packet.DNSQuestion) bool {
	rq, err := packet.ParseDNSQuestion(resp)
	if err != nil {
		return false
	}
	return rq.Response &&
		rq.ID == q.ID &&
		rq.Name == q.Name &&
		rq.QType == q.QType &&
		rq.Class == q.Class
}

// cacheable reports whether a relayed response may be stored.
//
// Only definitive answers are: NOERROR and NXDOMAIN, complete (TC clear).
// Anything else is either a failure that the next query should retry rather
// than be served for the TTL floor, or a partial answer whose missing records
// a cached copy would silently withhold from every later client.
func cacheable(resp []byte) bool {
	if len(resp) < 12 || isTruncated(resp) {
		return false
	}
	rc := rcode(resp)
	return rc == rcodeNoError || rc == rcodeNXDomain
}

func readFull(conn net.Conn, b []byte) (int, error) {
	read := 0
	for read < len(b) {
		n, err := conn.Read(b[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// upstreamOrder returns upstream indices sorted by consecutive failures, so a
// resolver that has stopped answering drops to the back instead of costing
// every query a full timeout.
func (r *Resolver) upstreamOrder() []int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	order := make([]int, len(r.cfg.Upstreams))
	for i := range order {
		order[i] = i
	}
	// Insertion sort: the slice has two or three elements in practice, and a
	// stable sort keeps the configured order as the tiebreak.
	for i := 1; i < len(order); i++ {
		for j := i; j > 0 && r.upstreamFailures[order[j]] < r.upstreamFailures[order[j-1]]; j-- {
			order[j], order[j-1] = order[j-1], order[j]
		}
	}
	return order
}

// maxRecordedFailures caps the failure counter so an upstream that was down
// for an hour is not permanently demoted once it recovers.
const maxRecordedFailures = 5

func (r *Resolver) recordUpstream(idx int, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		r.upstreamFailures[idx] = 0
		return
	}
	if r.upstreamFailures[idx] < maxRecordedFailures {
		r.upstreamFailures[idx]++
	}
}

// Close releases the resolver. In-flight queries finish; new ones fail.
func (r *Resolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	if r.cache != nil {
		r.cache.clear()
	}
	return nil
}

// --- response synthesis ---

// DNS header flag bits and response codes.
const (
	flagResponse    = 0x8000
	flagRecursionOK = 0x0080

	flagTruncated = 0x0200

	rcodeNoError  = 0
	rcodeFormErr  = 1
	rcodeServFail = 2
	rcodeNXDomain = 3
	rcodeRefused  = 5

	classIN = 1
)

// rcode returns the header's response code, or rcodeFormErr for a message too
// short to have one.
func rcode(msg []byte) uint16 {
	if len(msg) < 4 {
		return rcodeFormErr
	}
	return binary.BigEndian.Uint16(msg[2:4]) & 0x000f
}

// isTruncated reports whether the TC bit is set.
func isTruncated(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}
	return binary.BigEndian.Uint16(msg[2:4])&flagTruncated != 0
}

// errorResponse turns a query into a response with the given rcode, echoing
// the question section so the stub resolver accepts it.
func errorResponse(query []byte, rcode uint16) []byte {
	if len(query) < 12 {
		// Too short to echo anything meaningful; a bare header is still a
		// valid response and better than a drop.
		resp := make([]byte, 12)
		binary.BigEndian.PutUint16(resp[2:4], flagResponse|rcode)
		return resp
	}

	resp := append([]byte(nil), query...)
	flags := binary.BigEndian.Uint16(resp[2:4])
	// Preserve the opcode and RD bit, set QR and the rcode, clear everything
	// else. Echoing the opcode matters: a client that sent an inverse query
	// and gets a standard-query response back treats it as malformed.
	flags = (flags & 0x7800) | flagResponse | flagRecursionOK | rcode
	binary.BigEndian.PutUint16(resp[2:4], flags)

	// No answers, authority or additional records.
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}

func nxdomain(query []byte) []byte { return errorResponse(query, rcodeNXDomain) }
func servfail(query []byte) []byte { return errorResponse(query, rcodeServFail) }
func formerr(query []byte) []byte  { return errorResponse(query, rcodeFormErr) }

// truncatedResponse is a NOERROR reply with TC set and no records, which
// tells a stub resolver to retry the query over TCP.
func truncatedResponse(query []byte) []byte {
	resp := errorResponse(query, rcodeNoError)
	binary.BigEndian.PutUint16(resp[2:4], binary.BigEndian.Uint16(resp[2:4])|flagTruncated)
	return resp
}
