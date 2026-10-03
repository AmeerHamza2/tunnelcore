package netstack

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	tcpproto "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	udpproto "gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/ameerhamza2/tunnelcore/transport"
)

// installForwarders registers the TCP and UDP handlers that turn flows
// addressed to arbitrary destinations into proxied connections.
func (ns *Stack) installForwarders() {
	tcpFwd := tcpproto.NewForwarder(ns.s, tcpRcvWnd, ns.cfg.tcpMaxInFlight, ns.handleTCP)
	ns.s.SetTransportProtocolHandler(tcpproto.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udpproto.NewForwarder(ns.s, ns.handleUDP)
	ns.s.SetTransportProtocolHandler(udpproto.ProtocolNumber, udpFwd.HandlePacket)
}

// acquireSlot takes one slot against limit, or reports false if none is free.
func acquireSlot(n *atomic.Int64, limit int) bool {
	if n.Add(1) > int64(limit) {
		n.Add(-1)
		return false
	}
	return true
}

// handleTCP accepts one inbound TCP connection and proxies it.
//
// The ordering here is the part that matters. The proxied connection is dialed
// *before* the inner endpoint is created, so that a destination which refuses
// the connection produces a TCP reset back to the application rather than a
// completed handshake followed by an immediate close. An app can distinguish
// "connection refused" from "connection closed by peer" and behaves very
// differently in each case; getting this backwards makes a VPN that reports
// every dead host as a successful connection, and breaks every client that
// relies on a prompt refusal to fail over.
//
// The request is completed as soon as the handshake is done, not when the
// flow ends: gVisor counts a request against tcpMaxInFlight until Complete,
// and silently drops SYNs beyond it. Holding it for the life of the flow
// turns a half-open limit into a limit on established connections that
// presents as random connections hanging forever. The bound on established
// flows is MaxTCPFlows instead, which resets.
//
// TCP to port 53 is answered by the DNS handler when one is configured; see
// handleTCPDNS.
func (ns *Stack) handleTCP(req *tcpproto.ForwarderRequest) {
	id := req.ID()
	dst := addrPortFrom(id)
	client := clientAddrPort(id)

	// gVisor's forwarder already runs each request on its own goroutine, so
	// the flow runs here rather than on yet another one.
	if !ns.enter() {
		req.Complete(true) // closing: reset rather than leave the SYN pending
		return
	}
	func() {
		defer ns.wg.Done()

		// The slot is taken before the dial so that the cap bounds dialing
		// work as well as established flows.
		if !acquireSlot(&ns.tcpFlows, ns.cfg.MaxTCPFlows) {
			ns.rejectedFlows.Add(1)
			// Reset rather than drop: a reset makes the app back off, a drop
			// makes it retransmit the SYN into the same full table.
			req.Complete(true)
			ns.emit(FlowEvent{Proto: "tcp", Dst: dst, Err: ErrTooManyFlows})
			return
		}
		defer ns.tcpFlows.Add(-1)

		if dst.Port() == 53 && ns.cfg.DNS != nil {
			ns.handleTCPDNS(req, client, dst)
			return
		}

		ctx, cancel := context.WithTimeout(ns.ctx, dialTimeout)
		defer cancel()

		start := time.Now()
		outbound, err := ns.cfg.Dialer.DialTCP(ctx, dst)
		dialLatency := time.Since(start)
		if err != nil {
			ns.failedDials.Add(1)
			// sendReset true: tell the app the destination is unreachable.
			req.Complete(true)
			ns.emit(FlowEvent{
				Proto: "tcp", Dst: dst, DialLatency: dialLatency, Err: err,
			})
			return
		}

		wq := newWaiterQueue()
		ep, tcpipErr := req.CreateEndpoint(wq)
		if tcpipErr != nil {
			_ = outbound.Close()
			req.Complete(true)
			ns.emit(FlowEvent{
				Proto: "tcp", Dst: dst, DialLatency: dialLatency,
				Err: errors.New("netstack: creating inner endpoint: " + tcpipErr.String()),
			})
			return
		}
		// Complete must be called exactly once per request. sendReset is
		// false because the handshake succeeded; the endpoint now owns the
		// connection, and from here on the forwarder has nothing to track.
		req.Complete(false)

		ns.runTCPFlow(gonet.NewTCPConn(wq, ep), outbound, dst, dialLatency, 0)
	}()
}

// runTCPFlow splices an established flow and reports it. preUp is the number
// of upstream bytes already written to outbound before the splice started.
func (ns *Stack) runTCPFlow(inbound, outbound gonetConn, dst netip.AddrPort, dialLatency time.Duration, preUp int64) {
	ns.totalFlows.Add(1)
	ns.activeFlows.Add(1)
	up, down := ns.splice(inbound, outbound)
	ns.activeFlows.Add(-1)
	ns.emit(FlowEvent{
		Proto: "tcp", Dst: dst, DialLatency: dialLatency,
		BytesUp: preUp + up, BytesDown: down,
	})
}

// DNS-over-TCP limits.
const (
	// maxTCPDNSQuery bounds one query message. The two-byte length prefix
	// allows 64KiB, but a query is a header and one question; anything near
	// that size is an attempt to make the stack allocate. It matches the
	// dnsproxy limit, which would reject a larger query anyway.
	maxTCPDNSQuery = 4096

	// maxTCPDNSQueries bounds how many queries one connection may carry, so
	// a single client cannot pin a flow slot and a goroutine indefinitely.
	// RFC 7766 lets a server close an idle or busy connection at any time;
	// stub resolvers simply reconnect.
	maxTCPDNSQueries = 64
)

// dnsTCPIdleTimeout is how long a DNS-over-TCP connection may sit between
// messages, and also the most one message may take to arrive. RFC 7766
// suggests seconds rather than minutes; a stub resolver that fell back to TCP
// after a truncated UDP answer sends its query immediately.
const dnsTCPIdleTimeout = 10 * time.Second

// handleTCPDNS serves DNS over TCP through the DNS handler.
//
// This exists because a stub resolver that gets a truncated (TC=1) UDP answer
// retries the same query over TCP to the same address. Without this, that
// retry is proxied to the configured resolver address — which typically only
// exists inside the tunnel, so the lookup fails — and, worse, any lookup that
// does go out bypasses the DNS policy and cache entirely.
//
// Interception is by port, to any destination, for the same reason and with
// the same semantics as the UDP/53 path in handleUDP: the handler sees every
// DNS flow and declines the ones it does not want. A decline on the first
// query falls back to proxying the connection unchanged.
//
// Unlike ordinary flows the handshake is completed before anything is
// dialed, because the common case dials nothing at all.
func (ns *Stack) handleTCPDNS(req *tcpproto.ForwarderRequest, client, dst netip.AddrPort) {
	wq := newWaiterQueue()
	ep, tcpipErr := req.CreateEndpoint(wq)
	if tcpipErr != nil {
		req.Complete(true)
		ns.emit(FlowEvent{
			Proto: "dns", Dst: dst,
			Err: errors.New("netstack: creating inner endpoint: " + tcpipErr.String()),
		})
		return
	}
	req.Complete(false)

	conn := gonet.NewTCPConn(wq, ep)
	defer conn.Close()
	// Close must not wait out a read deadline, so tear the connection down
	// as soon as the stack shuts down.
	stop := context.AfterFunc(ns.ctx, func() { _ = conn.Close() })
	defer stop()

	pending, declined := ns.serveTCPDNS(conn, client, dst)
	if !declined {
		return
	}

	ctx, cancel := context.WithTimeout(ns.ctx, dialTimeout)
	start := time.Now()
	outbound, err := ns.cfg.Dialer.DialTCP(ctx, dst)
	cancel()
	dialLatency := time.Since(start)
	if err != nil {
		ns.failedDials.Add(1)
		ns.emit(FlowEvent{Proto: "tcp", Dst: dst, DialLatency: dialLatency, Err: err})
		return
	}
	// The first message was consumed to offer it to the handler; replay it
	// before splicing so the upstream sees the stream exactly as sent.
	if _, err := outbound.Write(pending); err != nil {
		_ = outbound.Close()
		ns.emit(FlowEvent{Proto: "tcp", Dst: dst, DialLatency: dialLatency, Err: err})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	ns.runTCPFlow(conn, outbound, dst, dialLatency, int64(len(pending)))
}

// serveTCPDNS answers RFC 1035 length-prefixed DNS messages on conn until the
// client closes, goes idle, misbehaves or reaches maxTCPDNSQueries.
//
// If the handler declines the first query, it returns that message, still
// framed, with declined true so the caller can proxy the connection instead.
// A decline after a query has been answered locally ends the connection, for
// the same stay-local reason as in serveDNS.
func (ns *Stack) serveTCPDNS(conn gonetConn, client, dst netip.AddrPort) (pending []byte, declined bool) {
	var hdr [2]byte
	msg := make([]byte, maxTCPDNSQuery)
	idle := ns.cfg.dnsTCPIdleTimeout

	for i := 0; i < maxTCPDNSQueries; i++ {
		// One deadline covers the whole message, so a client dribbling a
		// byte at a time cannot keep the connection alive past it.
		if err := conn.SetReadDeadline(time.Now().Add(idle)); err != nil {
			return nil, false
		}
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return nil, false
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if n == 0 || n > maxTCPDNSQuery {
			// There is no way to resynchronise a length-prefixed stream
			// after a bad length, so the only safe answer is to close.
			ns.emit(FlowEvent{Proto: "dns", Dst: dst,
				Err: fmt.Errorf("netstack: DNS-over-TCP message length %d out of range", n)})
			return nil, false
		}
		if _, err := io.ReadFull(conn, msg[:n]); err != nil {
			return nil, false
		}

		resp, handled, err := ns.cfg.DNS.HandleQuery(ns.ctx, client, msg[:n])
		if err != nil {
			ns.emit(FlowEvent{Proto: "dns", Dst: dst, Err: err})
			return nil, false
		}
		if !handled {
			if i == 0 {
				return append(hdr[:], msg[:n]...), true
			}
			return nil, false
		}
		if resp == nil {
			continue // intentional silent drop, e.g. a blocked name
		}
		if len(resp) > 0xffff {
			return nil, false // cannot be framed; nothing sensible to send
		}
		// One write for prefix and body, so the two never go out as
		// separate segments; some resolvers mishandle a split prefix.
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if err := conn.SetWriteDeadline(time.Now().Add(idle)); err != nil {
			return nil, false
		}
		if _, err := conn.Write(out); err != nil {
			return nil, false
		}
	}
	return nil, false
}

// splice copies in both directions until either side finishes, and returns the
// byte counts.
//
// The half-close handling is the subtle part. When the app finishes sending
// (FIN), we must propagate that as a close of the *write* half of the outbound
// connection and keep reading the response, because that is exactly the shape
// of an HTTP/1.1 request with no keep-alive, and of every protocol that
// signals end-of-request by closing. Closing both halves instead truncates the
// response, which presents as "large downloads sometimes end early".
func (ns *Stack) splice(inbound, outbound gonetConn) (up, down int64) {
	var (
		wg       sync.WaitGroup
		upCount  atomic.Int64
		dnCount  atomic.Int64
		closeOne sync.Once
	)

	// Cancellation: if the stack closes, tear both sides down so the copies
	// return instead of leaking until a TCP timeout.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ns.ctx.Done():
			closeOne.Do(func() {
				_ = inbound.Close()
				_ = outbound.Close()
			})
		case <-done:
		}
	}()

	closeBoth := func() {
		closeOne.Do(func() {
			_ = inbound.Close()
			_ = outbound.Close()
		})
	}

	// A direction that ends cleanly (EOF: the sender closed its write half)
	// is propagated as a half-close. One that ends in an error — a reset from
	// either end, a write into a dead peer — tears the whole flow down, which
	// is what a kernel does with a RST. Half-closing on an error instead left
	// the other direction waiting on a peer that had no reason to ever close:
	// an app killed mid-connection, or a server that ignores EOF on a long
	// poll, pinned two goroutines, 64 KiB of buffers and a flow slot until the
	// remote end happened to time out — on a phone, effectively forever.
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, err := copyBuffered(outbound, inbound)
		upCount.Store(n)
		if err != nil {
			closeBoth()
			return
		}
		halfClose(outbound)
	}()
	go func() {
		defer wg.Done()
		n, err := copyBuffered(inbound, outbound)
		dnCount.Store(n)
		if err != nil {
			closeBoth()
			return
		}
		halfClose(inbound)
	}()
	wg.Wait()

	closeBoth()
	return upCount.Load(), dnCount.Load()
}

// halfCloser is implemented by both net.TCPConn and gonet.TCPConn.
type halfCloser interface{ CloseWrite() error }

// halfClose signals end-of-stream in one direction only.
//
// If the connection cannot be half-closed, this does nothing, and the
// connection is torn down later by the caller once both directions have
// finished. That is the lesser of two bad options: a full Close here would
// also kill the direction that is still carrying the response, truncating it —
// which is the exact defect this function exists to avoid, and which presents
// as "large downloads sometimes end early".
//
// Transports are required to return half-closable connections; see the
// contract on transport.StreamDialer.DialTCP. Every in-tree transport returns
// a *net.TCPConn, which satisfies it.
func halfClose(c gonetConn) {
	if hc, ok := c.(halfCloser); ok {
		_ = hc.CloseWrite()
	}
}

// copyBuffered is io.Copy with a fixed buffer, avoiding io.Copy's per-call
// allocation on a path that runs once per direction per flow.
func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, spliceBufSize)
	return io.CopyBuffer(dst, src, buf)
}

// handleUDP proxies one UDP flow.
//
// UDP has no connection, so "a flow" here is a local 5-tuple with an idle
// timeout. The DNS interception hook is checked first: queries answered inside
// the tunnel never reach the transport at all.
func (ns *Stack) handleUDP(req *udpproto.ForwarderRequest) {
	id := req.ID()
	dst := addrPortFrom(id)
	client := clientAddrPort(id)

	// Registered before the endpoint exists, so a stack that is closing
	// creates nothing it would then have to tear down.
	if !ns.enter() {
		return
	}

	wq := newWaiterQueue()
	ep, tcpipErr := req.CreateEndpoint(wq)
	if tcpipErr != nil {
		ns.wg.Done()
		ns.failedDials.Add(1)
		ns.emit(FlowEvent{
			Proto: "udp", Dst: dst,
			Err: errors.New("netstack: creating inner UDP endpoint: " + tcpipErr.String()),
		})
		return
	}
	inbound := gonet.NewUDPConn(wq, ep)

	go func() {
		defer ns.wg.Done()
		defer inbound.Close()

		if dst.Port() == 53 && ns.cfg.DNS != nil {
			// Stub resolvers use a fresh source port per query, so each
			// query is its own flow. These flows used to be uncapped and to
			// live for the full UDP idle timeout after their one answer: a
			// browser resolving a page's worth of names held hundreds of
			// goroutines and gVisor endpoints for a minute, and an app
			// flooding port 53 could grow them without bound.
			if !acquireSlot(&ns.dnsFlows, ns.cfg.maxDNSFlows) {
				ns.rejectedFlows.Add(1)
				// Dropped, like any UDP flow over its cap; the stub retries.
				ns.emit(FlowEvent{Proto: "dns", Dst: dst, Err: ErrTooManyFlows})
				return
			}
			handled := ns.serveDNS(inbound, client, dst)
			ns.dnsFlows.Add(-1)
			if handled {
				return
			}
		}
		ns.proxyUDP(inbound, client, dst)
	}()
}

// udpIdleTimeout is how long a UDP flow with no traffic is kept.
//
// 60s is chosen to outlive a DNS retry and a QUIC handshake while not pinning
// a proxy association per short-lived flow. A phone opens and abandons a lot
// of UDP flows; without an idle timeout the association count grows without
// bound and the exit node runs out of ports.
const udpIdleTimeout = 60 * time.Second

// dnsUDPIdleTimeout is how long an intercepted UDP/53 flow waits for another
// query after its last one. A stub resolver sends one query per source port
// (plus, at most, a retry after a few seconds), so a minute of waiting — the
// generic UDP timeout — only pinned a goroutine per lookup.
const dnsUDPIdleTimeout = 10 * time.Second

// DefaultMaxDNSFlows bounds concurrent intercepted UDP DNS flows. Each holds a
// goroutine, a 1.5 KiB buffer and a gVisor endpoint for up to
// dnsUDPIdleTimeout; 512 is far above a busy browser's burst (tens of lookups)
// and far below a memory problem.
const DefaultMaxDNSFlows = 512

// serveDNS answers queries on this flow through the DNS handler. It returns
// false if the handler declined, in which case the caller proxies normally.
func (ns *Stack) serveDNS(inbound *gonet.UDPConn, client, dst netip.AddrPort) bool {
	buf := make([]byte, 1500)
	for {
		if err := inbound.SetReadDeadline(time.Now().Add(ns.cfg.dnsUDPIdleTimeout)); err != nil {
			return true
		}
		n, _, err := inbound.ReadFrom(buf)
		if err != nil {
			return true
		}

		resp, handled, err := ns.cfg.DNS.HandleQuery(ns.ctx, client, buf[:n])
		if err != nil {
			ns.emit(FlowEvent{Proto: "dns", Dst: dst, Err: err})
			return true
		}
		if !handled {
			// Declined on the first query: fall through to the proxy. Once
			// any query on this flow has been answered locally we stay local,
			// because switching mid-flow would send the app's next query
			// somewhere different from the one before it.
			return false
		}
		if resp == nil {
			continue // intentional silent drop, e.g. a blocked name
		}
		if _, err := inbound.Write(resp); err != nil {
			return true
		}
	}
}

// proxyUDP carries a UDP flow over the transport.
//
// Lifetime is the subtle part. The two directions block in different places —
// the gonet conn, which supports deadlines, and the transport session, which
// does not — so the only way to end the flow is to close both as soon as
// either direction stops, whether because of an error, the idle timeout or
// Close. Without that, the session reader sits in ReadFrom forever after the
// app has gone, and every abandoned flow leaks two goroutines, two buffers
// and an association on the exit node.
func (ns *Stack) proxyUDP(inbound *gonet.UDPConn, client, dst netip.AddrPort) {
	// Taken before the dial, for the same reason as the TCP cap.
	if !acquireSlot(&ns.udpFlows, ns.cfg.MaxUDPFlows) {
		ns.rejectedFlows.Add(1)
		// Dropped: UDP has no reset, and the caller's deferred Close removes
		// the endpoint, so the app's next datagram is offered a slot afresh.
		ns.emit(FlowEvent{Proto: "udp", Dst: dst, Err: ErrTooManyFlows})
		return
	}
	defer ns.udpFlows.Add(-1)

	ctx, cancel := context.WithTimeout(ns.ctx, dialTimeout)
	start := time.Now()
	session, err := ns.cfg.Dialer.DialUDP(ctx, dst)
	cancel()
	dialLatency := time.Since(start)

	if err != nil {
		ns.failedDials.Add(1)
		// A transport that cannot carry UDP must drop the flow, never let it
		// out of the tunnel. Returning here does exactly that: the app's
		// datagrams go nowhere and it falls back to TCP. The alternative —
		// dialing directly — is how a "UDP unsupported" limitation becomes a
		// traffic leak outside the tunnel.
		ns.emit(FlowEvent{Proto: "udp", Dst: dst, DialLatency: dialLatency, Err: err})
		return
	}

	var closeOnce sync.Once
	teardown := func() {
		closeOnce.Do(func() {
			_ = inbound.Close()
			_ = session.Close()
		})
	}
	defer teardown()

	ns.totalFlows.Add(1)
	ns.activeFlows.Add(1)
	defer ns.activeFlows.Add(-1)

	// lastActive is nanoseconds since epoch (a monotonic base) of the most
	// recent datagram in either direction. The idle timeout is enforced on
	// the app side, the only side with a deadline, but must be refreshed by
	// traffic both ways: a flow that only receives — a media stream, a
	// QUIC download — is not idle.
	epoch := time.Now()
	var lastActive atomic.Int64
	touch := func() { lastActive.Store(int64(time.Since(epoch))) }
	idle := ns.cfg.udpIdleTimeout

	var up, down atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)

	// App to exit node.
	go func() {
		defer wg.Done()
		defer teardown()
		buf := make([]byte, 1500)
		for {
			deadline := epoch.Add(time.Duration(lastActive.Load()) + idle)
			if !time.Now().Before(deadline) {
				return // idle in both directions
			}
			if err := inbound.SetReadDeadline(deadline); err != nil {
				return
			}
			n, _, err := inbound.ReadFrom(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue // re-check: the other direction may have been active
				}
				return
			}
			touch()
			if _, err := session.WriteTo(buf[:n], dst); err != nil {
				return
			}
			up.Add(int64(n))
		}
	}()

	// Exit node back to app.
	go func() {
		defer wg.Done()
		defer teardown()
		buf := make([]byte, 1500)
		for {
			n, _, err := session.ReadFrom(buf)
			if err != nil {
				return
			}
			touch()
			if _, err := inbound.Write(buf[:n]); err != nil {
				return
			}
			down.Add(int64(n))
		}
	}()

	// Stack shutdown tears the flow down too. The done case is what lets
	// this goroutine exit when the flow ends on its own.
	done := make(chan struct{})
	go func() {
		select {
		case <-ns.ctx.Done():
			teardown()
		case <-done:
		}
	}()

	wg.Wait()
	close(done)
	ns.emit(FlowEvent{
		Proto: "udp", Dst: dst, DialLatency: dialLatency,
		BytesUp: up.Load(), BytesDown: down.Load(),
	})
}

var _ transport.StreamDialer = transport.StreamDialer(nil)
var _ = stack.TransportEndpointID{}
