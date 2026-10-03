// Package netstack terminates the flows arriving on the tunnel interface in a
// userspace TCP/IP stack, so they can be carried over a transport that speaks
// connections rather than packets.
//
// Why this exists at all: a proxy protocol such as Shadowsocks, SOCKS5 or
// HTTP CONNECT has no concept of an IP packet. You hand it a destination and
// it hands you a byte stream. But the mobile OS hands *us* raw IP packets off
// the tunnel fd. Something has to sit in between and do what a kernel does —
// reassemble TCP segments into a stream, track connection state, generate
// ACKs, handle retransmission and window management — entirely in userspace,
// for traffic that is never destined for this host. That is what gVisor's
// netstack is for, and this package is the glue.
//
// The shape of the data path:
//
//	tunnel fd ──► DeliverInbound ──► channel.Endpoint ──► gVisor stack
//	                                                          │
//	                                            TCP/UDP forwarder intercepts
//	                                                          │
//	                                                   StreamDialer.DialTCP
//	                                                          │
//	                                                     exit node
//
//	exit node ──► proxied conn ──► gVisor stack ──► ReadOutbound ──► tunnel fd
//
// Two settings make this work and are worth calling out, because without them
// the stack silently drops everything and the mistake is very hard to see:
// promiscuous mode, so the NIC accepts frames not addressed to it, and
// spoofing, so the stack will originate packets from addresses it does not
// own. A normal host wants neither. A transparent proxy needs both, because
// every packet it handles is addressed to somebody else.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	tcpproto "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	udpproto "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/ameerhamza2/tunnelcore/transport"
)

// nicID is the single NIC in this stack. There is only ever one: the tunnel.
const nicID tcpip.NICID = 1

// Tuning constants.
const (
	// channelDepth is how many packets may sit between the tunnel reader and
	// the stack. See the drop-policy comment in DeliverInbound.
	channelDepth = 512

	// tcpRcvWnd is the receive window advertised to the application inside
	// the tunnel, and maxInFlight is how many half-open connections the
	// forwarder will track.
	//
	// maxInFlight matters more than it looks: it is the bound on resource
	// consumption when an app on the device opens connections faster than the
	// transport can establish them — a port scanner, a misbehaving SDK, or
	// simply a browser opening a page with fifty origins on a slow link.
	//
	// Note that gVisor *silently drops* SYNs beyond this limit rather than
	// resetting them, and it counts a request as in flight until Complete is
	// called on it. That is why handleTCP completes each request as soon as
	// the handshake is done: if it waited until the flow ended, this would
	// become a cap on established connections and connection 513 would hang
	// in SYN_SENT for as long as the other 512 stay open. The bound on
	// established flows is DefaultMaxTCPFlows, which resets instead.
	tcpRcvWnd      = 0 // 0 lets gVisor pick from the buffer-size range below
	tcpMaxInFlight = 512

	// DefaultMaxTCPFlows and DefaultMaxUDPFlows bound how many proxied flows
	// may exist at once (see Config.MaxTCPFlows / MaxUDPFlows).
	//
	// Each flow costs two goroutines, two copy buffers, gVisor endpoint
	// buffers and a connection or association on the exit node. Without a
	// cap, one misbehaving app holding connections open can exhaust memory
	// on a device where the OS kills the VPN extension long before Go would
	// notice. The numbers are far above what a phone legitimately uses
	// (a busy browser sits in the low hundreds) and far below what fits in
	// a mobile network-extension memory budget.
	DefaultMaxTCPFlows = 4096
	DefaultMaxUDPFlows = 1024

	// Buffer-size ranges for TCP. The defaults are tuned for a datacentre;
	// these are tuned for a phone, where memory is scarcer and the
	// bandwidth-delay product is smaller.
	tcpMinBuf     = 4 << 10
	tcpDefaultBuf = 128 << 10
	tcpMaxBuf     = 2 << 20

	// dialTimeout bounds how long a single proxied dial may take before the
	// stack resets the inner connection.
	dialTimeout = 15 * time.Second

	// spliceBufSize is the per-direction copy buffer for a proxied stream.
	spliceBufSize = 32 << 10
)

// Errors returned by this package.
var (
	ErrClosed     = errors.New("netstack: closed")
	ErrNoDialer   = errors.New("netstack: no stream dialer configured")
	ErrPacketSize = errors.New("netstack: packet larger than MTU")

	// ErrTooManyFlows is reported in a FlowEvent for a flow refused because
	// Config.MaxTCPFlows or Config.MaxUDPFlows was reached.
	ErrTooManyFlows = errors.New("netstack: too many concurrent flows")
)

// DNSHandler intercepts DNS queries before they reach the transport.
//
// The engine installs one so that name resolution happens inside the tunnel.
// Returning handled=false falls through to the normal proxied path.
type DNSHandler interface {
	// HandleQuery answers a DNS query. query is the raw DNS message payload.
	// Returning a nil response with a nil error means "drop silently".
	HandleQuery(ctx context.Context, client netip.AddrPort, query []byte) (response []byte, handled bool, err error)
}

// Config configures a Stack.
type Config struct {
	// Dialer carries the terminated flows to the exit node.
	Dialer transport.StreamDialer

	// MTU of the tunnel interface.
	MTU int

	// LocalAddresses are the addresses assigned to the tunnel interface.
	// Traffic to these is handled by the stack itself rather than proxied,
	// which is how the DNS proxy becomes reachable.
	LocalAddresses []netip.Prefix

	// DNS, if non-nil, intercepts UDP and TCP flows to port 53.
	DNS DNSHandler

	// OnFlow, if non-nil, is called once per accepted flow. The engine uses
	// it for metrics. It must not block.
	OnFlow func(flow FlowEvent)

	// MaxTCPFlows caps concurrent TCP flows, counting ones still being
	// dialed. A SYN beyond the cap is answered with a reset, so the app sees
	// a prompt refusal and backs off instead of retransmitting into a void.
	// Zero or negative means DefaultMaxTCPFlows.
	MaxTCPFlows int

	// MaxUDPFlows caps concurrent proxied UDP flows. A datagram that would
	// start a flow beyond the cap is dropped — UDP has no reset, and apps
	// already treat loss as normal. Zero or negative means
	// DefaultMaxUDPFlows.
	MaxUDPFlows int

	// Test hooks. Unexported so they are not part of the API; zero means the
	// production default. They exist so the regression tests for the idle
	// and in-flight limits run in milliseconds rather than minutes.
	udpIdleTimeout    time.Duration
	dnsUDPIdleTimeout time.Duration
	dnsTCPIdleTimeout time.Duration
	maxDNSFlows       int
	tcpMaxInFlight    int
}

// FlowEvent reports the outcome of one proxied flow.
type FlowEvent struct {
	Proto       string
	Dst         netip.AddrPort
	DialLatency time.Duration
	BytesUp     int64
	BytesDown   int64
	Err         error
}

// Stack is a userspace TCP/IP stack bound to one tunnel interface.
type Stack struct {
	cfg Config

	s  *stack.Stack
	ep *channel.Endpoint

	// ctx is cancelled on Close, which unblocks ReadOutbound and every
	// in-flight splice.
	ctx    context.Context
	cancel context.CancelFunc

	// wg tracks every flow goroutine. Flows are started from gVisor's packet
	// delivery path, which can run concurrently with Close (the engine's tunnel
	// reader may be inside DeliverInbound, and gVisor's TCP forwarder hands
	// SYNs to fresh goroutines that run later still). A bare wg.Add there
	// races wg.Wait in Close, which the race detector reports and the runtime
	// can turn into "WaitGroup is reused before previous Wait has returned".
	// enter/closing make Add and Wait mutually exclusive: once Close has set
	// closing, no new flow is admitted.
	wg        sync.WaitGroup
	closeMu   sync.Mutex
	closing   bool
	closeOnce sync.Once

	droppedInbound atomic.Uint64
	// droppedOutbound counts packets the stack generated for the tunnel that
	// the link queue had no room for; see countingLink.
	droppedOutbound atomic.Uint64
	activeFlows     atomic.Int64
	totalFlows      atomic.Uint64
	failedDials     atomic.Uint64
	rejectedFlows   atomic.Uint64

	// tcpFlows and udpFlows count the slots taken against MaxTCPFlows and
	// MaxUDPFlows. They are separate from activeFlows because a slot is
	// taken before the dial (that is what makes the cap a bound on dialing
	// work too), whereas activeFlows counts established flows only.
	tcpFlows atomic.Int64
	udpFlows atomic.Int64
	dnsFlows atomic.Int64
}

// New builds and starts a Stack.
func New(cfg Config) (*Stack, error) {
	if cfg.Dialer == nil {
		return nil, ErrNoDialer
	}
	if cfg.MTU <= 0 {
		return nil, fmt.Errorf("netstack: MTU must be positive, got %d", cfg.MTU)
	}

	if cfg.MaxTCPFlows <= 0 {
		cfg.MaxTCPFlows = DefaultMaxTCPFlows
	}
	if cfg.MaxUDPFlows <= 0 {
		cfg.MaxUDPFlows = DefaultMaxUDPFlows
	}
	if cfg.udpIdleTimeout <= 0 {
		cfg.udpIdleTimeout = udpIdleTimeout
	}
	if cfg.dnsUDPIdleTimeout <= 0 {
		cfg.dnsUDPIdleTimeout = dnsUDPIdleTimeout
	}
	if cfg.maxDNSFlows <= 0 {
		cfg.maxDNSFlows = DefaultMaxDNSFlows
	}
	if cfg.dnsTCPIdleTimeout <= 0 {
		cfg.dnsTCPIdleTimeout = dnsTCPIdleTimeout
	}
	if cfg.tcpMaxInFlight <= 0 {
		cfg.tcpMaxInFlight = tcpMaxInFlight
	}

	ns := &Stack{cfg: cfg}
	ns.ctx, ns.cancel = context.WithCancel(context.Background())

	ns.s = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcpproto.NewProtocol, udpproto.NewProtocol,
			icmp.NewProtocol4, icmp.NewProtocol6,
		},
		// HandleLocal false: packets addressed to our own tunnel addresses
		// still go through the normal demux path, which is what lets the
		// forwarders see traffic aimed at the DNS proxy.
		HandleLocal: false,
	})

	if err := ns.configureTCP(); err != nil {
		ns.s.Close()
		return nil, err
	}

	ns.ep = channel.New(channelDepth, uint32(cfg.MTU), "")
	if err := ns.s.CreateNIC(nicID, &countingLink{Endpoint: ns.ep, dropped: &ns.droppedOutbound}); err != nil {
		ns.s.Close()
		return nil, fmt.Errorf("netstack: creating NIC: %v", err)
	}

	// See the package doc: both of these are required for a transparent
	// proxy and would be wrong on an ordinary host.
	if err := ns.s.SetPromiscuousMode(nicID, true); err != nil {
		ns.s.Close()
		return nil, fmt.Errorf("netstack: enabling promiscuous mode: %v", err)
	}
	if err := ns.s.SetSpoofing(nicID, true); err != nil {
		ns.s.Close()
		return nil, fmt.Errorf("netstack: enabling spoofing: %v", err)
	}

	if err := ns.addLocalAddresses(); err != nil {
		ns.s.Close()
		return nil, err
	}
	ns.installDefaultRoutes()
	ns.installForwarders()

	return ns, nil
}

func (ns *Stack) configureTCP() error {
	opts := []tcpip.SettableTransportProtocolOption{
		// SACK is not optional on a mobile link. Without it a single lost
		// segment costs a full round of go-back-N retransmission, and on a
		// link with 2% loss that is the difference between a usable tunnel
		// and an unusable one.
		ptr(tcpip.TCPSACKEnabled(true)),

		// Disable Nagle. The stack is a relay, not an application: it has no
		// idea whether more data is coming, so coalescing small writes only
		// adds latency. Interactive traffic (SSH, a game, a chat app) is
		// exactly what suffers.
		ptr(tcpip.TCPDelayEnabled(false)),

		ptr(tcpip.TCPModerateReceiveBufferOption(true)),

		// Disable RACK-TLP loss detection, gVisor's default, and recover with
		// SACK (RFC 6675) plus the retransmission timer instead.
		//
		// With RACK on, a sender that loses segments around its FIN can stop
		// retransmitting altogether: the endpoint sits in FIN-WAIT-1 with
		// unacknowledged data and no timer armed (TCP Timeouts stays at
		// zero), forever. This stack is the sender towards every app, and it
		// sends a FIN whenever a server finishes a response, so on a lossy
		// radio the visible result was downloads that hang a few hundred
		// bytes from the end. TestSoakNetstackLossyDownload reproduces it
		// (several of 200 downloads stuck at 10% loss, one even at 2%;
		// STACKRACK=1 restores RACK to see it) and passes with it off.
		ptr(tcpip.TCPRecovery(0)),
		&tcpip.TCPSendBufferSizeRangeOption{
			Min: tcpMinBuf, Default: tcpDefaultBuf, Max: tcpMaxBuf,
		},
		&tcpip.TCPReceiveBufferSizeRangeOption{
			Min: tcpMinBuf, Default: tcpDefaultBuf, Max: tcpMaxBuf,
		},
	}
	for _, o := range opts {
		if err := ns.s.SetTransportProtocolOption(tcpproto.ProtocolNumber, o); err != nil {
			return fmt.Errorf("netstack: setting TCP option %T: %v", o, err)
		}
	}
	return nil
}

func ptr[T any](v T) *T { return &v }

func (ns *Stack) addLocalAddresses() error {
	for _, p := range ns.cfg.LocalAddresses {
		addr := p.Addr()
		proto := ipv4.ProtocolNumber
		if addr.Is6() && !addr.Is4In6() {
			proto = ipv6.ProtocolNumber
		}
		pa := tcpip.ProtocolAddress{
			Protocol: proto,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(addr.AsSlice()),
				PrefixLen: p.Bits(),
			},
		}
		if err := ns.s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			return fmt.Errorf("netstack: adding address %s: %v", p, err)
		}
	}
	return nil
}

// installDefaultRoutes points everything at the tunnel NIC.
//
// Both families get a default route unconditionally, even when the tunnel has
// no address in one of them. That is deliberate: an app that tries IPv6 must
// have its SYN *accepted and proxied* rather than dropped. If v6 is dropped
// instead, the app sits in happy-eyeballs limbo waiting for a timeout before
// falling back to v4, and the user sees a VPN that makes every connection feel
// slow for reasons no log explains.
func (ns *Stack) installDefaultRoutes() {
	ns.s.SetRouteTable([]tcpip.Route{
		{Destination: header4Subnet(), NIC: nicID},
		{Destination: header6Subnet(), NIC: nicID},
	})
}

func header4Subnet() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{}),
		tcpip.MaskFromBytes(make([]byte, 4)),
	)
	return sn
}

func header6Subnet() tcpip.Subnet {
	sn, _ := tcpip.NewSubnet(
		tcpip.AddrFrom16([16]byte{}),
		tcpip.MaskFromBytes(make([]byte, 16)),
	)
	return sn
}

// DeliverInbound hands one IP packet read off the tunnel to the stack.
//
// The packet is copied, because gVisor retains the buffer past this call and
// the caller wants its read buffer back immediately.
//
// A packet larger than the MTU returns ErrPacketSize rather than being
// truncated. Truncation here would corrupt a stream in a way that surfaces
// much later as an unexplained connection reset.
func (ns *Stack) DeliverInbound(p []byte) error {
	select {
	case <-ns.ctx.Done():
		return ErrClosed
	default:
	}
	if len(p) > ns.cfg.MTU {
		ns.droppedInbound.Add(1)
		return fmt.Errorf("%w: %d > %d", ErrPacketSize, len(p), ns.cfg.MTU)
	}
	if len(p) == 0 {
		return nil
	}

	var proto tcpip.NetworkProtocolNumber
	switch p[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		ns.droppedInbound.Add(1)
		return nil // not IP; the packet parser upstream logs these
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(p),
	})
	ns.ep.InjectInbound(proto, pkt)
	pkt.DecRef()
	return nil
}

// ReadOutbound blocks until the stack has a packet for the tunnel, copies it
// into b, and returns its length. It returns ErrClosed after Close.
func (ns *Stack) ReadOutbound(b []byte) (int, error) {
	pkt := ns.ep.ReadContext(ns.ctx)
	if pkt == nil {
		return 0, ErrClosed
	}
	defer pkt.DecRef()

	view := pkt.ToView()
	n, err := view.Read(b)
	if err != nil {
		return 0, fmt.Errorf("netstack: reading outbound packet: %w", err)
	}
	return n, nil
}

// Stats reports stack counters.
type Stats struct {
	ActiveFlows    int64
	TotalFlows     uint64
	FailedDials    uint64
	DroppedInbound uint64

	// DroppedOutbound counts packets for the tunnel (towards the apps) that
	// were discarded because the outbound queue was full, i.e. the tunnel
	// writer was not keeping up.
	DroppedOutbound uint64

	// RejectedFlows counts flows refused because MaxTCPFlows or MaxUDPFlows
	// was reached.
	RejectedFlows uint64
}

// Stats returns a snapshot of the stack's counters.
func (ns *Stack) Stats() Stats {
	return Stats{
		ActiveFlows:     ns.activeFlows.Load(),
		TotalFlows:      ns.totalFlows.Load(),
		FailedDials:     ns.failedDials.Load(),
		DroppedInbound:  ns.droppedInbound.Load(),
		DroppedOutbound: ns.droppedOutbound.Load(),
		RejectedFlows:   ns.rejectedFlows.Load(),
	}
}

// Close shuts the stack down and waits for in-flight flows to finish.
func (ns *Stack) Close() error {
	ns.closeOnce.Do(func() {
		ns.closeMu.Lock()
		ns.closing = true
		ns.closeMu.Unlock()
		ns.cancel()
		ns.ep.Close()
		ns.s.Close()
		ns.wg.Wait()
		ns.s.Wait()
	})
	return nil
}

// --- helpers shared with the forwarders ---

// enter registers one flow goroutine with ns.wg, or reports false if the stack
// is closing, in which case the caller must not start the flow. A true return
// must be paired with ns.wg.Done.
func (ns *Stack) enter() bool {
	ns.closeMu.Lock()
	defer ns.closeMu.Unlock()
	if ns.closing {
		return false
	}
	ns.wg.Add(1)
	return true
}

func (ns *Stack) emit(ev FlowEvent) {
	if ns.cfg.OnFlow != nil {
		ns.cfg.OnFlow(ev)
	}
}

// addrPortFrom converts a gVisor transport endpoint identifier into the
// destination the flow was originally aimed at.
func addrPortFrom(id stack.TransportEndpointID) netip.AddrPort {
	addr, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), id.LocalPort)
}

// clientAddrPort is the source of the flow, i.e. the app inside the tunnel.
func clientAddrPort(id stack.TransportEndpointID) netip.AddrPort {
	addr, ok := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), id.RemotePort)
}

// countingLink is the stack's link endpoint: gVisor's channel endpoint, with
// the packets it drops counted.
//
// channel.Endpoint discards a packet when its queue is full and reports
// nothing — WritePackets returns a short count with a nil error, and the NIC's
// own no-buffer-space counter is never incremented on that path. The drop is
// correct (see DeliverInbound's comment on queueing across a slow reader), but
// a silent one hid exactly the "tunnel quietly shedding traffic towards the
// apps" condition the metrics exist to expose: the soak tests' only symptom
// was TCP retransmission timeouts with every drop counter at zero.
type countingLink struct {
	*channel.Endpoint
	dropped *atomic.Uint64
}

func (l *countingLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n, err := l.Endpoint.WritePackets(pkts)
	if want := pkts.Len(); err == nil && n < want {
		l.dropped.Add(uint64(want - n))
	}
	return n, err
}

// newWaiterQueue is a tiny helper so the forwarders read more clearly.
func newWaiterQueue() *waiter.Queue { return &waiter.Queue{} }

// gonetConn is the subset of gonet's connection types the splicer needs.
type gonetConn interface {
	net.Conn
}

var _ gonetConn = (*gonet.TCPConn)(nil)
