package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	tcpproto "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	udpproto "gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/ameerhamza2/tunnelcore/engine"
	"github.com/ameerhamza2/tunnelcore/packet"
)

// phone is the device side of the tunnel: an ordinary userspace TCP/IP stack
// standing in for the phone's kernel and the apps running on it.
//
// The obvious way to drive the engine in a demo is to hand-craft IP packets
// and push them into a fake tun. That works for UDP and falls apart for TCP —
// a stream transport only does anything once a genuine three-way handshake,
// windowing and FIN exchange arrive at the engine's userspace stack. So this
// is a second, independent gVisor stack with the tunnel address, whose
// "interface" is the engine's TunDevice. Apps on it use real sockets (an HTTP
// client, a UDP socket), and every packet they produce crosses the engine
// exactly as it would cross a phone's tun fd.
type phone struct {
	s    *stack.Stack
	ep   *channel.Endpoint
	addr netip.Addr
	mtu  int
	p    *printer
}

const phoneNIC tcpip.NICID = 1

func newPhone(addr netip.Addr, mtu int, p *printer) (*phone, error) {
	s := stack.New(stack.Options{
		// IPv4 only: the demo's tunnel is v4, and leaving v6 out keeps the
		// stack from emitting router solicitations and MLD reports that would
		// show up as unexplained traffic in the -v packet trace.
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcpproto.NewProtocol, udpproto.NewProtocol},
	})
	ep := channel.New(512, uint32(mtu), "")
	if err := s.CreateNIC(phoneNIC, ep); err != nil {
		s.Close()
		return nil, fmt.Errorf("phone: creating NIC: %v", err)
	}
	if err := s.AddProtocolAddress(phoneNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		s.Close()
		return nil, fmt.Errorf("phone: adding address: %v", err)
	}
	// A default route into the tunnel: a full-tunnel VPN, as on the phone.
	defaultRoute, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	s.SetRouteTable([]tcpip.Route{{Destination: defaultRoute, NIC: phoneNIC}})

	return &phone{s: s, ep: ep, addr: addr, mtu: mtu, p: p}, nil
}

// Tun returns the engine's view of the phone: the tunnel device. Packets the
// phone's apps send come out of ReadPacket; packets the engine writes are
// delivered to the apps.
func (ph *phone) Tun() engine.TunDevice {
	ctx, cancel := context.WithCancel(context.Background())
	return &phoneTun{ph: ph, ctx: ctx, cancel: cancel}
}

func (ph *phone) Close() {
	ph.ep.Close()
	ph.s.Close()
	ph.s.Wait()
}

// DialUDP opens a UDP socket from an app on the phone.
func (ph *phone) DialUDP(dst netip.AddrPort) (*gonet.UDPConn, error) {
	return gonet.DialUDP(ph.s, nil, &tcpip.FullAddress{
		NIC:  phoneNIC,
		Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()),
		Port: dst.Port(),
	}, ipv4.ProtocolNumber)
}

// HTTPClient returns an HTTP client whose connections originate on the
// phone, so every request crosses the tunnel.
func (ph *phone) HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// Proxy is deliberately nil: an http.Transport literal does not
			// consult HTTP_PROXY, which matters on a machine that has one set
			// — the request must go through the tunnel, not around it.
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				ap, err := netip.ParseAddrPort(addr)
				if err != nil {
					return nil, fmt.Errorf("phone: the demo dials literal addresses only, got %q: %w", addr, err)
				}
				return gonet.DialContextTCP(ctx, ph.s, tcpip.FullAddress{
					NIC:  phoneNIC,
					Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()),
					Port: ap.Port(),
				}, ipv4.ProtocolNumber)
			},
			// One connection per request, so each request is a fresh flow the
			// engine's stack has to terminate and dial — the interesting case.
			DisableKeepAlives: true,
		},
	}
}

// phoneTun adapts the phone's link endpoint to engine.TunDevice.
type phoneTun struct {
	ph     *phone
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func (t *phoneTun) ReadPacket(b []byte) (int, error) {
	// ReadContext is what makes Close able to unblock a reader parked on an
	// idle tunnel, which the TunDevice contract requires.
	pkt := t.ph.ep.ReadContext(t.ctx)
	if pkt == nil {
		return 0, net.ErrClosed
	}
	defer pkt.DecRef()
	n, err := pkt.ToView().Read(b)
	if err != nil {
		return 0, err
	}
	t.ph.trace("phone ▶ engine", b[:n])
	return n, nil
}

func (t *phoneTun) WritePacket(p []byte) error {
	if t.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(p) == 0 || p[0]>>4 != 4 {
		return nil // not IPv4; the phone stack has no use for it
	}
	t.ph.trace("phone ◀ engine", p)
	// MakeWithData copies p, which the TunDevice contract requires: the
	// engine reuses its buffer as soon as this returns.
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
	t.ph.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
	return nil
}

func (t *phoneTun) MTU() int { return t.ph.mtu }

func (t *phoneTun) Close() error {
	t.once.Do(t.cancel)
	return nil
}

// trace prints one packet crossing the tun, in -v mode only.
func (ph *phone) trace(dir string, b []byte) {
	if !ph.p.verbose {
		return
	}
	ph.p.debug(tagTun, "%s %s", dir, describePacket(b))
}

// describePacket renders a one-line summary of an IP packet.
func describePacket(b []byte) string {
	pp, err := packet.Parse(b)
	if err != nil {
		return fmt.Sprintf("%d B (unparsed: %v)", len(b), err)
	}
	s := fmt.Sprintf("%-3s %s → %s  %d B", pp.Flow.Proto, pp.Flow.Src, pp.Flow.Dst, len(b))
	if pp.Flow.Proto == packet.ProtoTCP {
		s += " [" + pp.L4.Flags.String() + "]"
	}
	return s
}
