package netstack

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	tcpproto "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	udpproto "gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/ameerhamza2/tunnelcore/transport"
)

// testPeer is a second, ordinary userspace TCP/IP stack standing in for the
// device: the OS kernel and the application that opens connections.
//
// Testing a transparent proxy is awkward because the thing under test only
// does anything useful when real TCP segments arrive at it. Mocking the
// forwarder would test the mock. Instead this builds a plain gVisor stack with
// a tunnel address and a default route, pumps its outbound packets into the
// Stack under test, and pumps the replies back. Both ends then run a genuine
// TCP handshake, retransmit, window-manage and close, exactly as a phone and
// the engine do — with no TUN device, no privileges and no network.
type testPeer struct {
	stack *gvstack.Stack
	ep    *channel.Endpoint
	addr  netip.Addr

	cancel context.CancelFunc
}

func newTestPeer(t testing.TB, addr netip.Addr, mtu int, target *Stack) *testPeer {
	t.Helper()
	return newLossyTestPeer(t, addr, mtu, target, 0)
}

// newLossyTestPeer is newTestPeer with a link that drops each packet, in each
// direction, with probability loss — a congested radio, deterministically.
func newLossyTestPeer(t testing.TB, addr netip.Addr, mtu int, target *Stack, loss float64) *testPeer {
	t.Helper()
	var rngMu sync.Mutex
	rng := rand.New(rand.NewSource(42))
	drop := func() bool {
		if loss <= 0 {
			return false
		}
		rngMu.Lock()
		defer rngMu.Unlock()
		return rng.Float64() < loss
	}

	s := gvstack.New(gvstack.Options{
		NetworkProtocols: []gvstack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []gvstack.TransportProtocolFactory{
			tcpproto.NewProtocol, udpproto.NewProtocol,
			icmp.NewProtocol4, icmp.NewProtocol6,
		},
	})
	// The peer stands in for the phone's kernel, which does not share
	// gVisor's RACK-TLP stall (see configureTCP), so it runs with RACK off
	// like the Stack under test; with it on, the fixture's own uploads stall
	// under loss and the tests measure a bug in the fixture.
	noRACK := tcpip.TCPRecovery(0)
	if err := s.SetTransportProtocolOption(tcpproto.ProtocolNumber, &noRACK); err != nil {
		t.Fatalf("peer TCPRecovery: %v", err)
	}
	ep := channel.New(channelDepth, uint32(mtu), "")

	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("peer CreateNIC: %v", err)
	}
	proto := ipv4.ProtocolNumber
	prefixLen := 32
	if addr.Is6() {
		proto = ipv6.ProtocolNumber
		prefixLen = 128
	}
	pa := tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr.AsSlice()),
			PrefixLen: prefixLen,
		},
	}
	if err := s.AddProtocolAddress(1, pa, gvstack.AddressProperties{}); err != nil {
		t.Fatalf("peer AddProtocolAddress: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header4Subnet(), NIC: 1},
		{Destination: header6Subnet(), NIC: 1},
	})

	ctx, cancel := context.WithCancel(context.Background())
	p := &testPeer{stack: s, ep: ep, addr: addr, cancel: cancel}

	// Peer -> Stack under test.
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			b := pkt.ToView().AsSlice()
			cp := make([]byte, len(b))
			copy(cp, b)
			pkt.DecRef()
			if drop() {
				continue
			}
			if err := target.DeliverInbound(cp); err != nil {
				return
			}
		}
	}()

	// Stack under test -> peer.
	go func() {
		buf := make([]byte, mtu)
		for {
			n, err := target.ReadOutbound(buf)
			if err != nil {
				return
			}
			if drop() {
				continue
			}
			var netProto tcpip.NetworkProtocolNumber
			switch buf[0] >> 4 {
			case 4:
				netProto = ipv4.ProtocolNumber
			case 6:
				netProto = ipv6.ProtocolNumber
			default:
				continue
			}
			inj := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
				Payload: buffer.MakeWithData(buf[:n]),
			})
			ep.InjectInbound(netProto, inj)
			inj.DecRef()
		}
	}()

	t.Cleanup(func() {
		cancel()
		ep.Close()
		s.Close()
	})
	return p
}

// dialTCP opens a TCP connection from the peer to dst. dst is an arbitrary
// address that nothing owns: the point is that the Stack under test intercepts
// it.
func (p *testPeer) dialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	proto := ipv4.ProtocolNumber
	if dst.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return gonet.DialContextTCP(ctx, p.stack, tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()),
		Port: dst.Port(),
	}, proto)
}

// dialUDP opens a UDP "connection" from the peer to dst.
func (p *testPeer) dialUDP(dst netip.AddrPort) (*gonet.UDPConn, error) {
	proto := ipv4.ProtocolNumber
	if dst.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	return gonet.DialUDP(p.stack, nil, &tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(dst.Addr().AsSlice()),
		Port: dst.Port(),
	}, proto)
}

// --- fake transport ---

// fakeDialer is a StreamDialer whose behaviour each test sets explicitly.
type fakeDialer struct {
	name    string
	onTCP   func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	onUDP   func(ctx context.Context, dst netip.AddrPort) (transport.UDPSession, error)
	dialled chan netip.AddrPort
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{name: "fake/test", dialled: make(chan netip.AddrPort, 32)}
}

func (f *fakeDialer) Name() string             { return f.name }
func (f *fakeDialer) Kind() transport.Kind     { return transport.KindStream }
func (f *fakeDialer) Up(context.Context) error { return nil }
func (f *fakeDialer) Close() error             { return nil }

func (f *fakeDialer) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	select {
	case f.dialled <- dst:
	default:
	}
	if f.onTCP == nil {
		return nil, transport.ErrUnsupportedFlow
	}
	return f.onTCP(ctx, dst)
}

func (f *fakeDialer) DialUDP(ctx context.Context, dst netip.AddrPort) (transport.UDPSession, error) {
	select {
	case f.dialled <- dst:
	default:
	}
	if f.onUDP == nil {
		return nil, transport.ErrUnsupportedFlow
	}
	return f.onUDP(ctx, dst)
}

// loopbackServer starts a TCP server on loopback and returns a dial function
// that connects to it.
//
// These fixtures use a real loopback listener rather than net.Pipe on purpose.
// net.Pipe does not implement CloseWrite, so a pipe-backed fake would quietly
// violate the half-close contract that transport.StreamDialer.DialTCP
// requires, and the stack's half-close handling would be tested against
// something no real transport behaves like. A *net.TCPConn is exactly what the
// Shadowsocks transport returns.
func loopbackServer(t testing.TB, serve func(net.Conn)) func(context.Context, netip.AddrPort) (net.Conn, error) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(c)
		}
	}()

	addr := ln.Addr().String()
	return func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
}

// echoServer returns a dial function whose connections echo everything back,
// upper-cased so a test can tell the echo apart from its own write.
func echoServer(t *testing.T) func(context.Context, netip.AddrPort) (net.Conn, error) {
	t.Helper()
	return loopbackServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				out := make([]byte, n)
				for i := 0; i < n; i++ {
					ch := buf[i]
					if ch >= 'a' && ch <= 'z' {
						ch -= 'a' - 'A'
					}
					out[i] = ch
				}
				if _, werr := c.Write(out); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	})
}

// fakeUDPSession echoes datagrams back to the sender.
type fakeUDPSession struct {
	in     chan []byte
	closed chan struct{}
}

func newFakeUDPSession() *fakeUDPSession {
	return &fakeUDPSession{in: make(chan []byte, 16), closed: make(chan struct{})}
}

func (s *fakeUDPSession) WriteTo(b []byte, _ netip.AddrPort) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	select {
	case s.in <- cp:
		return len(b), nil
	case <-s.closed:
		return 0, net.ErrClosed
	}
}

func (s *fakeUDPSession) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	select {
	case p := <-s.in:
		return copy(b, p), netip.MustParseAddrPort("1.2.3.4:9"), nil
	case <-s.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

func (s *fakeUDPSession) Close() error {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	return nil
}

var _ transport.UDPSession = (*fakeUDPSession)(nil)
var _ transport.StreamDialer = (*fakeDialer)(nil)
