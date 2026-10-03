package netstack

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	tcpproto "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport"
)

// tcpSyn builds an IPv4 TCP SYN from src to dst with a valid checksum.
func tcpSyn(src, dst netip.AddrPort) []byte {
	const ipLen, tcpLen = 20, 20
	b := make([]byte, ipLen+tcpLen)
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], ipLen+tcpLen)
	b[8] = 64
	b[9] = 6
	copy(b[12:16], s4[:])
	copy(b[16:20], d4[:])
	binary.BigEndian.PutUint16(b[10:12], packet.Fold(packet.Checksum(b[:ipLen], 0)))

	tcp := b[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], src.Port())
	binary.BigEndian.PutUint16(tcp[2:4], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	tcp[12] = 5 << 4
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	var pseudo [12]byte
	copy(pseudo[0:4], s4[:])
	copy(pseudo[4:8], d4[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], tcpLen)
	binary.BigEndian.PutUint16(tcp[16:18], packet.Fold(packet.Checksum(tcp, packet.Checksum(pseudo[:], 0))))
	return b
}

// TestStackCloseRacesInboundDelivery is the regression test for flows being
// registered with the stack's WaitGroup while Close was already waiting on it.
//
// The engine's tunnel reader can be inside DeliverInbound when a session is
// torn down, and gVisor's TCP forwarder runs each SYN's handler on a goroutine
// that may start after Close. Both used to call wg.Add unguarded, which the
// race detector reported and the runtime occasionally turned into a panic
// ("WaitGroup is reused before previous Wait has returned") — a crash of the
// whole VPN process on a reconnect.
func TestStackCloseRacesInboundDelivery(t *testing.T) {
	iterations := 60
	if testing.Short() {
		iterations = 15
	}
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	udpDst := netip.MustParseAddrPort("93.184.216.34:4433")
	for i := 0; i < iterations; i++ {
		dialer := newFakeDialer()
		dialer.onTCP = func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		dialer.onUDP = func(context.Context, netip.AddrPort) (transport.UDPSession, error) {
			return newFakeUDPSession(), nil
		}
		ns, err := New(Config{Dialer: dialer, MTU: testMTU,
			LocalAddresses: []netip.Prefix{netip.PrefixFrom(tunnelAddr, 32)}})
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for w := 0; w < 2; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				buf := make([]byte, 1500)
				for port := uint16(1024 + w*20000); ; port++ {
					select {
					case <-stop:
						return
					default:
					}
					src := netip.AddrPortFrom(tunnelAddr, port)
					_ = ns.DeliverInbound(tcpSyn(src, dst))
					if p, err := packet.BuildUDP(buf, src, udpDst, []byte("x")); err == nil {
						_ = ns.DeliverInbound(p)
					}
				}
			}(w)
		}
		time.Sleep(time.Duration(1+i%5) * time.Millisecond)
		_ = ns.Close()
		close(stop)
		wg.Wait()
	}
}

// TestStackRemoteResetTearsDownFlow is the regression test for a reset on one
// direction of a spliced flow being propagated as a mere half-close.
//
// The exit-side connection is reset by the server while the app keeps its
// side open and never sends FIN. Before the fix, the reset was turned into a
// half-close towards the app, and the flow — two goroutines, two 32 KiB
// buffers and a flow slot — then waited for the app to close, which an app
// that ignores EOF (or is simply idle on a long-poll) never does.
func TestStackRemoteResetTearsDownFlow(t *testing.T) {
	dialer := newFakeDialer()
	dialer.onTCP = loopbackServer(t, func(c net.Conn) {
		buf := make([]byte, 64)
		_, _ = io.ReadFull(c, buf[:5])
		tc := c.(*net.TCPConn)
		_ = tc.SetLinger(0) // Close sends RST
		_ = tc.Close()
	})
	ns := newTestStack(t, Config{Dialer: dialer})
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := peer.dialTCP(ctx, remoteHTTP)
	if err != nil {
		t.Fatalf("dialTCP: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the flow to be torn down after the exit side reset", func() bool {
		return ns.Stats().ActiveFlows == 0 && ns.tcpFlows.Load() == 0
	})
}

// blockingDNS answers every query, but only once release is closed.
type blockingDNS struct {
	release chan struct{}
	mu      sync.Mutex
	seen    int
}

func (d *blockingDNS) HandleQuery(ctx context.Context, _ netip.AddrPort, q []byte) ([]byte, bool, error) {
	d.mu.Lock()
	d.seen++
	d.mu.Unlock()
	select {
	case <-d.release:
	case <-ctx.Done():
	}
	return q, true, nil
}

// TestStackDNSFlowsAreCappedAndReclaimed is the regression test for
// intercepted UDP/53 flows being uncapped and held for the generic 60s UDP
// idle timeout. Stub resolvers use one source port per query, so every lookup
// was a goroutine and a gVisor endpoint pinned for a minute, and an app
// flooding port 53 could grow them without bound.
func TestStackDNSFlowsAreCappedAndReclaimed(t *testing.T) {
	const maxFlows, queries = 20, 100
	dns := &blockingDNS{release: make(chan struct{})}
	ns := newTestStack(t, Config{
		Dialer: newFakeDialer(), DNS: dns,
		maxDNSFlows: maxFlows, dnsUDPIdleTimeout: 100 * time.Millisecond,
	})
	// Drain replies so the link queue never backs up.
	go func() {
		buf := make([]byte, testMTU)
		for {
			if _, err := ns.ReadOutbound(buf); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 1500)
	for i := 0; i < queries; i++ {
		src := netip.AddrPortFrom(tunnelAddr, uint16(30000+i))
		p, err := packet.BuildUDP(buf, src, remoteDNS, []byte("query"))
		if err != nil {
			t.Fatal(err)
		}
		if err := ns.DeliverInbound(p); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 5*time.Second, "the DNS flow cap to engage", func() bool {
		return ns.Stats().RejectedFlows >= queries-maxFlows
	})
	if n := ns.dnsFlows.Load(); n > maxFlows {
		t.Fatalf("%d concurrent DNS flows, cap is %d", n, maxFlows)
	}
	close(dns.release)
	waitFor(t, 5*time.Second, "idle DNS flows to be reclaimed", func() bool {
		return ns.dnsFlows.Load() == 0
	})
}

// TestStackCountsOutboundQueueDrops is the regression test for packets the
// stack generates towards the tunnel being dropped silently when the outbound
// queue is full. Here nothing reads ReadOutbound, and every SYN is refused, so
// each produces a RST: the first channelDepth fit, the rest must be counted.
func TestStackCountsOutboundQueueDrops(t *testing.T) {
	dialer := newFakeDialer() // onTCP nil: every dial fails, every SYN gets a RST
	ns := newTestStack(t, Config{Dialer: dialer})
	const syns = channelDepth + 100
	for i := 0; i < syns; i++ {
		src := netip.AddrPortFrom(tunnelAddr, uint16(10000+i))
		if err := ns.DeliverInbound(tcpSyn(src, remoteHTTP)); err != nil {
			t.Fatal(err)
		}
		if i%64 == 63 {
			// Stay under the forwarder's in-flight limit, which drops SYNs
			// (silently, and before any RST) rather than queueing them.
			waitFor(t, 5*time.Second, "SYNs to be answered", func() bool {
				return int(ns.Stats().FailedDials) >= i+1-8
			})
		}
	}
	waitFor(t, 10*time.Second, "outbound drops to be counted", func() bool {
		return ns.ep.NumQueued() == channelDepth && ns.Stats().DroppedOutbound >= 50
	})
}

// TestStackDisablesRACK pins the loss-recovery choice made in configureTCP.
// gVisor's default RACK-TLP can leave a sender in FIN-WAIT-1 with no timer
// armed after losses near the FIN, so downloads over a lossy radio hung just
// short of the end; TestSoakNetstackLossyDownload (soak tag) is the
// behavioural reproduction, and is too slow for the default suite.
func TestStackDisablesRACK(t *testing.T) {
	ns := newTestStack(t, Config{Dialer: newFakeDialer()})
	var r tcpip.TCPRecovery
	if err := ns.s.TransportProtocolOption(tcpproto.ProtocolNumber, &r); err != nil {
		t.Fatal(err)
	}
	if r&tcpip.TCPRACKLossDetection != 0 {
		t.Fatalf("TCPRecovery = %#x: RACK is enabled", r)
	}
}
