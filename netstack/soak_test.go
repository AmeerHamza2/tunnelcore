//go:build soak

package netstack

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/ameerhamza2/tunnelcore/transport"
)

func settleNS(d time.Duration) (int, uint64) {
	time.Sleep(d)
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return runtime.NumGoroutine(), ms.HeapAlloc
}

// loopbackUDPSession is a transport.UDPSession over a real loopback socket,
// so the soak exercises the stack against kernel UDP rather than a channel.
type loopbackUDPSession struct{ c *net.UDPConn }

func (s *loopbackUDPSession) WriteTo(b []byte, _ netip.AddrPort) (int, error) { return s.c.Write(b) }
func (s *loopbackUDPSession) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	n, err := s.c.Read(b)
	return n, netip.AddrPort{}, err
}
func (s *loopbackUDPSession) Close() error { return s.c.Close() }

func udpEchoServer(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadBuffer(4 << 20)
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], addr)
		}
	}()
	return pc
}

// rawEchoServer echoes bytes unchanged and propagates the client's half-close.
func rawEchoServer(t *testing.T) func(context.Context, netip.AddrPort) (net.Conn, error) {
	return loopbackServer(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.Copy(c, c)
		_ = c.(*net.TCPConn).CloseWrite()
	})
}

// TestSoakNetstackConcurrentFlows opens 2,000 concurrent TCP flows and 1,000
// UDP flows from an app-side stack through the Stack under test to loopback
// servers, checks every byte, and then checks that closing them returns the
// stack to zero flows and the process to its baseline goroutine count.
func TestSoakNetstackConcurrentFlows(t *testing.T) {
	tcpFlows, udpFlows := 2000, 1000
	if testing.Short() {
		tcpFlows, udpFlows = 200, 100
	}
	udpSrv := udpEchoServer(t)
	dialer := newFakeDialer()
	dialer.dialled = make(chan netip.AddrPort) // unbuffered + non-blocking send: never record
	dialer.onTCP = rawEchoServer(t)
	dialer.onUDP = func(ctx context.Context, _ netip.AddrPort) (transport.UDPSession, error) {
		c, err := net.DialUDP("udp", nil, udpSrv.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return nil, err
		}
		return &loopbackUDPSession{c}, nil
	}

	baseG, baseHeap := settleNS(100 * time.Millisecond)

	ns, err := New(Config{
		Dialer: dialer, MTU: testMTU,
		LocalAddresses: []netip.Prefix{netip.PrefixFrom(tunnelAddr, 32)},
		udpIdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	peer := newTestPeer(t, tunnelAddr, testMTU, ns)

	// Deadlines only bound "never completes"; the run takes ~10s on an idle
	// 2-CPU box and about the same with two CPU-burning processes beside it.
	// Before RACK was disabled (see configureTCP) that contended run left
	// flows stuck in FIN-WAIT-1 past an 8-minute deadline: link-queue drops
	// under starvation tripped gVisor's RACK-TLP stall.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Phase 1: open every TCP flow and hold them all open at once.
	conns := make([]net.Conn, tcpFlows)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 256) // below the forwarder's in-flight SYN limit
	var dialErrs atomic.Int64
	start := time.Now()
	for i := range conns {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, byte(i >> 8), byte(i)}), 443)
			c, err := peer.dialTCP(ctx, dst)
			if err != nil {
				dialErrs.Add(1)
				return
			}
			conns[i] = c
		}(i)
	}
	wg.Wait()
	if n := dialErrs.Load(); n > 0 {
		t.Fatalf("%d of %d TCP dials failed", n, tcpFlows)
	}
	waitFor(t, 30*time.Second, "every TCP flow to be established", func() bool {
		return ns.Stats().ActiveFlows == int64(tcpFlows)
	})
	t.Logf("%d TCP flows open concurrently after %s", tcpFlows, time.Since(start).Round(time.Millisecond))

	// Phase 2: every flow sends a random-sized payload, half-closes, and
	// reads the echo back; byte-exact.
	var bytesMoved atomic.Int64
	var tcpBad atomic.Int64
	start = time.Now()
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c net.Conn) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(i)))
			payload := make([]byte, 1+rng.Intn(64<<10))
			rng.Read(payload)
			want := sha256.Sum256(payload)
			_ = c.SetDeadline(time.Now().Add(8 * time.Minute))
			errc := make(chan error, 1)
			go func() {
				_, err := c.Write(payload)
				if err == nil {
					err = c.(interface{ CloseWrite() error }).CloseWrite()
				}
				errc <- err
			}()
			got, err := io.ReadAll(c)
			if werr := <-errc; werr != nil || err != nil || sha256.Sum256(got) != want {
				tcpBad.Add(1)
				if tcpBad.Load() == 1 {
					lp := uint16(c.LocalAddr().(*net.TCPAddr).Port)
					t.Logf("first bad flow (client port %d):\n  stack side: %s\n  peer side:  %s\nflow goroutines:\n%s",
						lp, endpointInfo(ns.s, lp, false), endpointInfo(peer.stack, lp, true), flowStacks())
				}
				if tcpBad.Load() <= 3 {
					t.Errorf("flow %d: write=%v read=%v got %d bytes want %d", i, werr, err, len(got), len(payload))
				}
				return
			}
			bytesMoved.Add(int64(2 * len(payload)))
		}(i, c)
	}

	// UDP, concurrently with the TCP transfers: each flow does request/
	// response exchanges, retrying on loss, and checks every reply.
	var udpBad atomic.Int64
	udpConns := make([]net.Conn, udpFlows)
	for i := range udpConns {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)}), 4433)
			c, err := peer.dialUDP(dst)
			if err != nil {
				udpBad.Add(1)
				return
			}
			udpConns[i] = c
			buf := make([]byte, 2048)
			for seq := 0; seq < 5; seq++ {
				msg := make([]byte, 64+(i*7+seq*131)%1200)
				binary.BigEndian.PutUint32(msg, uint32(i))
				binary.BigEndian.PutUint32(msg[4:], uint32(seq))
				for j := 8; j < len(msg); j++ {
					msg[j] = byte(i + seq + j)
				}
				ok := false
				for try := 0; try < 20 && !ok; try++ {
					if _, err := c.Write(msg); err != nil {
						break
					}
					_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					for {
						n, err := c.Read(buf)
						if err != nil {
							break // timeout: retransmit
						}
						if bytes.Equal(buf[:n], msg) {
							ok = true
							break
						}
						// A late duplicate of an earlier exchange; keep reading.
						if n < 8 || binary.BigEndian.Uint32(buf) != uint32(i) {
							udpBad.Add(1) // another flow's datagram: a demux bug
							return
						}
					}
				}
				if !ok {
					udpBad.Add(1)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)
	for name, st := range map[string]*gvstack.Stack{"stack": ns.s, "peer": peer.stack} {
		s := st.Stats()
		t.Logf("%s: tcp retransmits=%d timeouts=%d send-errors=%d; link tx-queue-full drops=%d",
			name, s.TCP.Retransmits.Value(), s.TCP.Timeouts.Value(), s.TCP.SegmentSendErrors.Value(),
			s.NICs.TxPacketsDroppedNoBufferSpace.Value())
	}
	if n := tcpBad.Load(); n > 0 {
		t.Errorf("%d of %d TCP flows were not byte-exact", n, tcpFlows)
	}
	if n := udpBad.Load(); n > 0 {
		t.Errorf("%d of %d UDP flows failed or saw foreign datagrams", n, udpFlows)
	}
	t.Logf("TCP: %.1f MiB echoed over %d flows in %s; UDP: %d flows x 5 exchanges",
		float64(bytesMoved.Load())/(1<<20), tcpFlows, elapsed.Round(time.Millisecond), udpFlows)

	// Phase 3: close everything; the stack must return to zero flows.
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
	for _, c := range udpConns {
		if c != nil {
			_ = c.Close()
		}
	}
	reclaimed := func() bool {
		return ns.Stats().ActiveFlows == 0 && ns.tcpFlows.Load() == 0 && ns.udpFlows.Load() == 0
	}
	for deadline := time.Now().Add(5 * time.Minute); !reclaimed() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !reclaimed() {
		t.Errorf("flows not reclaimed: %+v tcp=%d udp=%d\n%s", ns.Stats(), ns.tcpFlows.Load(), ns.udpFlows.Load(), flowStacks())
		return
	}
	st := ns.Stats()
	t.Logf("stack stats: %+v (outbound queue drops: %d)", st, st.DroppedOutbound)
	if st.RejectedFlows != 0 {
		t.Errorf("%d flows rejected; the caps should not have been reached", st.RejectedFlows)
	}

	if err := ns.Close(); err != nil {
		t.Fatal(err)
	}
	peer.cancel()
	peer.ep.Close()
	peer.stack.Close()
	var g int
	var heap uint64
	ok := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		g, heap = settleNS(200 * time.Millisecond)
		if g <= baseG+10 {
			ok = true
			break
		}
	}
	t.Logf("goroutines: baseline %d, after close %d; heap: baseline %.1f MiB, after %.1f MiB",
		baseG, g, float64(baseHeap)/(1<<20), float64(heap)/(1<<20))
	if !ok {
		buf := make([]byte, 1<<20)
		t.Fatalf("goroutines did not return to baseline (%d -> %d):\n%s", baseG, g, buf[:runtime.Stack(buf, true)])
	}
	if heap > baseHeap+32<<20 {
		t.Errorf("heap after close %.1f MiB, baseline %.1f MiB", float64(heap)/(1<<20), float64(baseHeap)/(1<<20))
	}
	_ = fmt.Sprint
}

// flowStacks returns the stacks of goroutines inside this package's flow
// code, which is where a stuck flow shows what it is blocked on.
func flowStacks() string {
	buf := make([]byte, 8<<20)
	all := string(buf[:runtime.Stack(buf, true)])
	var out []string
	for _, g := range strings.Split(all, "\n\n") {
		if strings.Contains(g, "netstack.(*Stack).splice") || strings.Contains(g, "netstack.(*Stack).proxyUDP") {
			out = append(out, g)
		}
		if len(out) >= 12 {
			break
		}
	}
	return strings.Join(out, "\n\n")
}

// endpointInfo describes the TCP endpoint for one flow, found by the app-side
// port: the remote port on the Stack under test, the local port on the peer.
func endpointInfo(s *gvstack.Stack, port uint16, local bool) string {
	for _, tep := range s.RegisteredEndpoints() {
		ep, ok := tep.(tcpip.Endpoint)
		if !ok {
			continue
		}
		info, err := ep.GetRemoteAddress()
		laddr, lerr := ep.GetLocalAddress()
		if err != nil || lerr != nil {
			continue
		}
		if (local && laddr.Port != port) || (!local && info.Port != port) {
			continue
		}
		var ti tcpip.TCPInfoOption
		_ = ep.GetSockOpt(&ti)
		st, _ := ep.Stats().(*tcp.Stats)
		var ss string
		if st != nil {
			ss = fmt.Sprintf("rx=%d tx=%d rcvbufOverflow=%d segQueueDropped=%d closedRcv=%d csum=%d retrans=%d timeouts=%d fastRetrans=%d sendFail=%d",
				st.SegmentsReceived.Value(), st.SegmentsSent.Value(),
				st.ReceiveErrors.ReceiveBufferOverflow.Value(), st.ReceiveErrors.SegmentQueueDropped.Value(),
				st.ReceiveErrors.ClosedReceiver.Value(), st.ReceiveErrors.ChecksumErrors.Value(),
				st.SendErrors.Retransmits.Value(), st.SendErrors.Timeouts.Value(), st.SendErrors.FastRetransmit.Value(),
				st.SendErrors.SegmentSendToNetworkFailed.Value())
		}
		return fmt.Sprintf("state=%v rtt=%v rto=%v cwnd=%d ssthresh=%d cc=%v %s rcvbuf=%d sndbuf=%d",
			tcp.EndpointState(ti.State), ti.RTT, ti.RTO, ti.SndCwnd, ti.SndSsthresh, ti.CcState, ss,
			ep.SocketOptions().GetReceiveBufferSize(), ep.SocketOptions().GetSendBufferSize())
	}
	return "endpoint not found"
}

// TestSoakNetstackLossyLink runs concurrent echo flows over a link that drops
// a fixed fraction of packets in both directions, and requires every flow to
// finish byte-exact: TCP on both sides of the stack must recover from loss
// rather than stall.
func TestSoakNetstackLossyLink(t *testing.T) {
	for _, loss := range []float64{0.02, 0.10} {
		t.Run(fmt.Sprintf("loss=%.0f%%", loss*100), func(t *testing.T) { lossySoak(t, loss) })
	}
}

func lossySoak(t *testing.T, loss float64) {
	const flows = 200
	dialer := newFakeDialer()
	dialer.dialled = make(chan netip.AddrPort)
	dialer.onTCP = rawEchoServer(t)
	ns := newTestStack(t, Config{Dialer: dialer})
	peer := newLossyTestPeer(t, tunnelAddr, testMTU, ns, loss)
	flowDeadline := 8 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("FLOWDEADLINE")); err == nil {
		flowDeadline = d
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	var bad atomic.Int64
	start := time.Now()
	for i := 0; i < flows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := peer.dialTCP(ctx, netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 0, byte(i)}), 443))
			if err != nil {
				bad.Add(1)
				t.Errorf("flow %d: dial: %v", i, err)
				return
			}
			defer c.Close()
			rng := rand.New(rand.NewSource(int64(i)))
			payload := make([]byte, 1+rng.Intn(48<<10))
			rng.Read(payload)
			_ = c.SetDeadline(time.Now().Add(flowDeadline))
			go func() {
				_, _ = c.Write(payload)
				_ = c.(interface{ CloseWrite() error }).CloseWrite()
			}()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, payload) {
				bad.Add(1)
				lp := uint16(c.LocalAddr().(*net.TCPAddr).Port)
				t.Errorf("flow %d: %v, got %d/%d bytes after %s\n  stack: %s\n  peer:  %s", i, err, len(got), len(payload),
					time.Since(start).Round(time.Second), endpointInfo(ns.s, lp, false), endpointInfo(peer.stack, lp, true))
			}
		}(i)
	}
	wg.Wait()
	t.Logf("%d flows over a %.0f%%-loss link in %s, %d failed", flows, loss*100, time.Since(start).Round(time.Millisecond), bad.Load())
}

// TestSoakNetstackLossyDownload is the download-direction counterpart of
// TestSoakNetstackLossyLink: the exit side sends a body and closes, so the
// Stack under test is the TCP sender towards the app, including the FIN that
// ends the body. Every body must arrive complete and terminated.
func TestSoakNetstackLossyDownload(t *testing.T) {
	const flows = 200
	const loss = 0.10
	dialer := newFakeDialer()
	dialer.dialled = make(chan netip.AddrPort)
	dialer.onTCP = loopbackServer(t, func(c net.Conn) {
		defer c.Close()
		var hdr [4]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i * 7)
		}
		_, _ = c.Write(body)
	})
	ns := newTestStack(t, Config{Dialer: dialer})
	if os.Getenv("STACKRACK") != "" {
		// Reproduce the gVisor RACK-TLP stall that configureTCP avoids.
		r := tcpip.TCPRACKLossDetection
		if err := ns.s.SetTransportProtocolOption(tcp.ProtocolNumber, &r); err != nil {
			t.Fatal(err)
		}
	}
	peer := newLossyTestPeer(t, tunnelAddr, testMTU, ns, loss)
	flowDeadline := 8 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("FLOWDEADLINE")); err == nil {
		flowDeadline = d
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var wg sync.WaitGroup
	var bad atomic.Int64
	start := time.Now()
	for i := 0; i < flows; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := peer.dialTCP(ctx, netip.AddrPortFrom(netip.AddrFrom4([4]byte{93, 184, 1, byte(i)}), 80))
			if err != nil {
				bad.Add(1)
				t.Errorf("flow %d: dial: %v", i, err)
				return
			}
			defer c.Close()
			size := 1 + (i*7919)%(64<<10)
			_ = c.SetDeadline(time.Now().Add(flowDeadline))
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], uint32(size))
			if _, err := c.Write(hdr[:]); err != nil {
				bad.Add(1)
				return
			}
			got, err := io.ReadAll(c)
			ok := err == nil && len(got) == size
			for j := 0; ok && j < size; j++ {
				ok = got[j] == byte(j*7)
			}
			if !ok {
				bad.Add(1)
				lp := uint16(c.LocalAddr().(*net.TCPAddr).Port)
				t.Errorf("flow %d: %v, got %d/%d bytes after %s\n  stack: %s\n  peer:  %s", i, err, len(got), size,
					time.Since(start).Round(time.Second), endpointInfo(ns.s, lp, false), endpointInfo(peer.stack, lp, true))
			}
		}(i)
	}
	wg.Wait()
	t.Logf("%d downloads over a %.0f%%-loss link in %s, %d failed", flows, loss*100, time.Since(start).Round(time.Millisecond), bad.Load())
}
