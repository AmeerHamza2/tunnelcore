package netstack

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport"
)

var (
	fuzzStackOnce sync.Once
	fuzzStack     *Stack
)

// echoDNS answers every query with the query itself, so fuzzed UDP/53 and
// TCP/53 payloads reach a handler and the reply path is exercised too.
type echoDNS struct{}

func (echoDNS) HandleQuery(_ context.Context, _ netip.AddrPort, q []byte) ([]byte, bool, error) {
	return q, true, nil
}

// sharedFuzzStack is one Stack for the whole fuzz run: building a gVisor stack
// per input would make the target too slow to find anything. Flow state
// carrying over between inputs is fine (and closer to reality).
func sharedFuzzStack() *Stack {
	fuzzStackOnce.Do(func() {
		dialer := newFakeDialer()
		dialer.dialled = make(chan netip.AddrPort)
		dialer.onTCP = func(context.Context, netip.AddrPort) (net.Conn, error) {
			return nil, transport.ErrUnsupportedFlow
		}
		dialer.onUDP = func(context.Context, netip.AddrPort) (transport.UDPSession, error) {
			return newFakeUDPSession(), nil
		}
		ns, err := New(Config{
			Dialer: dialer, MTU: testMTU, DNS: echoDNS{},
			LocalAddresses:    []netip.Prefix{netip.PrefixFrom(tunnelAddr, 32), netip.MustParsePrefix("fd00::2/128")},
			udpIdleTimeout:    50 * time.Millisecond,
			dnsUDPIdleTimeout: 50 * time.Millisecond,
			dnsTCPIdleTimeout: 50 * time.Millisecond,
		})
		if err != nil {
			panic(err)
		}
		go func() {
			buf := make([]byte, testMTU)
			for {
				if _, err := ns.ReadOutbound(buf); err != nil {
					return
				}
			}
		}()
		fuzzStack = ns
	})
	return fuzzStack
}

func fuzzSeedPackets() [][]byte {
	buf := make([]byte, 1500)
	src := netip.AddrPortFrom(tunnelAddr, 40000)
	var seeds [][]byte
	add := func(p []byte, err error) {
		if err == nil {
			seeds = append(seeds, append([]byte(nil), p...))
		}
	}
	add(packet.BuildUDP(buf, src, remoteDNS, []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'f', 'o', 'o', 0, 0, 1, 0, 1}))
	add(packet.BuildUDP(buf, src, netip.MustParseAddrPort("8.8.8.8:443"), []byte("quic")))
	add(packet.BuildUDP(buf, netip.MustParseAddrPort("[fd00::2]:5000"), netip.MustParseAddrPort("[2001:db8::1]:53"), []byte("v6")))
	syn := tcpSyn(src, remoteHTTP)
	seeds = append(seeds, syn)
	dnsSyn := tcpSyn(src, netip.AddrPortFrom(remoteDNS.Addr(), 53))
	seeds = append(seeds, dnsSyn)
	// A first fragment (MF set) and a non-first fragment.
	frag := append([]byte(nil), seeds[1]...)
	binary.BigEndian.PutUint16(frag[6:8], 0x2000)
	seeds = append(seeds, frag)
	frag2 := append([]byte(nil), seeds[1]...)
	binary.BigEndian.PutUint16(frag2[6:8], 0x0001)
	seeds = append(seeds, frag2)
	seeds = append(seeds, []byte{0x45}, []byte{0x60, 0, 0, 0}, []byte{})
	return seeds
}

// FuzzStackDeliverInbound feeds arbitrary bytes into the userspace stack as if
// an app had written them into the tunnel. The engine hands the stack every
// packet the OS gives it, so this is the device-side attack surface: it must
// never panic, whatever the IP, TCP, UDP or DNS framing.
func FuzzStackDeliverInbound(f *testing.F) {
	for _, s := range fuzzSeedPackets() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p []byte) {
		ns := sharedFuzzStack()
		_ = ns.DeliverInbound(p)
	})
}
