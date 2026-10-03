package engine

import (
	"encoding/binary"
	"math/rand"
	"runtime"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport"
)

// hostilePackets returns a deterministic corpus of malformed, fragmented and
// oversized packets: what a buggy or malicious app on the device can write
// into the tunnel.
func hostilePackets(n int) [][]byte {
	rng := rand.New(rand.NewSource(1))
	valid := [][]byte{ipv4UDPPacket("hostile"), ipv4TCPSyn(1234)}
	var out [][]byte
	out = append(out,
		nil, []byte{}, []byte{0x45}, []byte{0x60}, []byte{0xff, 0xff, 0xff, 0xff},
		make([]byte, 20),                          // IPv4 header of zeros
		make([]byte, 65535),                       // far over the MTU
		make([]byte, testMTU+1),                   // one over
		append([]byte{0x46}, make([]byte, 59)...), // IHL 6 with options of zeros
	)
	// Header fields lying about the packet.
	for _, v := range valid {
		p := append([]byte(nil), v...)
		binary.BigEndian.PutUint16(p[2:4], 0xffff) // total length > actual
		out = append(out, p)
		p = append([]byte(nil), v...)
		binary.BigEndian.PutUint16(p[2:4], 10) // total length < header
		out = append(out, p)
		p = append([]byte(nil), v...)
		p[0] = 0x4f // IHL 15: options run past the packet
		out = append(out, p)
		p = append([]byte(nil), v...)
		binary.BigEndian.PutUint16(p[6:8], 0x2000) // first fragment
		out = append(out, p)
		p = append([]byte(nil), v...)
		binary.BigEndian.PutUint16(p[6:8], 0x1fff) // last-offset fragment
		out = append(out, p)
		p = append([]byte(nil), v...)
		p[9] = 47 // GRE: unsupported protocol
		out = append(out, p)
		p = append([]byte(nil), v...)
		p[20+12] = 0xf0 // TCP data offset 15 / UDP length garbage
		out = append(out, p)
		// IPv6 header with a chain of hop-by-hop extension headers.
		v6 := make([]byte, 40+8*16)
		v6[0] = 0x60
		binary.BigEndian.PutUint16(v6[4:6], uint16(8*16))
		v6[6] = 0 // hop-by-hop
		for i := 0; i < 16; i++ {
			v6[40+8*i] = 0 // next header: hop-by-hop again
		}
		out = append(out, v6)
	}
	// Random mutations of valid packets.
	for len(out) < n {
		v := valid[rng.Intn(len(valid))]
		p := append([]byte(nil), v...)
		switch rng.Intn(4) {
		case 0:
			for k := 0; k < 1+rng.Intn(8); k++ {
				p[rng.Intn(len(p))] ^= byte(1 << rng.Intn(8))
			}
		case 1:
			p = p[:rng.Intn(len(p))]
		case 2:
			p = append(p, make([]byte, rng.Intn(2000))...)
		case 3:
			p = make([]byte, rng.Intn(1600))
			rng.Read(p)
			if len(p) > 0 {
				p[0] = []byte{0x45, 0x60}[rng.Intn(2)]
			}
		}
		out = append(out, p)
	}
	return out
}

// TestHostilePacketsDoNotDisruptEngine pushes a corpus of malformed,
// fragmented and oversized packets through both data-path shapes. None may
// panic, fail the session or leak, and well-formed traffic must keep flowing
// afterwards: one misbehaving app must not take the tunnel down for the rest.
func TestHostilePacketsDoNotDisruptEngine(t *testing.T) {
	corpus := hostilePackets(3000)
	nonEmpty := 0
	for _, p := range corpus {
		if len(p) > 0 {
			nonEmpty++ // a zero-length read is skipped, not counted
		}
	}
	for _, kind := range []string{"packet", "stream"} {
		t.Run(kind, func(t *testing.T) {
			runtime.GC()
			baseG := runtime.NumGoroutine()

			tun := newFakeTun(testMTU)
			pipe := newFakePipe("wg")
			dialer := newFakeDialer("ss")
			e := newTestEngine(t, tun, Config{}, func() []transport.Transport {
				if kind == "packet" {
					return []transport.Transport{pipe}
				}
				return []transport.Transport{dialer}
			})
			if err := e.Start(); err != nil {
				t.Fatal(err)
			}
			if !waitFor(3*time.Second, func() bool { return e.State() == StateConnected }) {
				t.Fatal("never connected")
			}
			go func() { // drain both sinks
				for {
					select {
					case <-pipe.written:
					case <-tun.inbound:
					case <-tun.closed:
						return
					}
				}
			}()
			for _, p := range corpus {
				tun.send(p)
				if kind == "packet" {
					pipe.deliver(p) // hostile bytes from the peer side too
				}
			}
			if !waitFor(10*time.Second, func() bool {
				return e.Stats().PacketsOut >= uint64(nonEmpty)
			}) {
				t.Fatalf("engine stopped reading the tunnel: %+v", e.Stats())
			}
			if e.State() != StateConnected || e.Stats().Reconnects != 0 {
				t.Fatalf("hostile packets disrupted the session: state=%s reconnects=%d last=%s",
					e.State(), e.Stats().Reconnects, e.LastChange())
			}
			// Well-formed traffic still flows.
			before := e.Stats().PacketsOut
			tun.send(ipv4UDPPacket("still alive"))
			if !waitFor(3*time.Second, func() bool { return e.Stats().PacketsOut > before }) {
				t.Fatal("a valid packet after the corpus was not carried")
			}
			if err := e.Stop(); err != nil {
				t.Fatal(err)
			}
			var g int
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
				if g = runtime.NumGoroutine(); g <= baseG+3 {
					return
				}
			}
			t.Errorf("goroutines %d -> %d after Stop", baseG, g)
		})
	}
}
