package wireguard

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// virtualTUN is an in-memory implementation of wireguard-go's tun.Device.
//
// The obvious way to use wireguard-go on mobile is to hand it the real tunnel
// file descriptor and let it own the data path. This engine deliberately does
// not do that. Instead wireguard-go is given this fake device, and the engine
// keeps the real fd for itself.
//
// That inversion buys three things that matter:
//
//   - Transports become swappable at runtime. The racer can tear down a
//     WireGuard transport and bring up Shadowsocks without ever re-plumbing
//     the OS fd, which on Android means not re-establishing the VpnService
//     and not showing the user a reconnect.
//   - The DNS proxy and the MTU clamp sit *above* the transport, so they work
//     identically for every protocol instead of being reimplemented per
//     protocol.
//   - The whole WireGuard path becomes testable in a unit test with no TUN
//     device and no privileges, because both ends of the tunnel are just
//     channels. See TestTransportEndToEnd.
//
// The cost is one extra copy per packet in each direction. At mobile
// throughput that is not the bottleneck; the handshake and the radio are.
type virtualTUN struct {
	mtu    atomic.Int64
	events chan wgtun.Event

	// outbound carries packets from the engine into wireguard-go, which reads
	// them as if an application had just sent them. inbound carries decrypted
	// packets the other way.
	outbound chan []byte
	inbound  chan []byte

	closeOnce sync.Once
	closed    chan struct{}

	pool sync.Pool

	// Dropped counts packets discarded because a queue was full. See the
	// comment on enqueue for why dropping is the right policy.
	droppedInbound  atomic.Uint64
	droppedOutbound atomic.Uint64

	// firstUnanswered is the UnixNano time of the first outbound data packet
	// queued since the liveness monitor last saw the peer's rx counter move,
	// or 0 if there is none. Only engine packets pass through writeOutbound;
	// wireguard-go's own keepalives and handshakes never do, which is exactly
	// the distinction the monitor needs (see Transport.monitor).
	firstUnanswered atomic.Int64
}

// errTUNClosed is returned by the device once Close has been called.
var errTUNClosed = errors.New("wireguard: virtual tun closed")

const (
	// queueDepth is how many packets may be in flight in each direction. One
	// bandwidth-delay product on a mobile link is a few dozen packets; 256
	// absorbs a burst without letting a stalled reader accumulate seconds of
	// stale traffic.
	queueDepth = 256

	// maxPacketSize bounds a single packet, including room for the largest
	// MTU we will negotiate plus wireguard-go's write offset.
	maxPacketSize = 2048
)

func newVirtualTUN(mtu int) *virtualTUN {
	t := &virtualTUN{
		events:   make(chan wgtun.Event, 4),
		outbound: make(chan []byte, queueDepth),
		inbound:  make(chan []byte, queueDepth),
		closed:   make(chan struct{}),
	}
	t.mtu.Store(int64(mtu))
	t.pool.New = func() any {
		b := make([]byte, maxPacketSize)
		return &b
	}
	t.events <- wgtun.EventUp
	return t
}

// --- wireguard-go tun.Device implementation ---

// File has no meaning for a virtual device. wireguard-go only calls it on
// platforms that need the fd for routing table manipulation, which is not a
// path a mobile client takes.
func (t *virtualTUN) File() *os.File { return nil }

func (t *virtualTUN) Name() (string, error) { return "tunnelcore-virtual", nil }

func (t *virtualTUN) Events() <-chan wgtun.Event { return t.events }

func (t *virtualTUN) MTU() (int, error) {
	select {
	case <-t.closed:
		return 0, errTUNClosed
	default:
	}
	return int(t.mtu.Load()), nil
}

// setMTU updates the device MTU and notifies wireguard-go, which recomputes
// its own padding and keepalive sizing from it.
func (t *virtualTUN) setMTU(mtu int) {
	if int(t.mtu.Swap(int64(mtu))) == mtu {
		return
	}
	select {
	case t.events <- wgtun.EventMTUUpdate:
	default: // event channel full; wireguard-go will pick up the new MTU anyway
	}
}

// BatchSize is 1 because the queues hold one packet per element. Claiming a
// larger batch would make wireguard-go allocate bigger slices for no gain.
func (t *virtualTUN) BatchSize() int { return 1 }

// Read is called by wireguard-go to collect packets to encrypt. It blocks
// until at least one packet is available, then opportunistically drains more
// without blocking, because amortising the encryption worker's wakeup over a
// burst is most of what batching is for.
func (t *virtualTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	select {
	case <-t.closed:
		return 0, errTUNClosed
	case pkt, ok := <-t.outbound:
		if !ok {
			return 0, errTUNClosed
		}
		n := t.copyOut(bufs[0], sizes, 0, offset, pkt)
		count := 1
		for count < len(bufs) {
			select {
			case more, ok := <-t.outbound:
				if !ok {
					return count, nil
				}
				t.copyOut(bufs[count], sizes, count, offset, more)
				count++
			default:
				return count, nil
			}
		}
		_ = n
		return count, nil
	}
}

func (t *virtualTUN) copyOut(buf []byte, sizes []int, i, offset int, pkt []byte) int {
	n := copy(buf[offset:], pkt)
	sizes[i] = n
	t.release(pkt)
	return n
}

// Write is called by wireguard-go with freshly decrypted IP packets. The
// engine picks them up through ReadPacket.
func (t *virtualTUN) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, b := range bufs {
		if offset > len(b) {
			continue
		}
		pkt := b[offset:]
		if len(pkt) == 0 {
			continue
		}
		if err := t.enqueue(t.inbound, pkt, &t.droppedInbound); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func (t *virtualTUN) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// --- engine-facing side ---

// writeOutbound hands one outbound IP packet to wireguard-go.
func (t *virtualTUN) writeOutbound(p []byte) error {
	before := t.droppedOutbound.Load()
	if err := t.enqueue(t.outbound, p, &t.droppedOutbound); err != nil {
		return err
	}
	// A packet dropped here never reaches the peer, so it cannot be owed a
	// reply. The drop counter is the cheapest way to tell without changing
	// enqueue's contract; a concurrent drop can only make this undercount,
	// which errs towards not declaring a live peer dead.
	if t.droppedOutbound.Load() == before {
		t.firstUnanswered.CompareAndSwap(0, time.Now().UnixNano())
	}
	return nil
}

// readInbound blocks for one decrypted IP packet and copies it into b.
func (t *virtualTUN) readInbound(b []byte) (int, error) {
	select {
	case <-t.closed:
		return 0, errTUNClosed
	case pkt, ok := <-t.inbound:
		if !ok {
			return 0, errTUNClosed
		}
		n := copy(b, pkt)
		t.release(pkt)
		return n, nil
	}
}

// enqueue copies p into a pooled buffer and pushes it onto q.
//
// When q is full the packet is dropped and counted, rather than blocking. This
// is the correct policy for a tunnel and worth being explicit about: the
// tunnel is a datagram path, so a drop is exactly the signal the endpoints'
// own congestion control is built to handle, and TCP will retransmit. Blocking
// instead would stall whichever worker called in — wireguard-go's receive
// worker, or the engine's tunnel reader — and convert a transient queue
// overrun into a stall of every other flow sharing that worker. The drop
// counters are exported through metrics so that a tunnel that is quietly
// shedding traffic is visible rather than merely slow.
func (t *virtualTUN) enqueue(q chan []byte, p []byte, dropped *atomic.Uint64) error {
	select {
	case <-t.closed:
		return errTUNClosed
	default:
	}
	if len(p) > maxPacketSize {
		dropped.Add(1)
		return nil
	}
	buf := t.acquire(len(p))
	copy(buf, p)
	select {
	case q <- buf:
		return nil
	case <-t.closed:
		t.release(buf)
		return errTUNClosed
	default:
		t.release(buf)
		dropped.Add(1)
		return nil
	}
}

func (t *virtualTUN) acquire(n int) []byte {
	bp := t.pool.Get().(*[]byte)
	return (*bp)[:n]
}

func (t *virtualTUN) release(b []byte) {
	if cap(b) < maxPacketSize {
		return
	}
	full := b[:maxPacketSize]
	t.pool.Put(&full)
}

var _ wgtun.Device = (*virtualTUN)(nil)
