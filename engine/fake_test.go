package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport"
)

// fakeTun is an in-memory TunDevice.
//
// Having this behind an interface is what makes the engine's interesting
// behaviour testable at all: a reconnect, a network handover and a transport
// dying mid-session cannot be provoked on demand against a real tunnel
// interface, and all three are exactly where the bugs are.
type fakeTun struct {
	mtu int

	// outbound carries packets the "OS" is sending into the tunnel.
	outbound chan []byte
	// inbound records packets the engine wrote back to the "OS".
	inbound chan []byte

	closeOnce sync.Once
	closed    chan struct{}

	reads     atomic.Int64
	writes    atomic.Int64
	writeFail atomic.Bool
}

func newFakeTun(mtu int) *fakeTun {
	return &fakeTun{
		mtu:      mtu,
		outbound: make(chan []byte, 256),
		inbound:  make(chan []byte, 256),
		closed:   make(chan struct{}),
	}
}

func (f *fakeTun) ReadPacket(b []byte) (int, error) {
	select {
	case <-f.closed:
		return 0, net.ErrClosed
	case p := <-f.outbound:
		f.reads.Add(1)
		return copy(b, p), nil
	}
}

func (f *fakeTun) WritePacket(p []byte) error {
	select {
	case <-f.closed:
		return net.ErrClosed
	default:
	}
	if f.writeFail.Load() {
		return errors.New("fakeTun: write failed")
	}
	f.writes.Add(1)
	select {
	case f.inbound <- append([]byte(nil), p...):
	default: // test is not draining; drop rather than block the engine
	}
	return nil
}

func (f *fakeTun) MTU() int { return f.mtu }

func (f *fakeTun) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

// send queues a packet as though an app had written it into the tunnel.
func (f *fakeTun) send(p []byte) {
	select {
	case f.outbound <- append([]byte(nil), p...):
	case <-f.closed:
	}
}

// --- fake transports ---

// fakePipe is a PacketPipe whose two directions are channels.
type fakePipe struct {
	name    string
	mtu     int
	upErr   error
	upDelay time.Duration
	// dieAfterUp, if positive, makes the pipe close itself that long after a
	// successful Up: a transport that handshakes and then immediately dies,
	// which is what a flapping server looks like from the client.
	dieAfterUp time.Duration

	// written records packets the engine sent through this transport.
	written chan []byte
	// toTun queues packets the transport "received" from its peer.
	toTun chan []byte

	mu     sync.Mutex
	up     bool
	closed bool

	closeOnce sync.Once
	done      chan struct{}

	upCalls    atomic.Int32
	closeCalls atomic.Int32
	// writeErr, when set, makes WritePacket fail, standing in for a transport
	// that has died under the engine.
	writeErr atomic.Pointer[error]
}

func newFakePipe(name string) *fakePipe {
	return &fakePipe{
		name:    name,
		mtu:     1420,
		written: make(chan []byte, 256),
		toTun:   make(chan []byte, 256),
		done:    make(chan struct{}),
	}
}

func (p *fakePipe) Name() string         { return p.name }
func (p *fakePipe) Kind() transport.Kind { return transport.KindPacket }
func (p *fakePipe) MTU() int             { return p.mtu }

func (p *fakePipe) Up(ctx context.Context) error {
	p.upCalls.Add(1)
	if p.upDelay > 0 {
		select {
		case <-time.After(p.upDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if p.upErr != nil {
		return p.upErr
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return transport.ErrClosed
	}
	p.up = true
	if p.dieAfterUp > 0 {
		time.AfterFunc(p.dieAfterUp, func() { _ = p.Close() })
	}
	return nil
}

func (p *fakePipe) WritePacket(b []byte) error {
	if e := p.writeErr.Load(); e != nil {
		return *e
	}
	p.mu.Lock()
	up, closed := p.up, p.closed
	p.mu.Unlock()
	if closed {
		return transport.ErrClosed
	}
	if !up {
		return transport.ErrNotReady
	}
	select {
	case p.written <- append([]byte(nil), b...):
	default:
	}
	return nil
}

func (p *fakePipe) ReadPacket(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, transport.ErrClosed
	case pkt := <-p.toTun:
		return copy(b, pkt), nil
	}
}

func (p *fakePipe) Close() error {
	p.closeCalls.Add(1)
	p.mu.Lock()
	p.up = false
	p.closed = true
	p.mu.Unlock()
	p.closeOnce.Do(func() { close(p.done) })
	return nil
}

// deliver queues a packet as though it arrived from the transport's peer.
func (p *fakePipe) deliver(b []byte) {
	select {
	case p.toTun <- append([]byte(nil), b...):
	case <-p.done:
	}
}

func (p *fakePipe) failWrites(err error) { p.writeErr.Store(&err) }

var _ transport.PacketPipe = (*fakePipe)(nil)

// fakeDialer is a minimal StreamDialer, used to exercise the stream data path.
type fakeDialer struct {
	name   string
	upErr  error
	closed atomic.Bool

	dialed atomic.Int32
	// dialErr, when set, makes DialTCP fail, standing in for a proxy server
	// that has gone away while the transport object is still open.
	dialErr atomic.Pointer[error]
}

func (d *fakeDialer) failDials(err error) { d.dialErr.Store(&err) }

func newFakeDialer(name string) *fakeDialer { return &fakeDialer{name: name} }

func (d *fakeDialer) Name() string         { return d.name }
func (d *fakeDialer) Kind() transport.Kind { return transport.KindStream }

func (d *fakeDialer) Up(context.Context) error {
	if d.upErr != nil {
		return d.upErr
	}
	return nil
}

func (d *fakeDialer) Close() error {
	d.closed.Store(true)
	return nil
}

func (d *fakeDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	d.dialed.Add(1)
	if d.closed.Load() {
		return nil, transport.ErrClosed
	}
	if e := d.dialErr.Load(); e != nil {
		return nil, *e
	}
	// A real loopback connection, so the half-close contract on
	// StreamDialer.DialTCP is honoured rather than quietly violated the way
	// net.Pipe would.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	var dl net.Dialer
	return dl.DialContext(ctx, "tcp", ln.Addr().String())
}

func (d *fakeDialer) DialUDP(context.Context, netip.AddrPort) (transport.UDPSession, error) {
	return nil, transport.ErrUnsupportedFlow
}

var _ transport.StreamDialer = (*fakeDialer)(nil)

// --- helpers ---

// ipv4UDPPacket builds a small, valid packet for driving the data path.
func ipv4UDPPacket(payload string) []byte {
	buf := make([]byte, 1500)
	p, err := packet.BuildUDP(buf,
		netip.MustParseAddrPort("10.9.0.2:40000"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		[]byte(payload))
	if err != nil {
		panic(err)
	}
	return p
}

// ipv4TCPSyn builds a TCP SYN from the tunnel address, which the userspace
// stack answers by asking the stream transport to dial. Each source port is a
// distinct flow, and so a distinct dial.
func ipv4TCPSyn(srcPort uint16) []byte {
	const ipLen, tcpLen = 20, 20
	b := make([]byte, ipLen+tcpLen)
	src := netip.MustParseAddr("10.9.0.2").As4()
	dst := netip.MustParseAddr("93.184.216.34").As4()

	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], ipLen+tcpLen)
	b[8] = 64
	b[9] = 6 // TCP
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:12], packet.Fold(packet.Checksum(b[:ipLen], 0)))

	tcp := b[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 1000) // ISN
	tcp[12] = 5 << 4                           // data offset
	tcp[13] = 0x02                             // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	var pseudo [12]byte
	copy(pseudo[0:4], src[:])
	copy(pseudo[4:8], dst[:])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], tcpLen)
	binary.BigEndian.PutUint16(tcp[16:18], packet.Fold(packet.Checksum(tcp, packet.Checksum(pseudo[:], 0))))
	return b
}

// waitFor polls cond until it holds or the deadline passes.
//
// Polling rather than a fixed sleep: the engine's transitions are driven by
// goroutine scheduling, and a sleep long enough to be reliable on a loaded CI
// box makes the suite slow for no benefit.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}
