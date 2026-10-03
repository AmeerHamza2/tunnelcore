// Package wireguard implements a KindPacket transport over wireguard-go.
//
// The engine owns the OS tunnel file descriptor; this package gives
// wireguard-go an in-memory device instead (see virtualtun.go for why). The
// result is a transport that takes raw IP packets in and gives raw IP packets
// back, with no TUN device and no privileges required to exercise it.
package wireguard

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	wgdevice "golang.zx2c4.com/wireguard/device"

	"github.com/ameerhamza2/tunnelcore/transport"
)

// Transport is a WireGuard packet transport.
type Transport struct {
	cfg Config

	mu     sync.Mutex
	dev    *wgdevice.Device
	vtun   *virtualTUN
	up     bool
	closed bool

	// upping is non-nil while an Up is building the device and waiting for
	// the handshake, and is closed when that Up returns. A concurrent Up
	// waits on it instead of building a second device: without it, the
	// second call saw !up, created another device and overwrote dev/vtun,
	// leaking the first one's sockets and goroutines.
	upping chan struct{}

	// stopMonitor ends the liveness monitor; nil when none is running.
	stopMonitor chan struct{}

	// closeCause, if set, is why the transport closed itself. ReadPacket and
	// WritePacket return it instead of the bare transport.ErrClosed so the
	// engine (and its logs) can tell a dead peer from an ordinary teardown.
	closeCause error

	// devicesCreated counts wireguard-go devices built by Up. It exists for
	// the concurrency regression test: more than one per transport is a
	// leaked device.
	devicesCreated int

	logLevel int
}

// ErrPeerUnresponsive means the peer stopped answering: data was sent and
// nothing at all came back within Config.DeadPeerTimeout. It is always
// returned wrapped together with transport.ErrClosed, because the transport
// has closed itself and the engine's existing "closed means re-race" handling
// is the right response.
var ErrPeerUnresponsive = errors.New("wireguard: peer unresponsive")

// New creates a WireGuard transport from cfg. It does not perform any
// network I/O; call Up for that.
func New(cfg Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Transport{cfg: cfg, logLevel: wgdevice.LogLevelError}, nil
}

// SetVerbose turns on wireguard-go's verbose logging.
//
// This is for the harness CLI and for reproducing handshake failures, never
// for a shipped build: at verbose level wireguard-go logs peer public keys and
// endpoint addresses, which is user-identifying information that has no
// business in a privacy product's log sink.
func (t *Transport) SetVerbose(v bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v {
		t.logLevel = wgdevice.LogLevelVerbose
	} else {
		t.logLevel = wgdevice.LogLevelError
	}
}

func (t *Transport) Name() string         { return t.cfg.name() }
func (t *Transport) Kind() transport.Kind { return transport.KindPacket }
func (t *Transport) MTU() int             { return t.cfg.mtu() }

// Up brings up the WireGuard device and blocks until the Noise handshake with
// the peer has completed, or ctx expires.
//
// Waiting for the handshake rather than returning as soon as the device is
// configured is the whole point. A WireGuard device configures successfully
// against an endpoint that is firewalled, blackholed or simply wrong, and
// reports nothing: packets go out, none come back. If Up returned early, the
// racer could not tell a working server from a blocked one, and the user would
// see "Connected" over a tunnel that carries nothing. Connection success rate
// is only a meaningful metric if "success" means a completed handshake.
func (t *Transport) Up(ctx context.Context) error {
	t.mu.Lock()
	for {
		if t.closed {
			t.mu.Unlock()
			return transport.ErrClosed
		}
		if t.up {
			t.mu.Unlock()
			return nil
		}
		if t.upping == nil {
			break
		}
		// Another Up is in flight. Wait for it and then re-evaluate rather
		// than trusting its result: it may have failed (and closed the
		// transport), succeeded, or been overtaken by a Close.
		wait := t.upping
		t.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%w: %s did not respond", transport.ErrHandshakeTimeout, t.Name())
			}
			return ctx.Err()
		}
		t.mu.Lock()
	}
	done := make(chan struct{})
	t.upping = done
	defer func() {
		t.mu.Lock()
		t.upping = nil
		t.mu.Unlock()
		close(done)
	}()

	vtun := newVirtualTUN(t.cfg.mtu())
	logger := wgdevice.NewLogger(t.logLevel, "["+t.Name()+"] ")
	dev := wgdevice.NewDevice(vtun, newBind(t.cfg.Protect), logger)
	t.devicesCreated++

	if err := dev.IpcSet(t.cfg.uapi()); err != nil {
		dev.Close()
		t.mu.Unlock()
		// IpcSet echoes the configuration it could not parse, which would put
		// the private key into the error string. Replace the message rather
		// than wrapping it.
		return fmt.Errorf("wireguard: applying device configuration failed (%d-byte config rejected)",
			len(t.cfg.uapi()))
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		t.mu.Unlock()
		return fmt.Errorf("wireguard: bringing device up: %w", err)
	}

	t.dev = dev
	t.vtun = vtun
	t.mu.Unlock()

	if err := t.waitHandshake(ctx); err != nil {
		t.Close()
		return err
	}

	t.mu.Lock()
	// A Close that landed after the handshake was observed but before this
	// point has already torn the device down. Reporting success would hand
	// the racer a "winner" that is closed.
	if t.closed {
		t.mu.Unlock()
		return transport.ErrClosed
	}
	t.up = true
	if timeout := t.cfg.deadPeerTimeout(); timeout > 0 {
		stop := make(chan struct{})
		t.stopMonitor = stop
		go t.monitor(dev, vtun, timeout, stop)
	}
	t.mu.Unlock()
	return nil
}

// monitor closes the transport when the peer stops answering.
//
// Without it a dead or silently-blackholed peer leaves the engine
// "connected" forever: WireGuard has no notion of a session ending, so
// ReadPacket just blocks, writes succeed into the void, and the user sees a
// shield icon over a tunnel that carries nothing.
//
// The signal comes from WireGuard's own timer rules. A peer that receives an
// authenticated data packet must send something back — its own data, or a
// passive keepalive after KEEPALIVE_TIMEOUT (10s) — and the sender starts a
// new handshake after KEEPALIVE_TIMEOUT + REKEY_TIMEOUT (15s) of silence, to
// which a live peer also replies. So "data sent, and rx_bytes has not moved
// for DeadPeerTimeout since" is a reliable death certificate.
//
// The clock starts only at the first *data* packet after rx last moved:
// keepalives are not data, are never answered, and do not pass through
// virtualTUN, so an idle tunnel with persistent keepalive never trips.
func (t *Transport) monitor(dev *wgdevice.Device, vtun *virtualTUN, timeout time.Duration, stop <-chan struct{}) {
	// Poll at a fraction of the timeout so detection lands within ~20% of
	// it; one second is plenty for the 20s default and costs nothing.
	interval := timeout / 5
	if interval > time.Second {
		interval = time.Second
	}
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	lastRx, _ := peerRxBytes(dev)
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		// Only a packet sent before the counter was read can have been
		// answered by what the counter shows; one sent after must keep its
		// clock, or a send racing the poll would be forgotten.
		observed := time.Now().UnixNano()
		rx, ok := peerRxBytes(dev)
		if !ok {
			// The device is gone or unreadable, which only happens when it
			// is being closed; Close will stop us.
			continue
		}
		if rx != lastRx {
			lastRx = rx
			if f := vtun.firstUnanswered.Load(); f != 0 && f <= observed {
				vtun.firstUnanswered.CompareAndSwap(f, 0)
			}
			continue
		}
		first := vtun.firstUnanswered.Load()
		if first == 0 {
			continue
		}
		if silent := time.Since(time.Unix(0, first)); silent > timeout {
			t.closeWithCause(fmt.Errorf("%w: %w: %s sent nothing for %s after data was sent",
				transport.ErrClosed, ErrPeerUnresponsive, t.Name(), silent.Round(time.Millisecond)))
			return
		}
	}
}

// peerRxBytes reads the peer's received-byte counter from the device.
func peerRxBytes(dev *wgdevice.Device) (uint64, bool) {
	var sb strings.Builder
	if err := dev.IpcGetOperation(&sb); err != nil {
		return 0, false
	}
	for _, line := range strings.Split(sb.String(), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || k != "rx_bytes" {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	}
	return 0, false
}

const (
	// handshakePollInterval is how often Up checks whether a handshake has
	// landed.
	//
	// wireguard-go exposes no handshake-completion signal, so this polls
	// IpcGet. 50ms costs nothing next to a handshake RTT and keeps the racer's
	// resolution fine enough that two servers 100ms apart are reliably
	// ordered.
	handshakePollInterval = 50 * time.Millisecond

	// handshakeRetryInterval is how often Up re-initiates the handshake while
	// waiting.
	//
	// This exists because of a number that is right for WireGuard's own
	// purposes and wrong for ours: wireguard-go retries a lost handshake
	// initiation after RekeyTimeout, which is 5 seconds. On a server that is
	// the correct, conservative choice. On a phone it means a single dropped
	// UDP packet — entirely normal on a congested cell, and the common case in
	// the restrictive networks this engine targets — costs five seconds of
	// connect time, which is well past the point where a user force-quits the
	// app and tries a different server.
	//
	// Re-initiating every second instead bounds the cost of one lost packet to
	// roughly one second. The extra initiations are cheap (a handshake
	// initiation is 148 bytes) and harmless: WireGuard's handshake is designed
	// to tolerate repeats, and the peer discards an initiation it has already
	// answered.
	handshakeRetryInterval = time.Second
)

func (t *Transport) waitHandshake(ctx context.Context) error {
	poll := time.NewTicker(handshakePollInterval)
	defer poll.Stop()
	retry := time.NewTicker(handshakeRetryInterval)
	defer retry.Stop()

	// Initiate immediately rather than waiting for the first retry tick.
	//
	// WireGuard is lazy by design: a configured device sends nothing until it
	// has traffic for the peer. That is fine for a long-lived server but wrong
	// for a client that has to answer "is this server usable?" in bounded
	// time. Without an explicit initiation, Up would sit idle until either the
	// persistent-keepalive timer fired or the user's first packet arrived, and
	// the racer would score every candidate server identically at zero.
	t.initiateHandshake()

	for {
		ok, err := t.handshakeComplete()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%w: %s did not respond", transport.ErrHandshakeTimeout, t.Name())
			}
			return ctx.Err()
		case <-retry.C:
			t.initiateHandshake()
		case <-poll.C:
		}
	}
}

// initiateHandshake nudges wireguard-go into sending a handshake initiation by
// queueing a keepalive for the peer.
func (t *Transport) initiateHandshake() {
	t.mu.Lock()
	dev := t.dev
	t.mu.Unlock()
	if dev == nil {
		return
	}
	if peer := dev.LookupPeer(wgdevice.NoisePublicKey(t.cfg.PeerPublicKey)); peer != nil {
		peer.SendKeepalive()
	}
}

// handshakeComplete reports whether the peer has a non-zero last-handshake
// timestamp.
func (t *Transport) handshakeComplete() (bool, error) {
	t.mu.Lock()
	dev := t.dev
	t.mu.Unlock()
	if dev == nil {
		return false, transport.ErrClosed
	}

	var sb strings.Builder
	if err := dev.IpcGetOperation(&sb); err != nil {
		return false, fmt.Errorf("wireguard: reading device state: %w", err)
	}
	return hasHandshake(sb.String()), nil
}

// ListenPort reports the UDP port the device is actually bound to.
//
// With Config.ListenPort left at zero — which is what a client should do, see
// the comment there — the kernel picks an ephemeral port, and this is the only
// way to learn which. It returns 0 before the device exists.
//
// Beyond tests, this is what a support bundle needs: "which source port are we
// using" is the first question when diagnosing a carrier NAT that is dropping
// the tunnel, and the answer is otherwise invisible from inside the app.
func (t *Transport) ListenPort() int {
	t.mu.Lock()
	dev := t.dev
	t.mu.Unlock()
	if dev == nil {
		return 0
	}

	var sb strings.Builder
	if err := dev.IpcGetOperation(&sb); err != nil {
		return 0
	}
	for _, line := range strings.Split(sb.String(), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || k != "listen_port" {
			continue
		}
		port, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return port
	}
	return 0
}

// hasHandshake parses wireguard-go's IPC output for a completed handshake.
//
// The UAPI reports last_handshake_time_sec and last_handshake_time_nsec, both
// zero until the first handshake lands. Checking only the seconds field would
// miss a handshake that completed in the same second as the Unix epoch, which
// never happens in production but does happen in tests with a fake clock.
func hasHandshake(ipc string) bool {
	for _, line := range strings.Split(ipc, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "last_handshake_time_sec", "last_handshake_time_nsec":
			if v != "0" && v != "" {
				return true
			}
		}
	}
	return false
}

// WritePacket sends one outbound IP packet into the tunnel.
func (t *Transport) WritePacket(p []byte) error {
	t.mu.Lock()
	vtun, up, cause := t.vtun, t.up, t.closeCause
	t.mu.Unlock()
	if vtun == nil {
		if cause != nil {
			return cause
		}
		return transport.ErrClosed
	}
	if !up {
		return transport.ErrNotReady
	}
	return vtun.writeOutbound(p)
}

// ReadPacket blocks for one decrypted inbound IP packet.
//
// After the transport closes it returns transport.ErrClosed; if it closed
// itself because the peer went silent, the error also wraps
// ErrPeerUnresponsive.
func (t *Transport) ReadPacket(b []byte) (int, error) {
	t.mu.Lock()
	vtun := t.vtun
	t.mu.Unlock()
	if vtun == nil {
		return 0, t.closedErr()
	}
	n, err := vtun.readInbound(b)
	if errors.Is(err, errTUNClosed) {
		return 0, t.closedErr()
	}
	return n, err
}

// closedErr is the error for I/O on a closed transport: the recorded cause
// if the transport closed itself, plain ErrClosed otherwise.
func (t *Transport) closedErr() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closeCause != nil {
		return t.closeCause
	}
	return transport.ErrClosed
}

// SetMTU updates the tunnel MTU at runtime, which the engine does when path
// MTU discovery finds a smaller path than the one it assumed.
func (t *Transport) SetMTU(mtu int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg.MTU = mtu
	if t.vtun != nil {
		t.vtun.setMTU(mtu)
	}
}

// Stats reports counters useful for diagnosing a tunnel that is up but slow.
type Stats struct {
	DroppedInbound  uint64
	DroppedOutbound uint64
	HandshakeOK     bool
}

// Stats returns current transport counters.
func (t *Transport) Stats() Stats {
	t.mu.Lock()
	vtun := t.vtun
	t.mu.Unlock()
	if vtun == nil {
		return Stats{}
	}
	ok, _ := t.handshakeComplete()
	return Stats{
		DroppedInbound:  vtun.droppedInbound.Load(),
		DroppedOutbound: vtun.droppedOutbound.Load(),
		HandshakeOK:     ok,
	}
}

// Close tears down the device. It is safe to call concurrently with Up and
// more than once.
func (t *Transport) Close() error {
	return t.closeWithCause(nil)
}

// closeWithCause is Close, recording cause (if non-nil and the transport is
// not already closed) as what ReadPacket and WritePacket report from now on.
// The cause is stored before the device is torn down, so a reader woken by
// the teardown always sees it.
func (t *Transport) closeWithCause(cause error) error {
	t.mu.Lock()
	if cause != nil && !t.closed {
		t.closeCause = cause
	}
	dev, vtun := t.dev, t.vtun
	t.dev, t.vtun = nil, nil
	t.up = false
	t.closed = true
	if t.stopMonitor != nil {
		close(t.stopMonitor)
		t.stopMonitor = nil
	}
	t.mu.Unlock()

	if dev != nil {
		dev.Close()
	}
	if vtun != nil {
		_ = vtun.Close()
	}
	return nil
}

var (
	_ transport.Transport  = (*Transport)(nil)
	_ transport.PacketPipe = (*Transport)(nil)
)
