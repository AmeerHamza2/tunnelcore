package wireguard

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/ameerhamza2/tunnelcore/transport/protect"
)

// portReportingBind wraps wireguard-go's default UDP bind to fix the port it
// reports on hosts without IPv6.
//
// The upstream bug: StdNetBind.Open listens on udp4, then listens on udp6
// *with the same variable* holding the port, and on a host where IPv6 is
// unavailable the failed udp6 listen returns port 0 and overwrites the real
// one. The sockets are fine — traffic flows on the real port — but the device
// records listen_port=0, so UAPI, Transport.ListenPort and every support
// bundle report the wrong source port. IPv4-only hosts are not exotic: CI
// containers, some carrier-provisioned Android builds with IPv6 disabled, and
// any sandbox with the v6 stack turned off all hit it.
//
// The workaround is to never ask the bind to choose. When the caller wants an
// ephemeral port, this picks one itself from the IANA dynamic range, retries
// on collision, and, if the inner bind reports 0 back, returns the port it
// actually requested.
//
// Picking the port in-process rather than letting the kernel do it also keeps
// the privacy property Config.ListenPort documents: the source port is random
// per bind, so a device is not recognisable by it across reconnects.
//
// Cost: wireguard-go's netlink sticky-socket route listener only engages for
// an unwrapped *conn.StdNetBind. Sticky sockets are compiled out on Android
// and do not exist on iOS (conn.StdNetSupportsStickySockets is false on
// both), so this changes nothing on the platforms the engine ships to. It
// affects only desktop Linux, i.e. the harness.
//
// It is also where socket protection happens (see package protect). Open is
// the only moment both sockets exist and nothing has been sent on them yet:
// wireguard-go starts its receive routines and the handshake only after Open
// returns. Protecting here, rather than after Device.Up, closes the window in
// which a keepalive or initiation could be written into the tunnel it is
// trying to establish — and it covers every later rebind for free.
type portReportingBind struct {
	conn.Bind
	protect protect.Func
}

func newBind(p protect.Func) conn.Bind {
	return &portReportingBind{Bind: conn.NewDefaultBind(), protect: p}
}

// ErrProtectUnsupported means a protector was configured on a platform where
// the WireGuard bind cannot expose its socket descriptors. Only Android
// exposes them, and only Android needs protecting, so seeing this means the
// app installed a protector on the wrong platform.
var ErrProtectUnsupported = errors.New("wireguard: socket protection is not supported on this platform")

const (
	ephemeralPortLow  = 49152
	ephemeralPortHigh = 65535
	maxBindAttempts   = 64
)

func (b *portReportingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, got, err := b.open(port)
	if err != nil {
		return nil, 0, err
	}
	if err := b.protectSockets(); err != nil {
		_ = b.Bind.Close()
		return nil, 0, err
	}
	return fns, got, nil
}

// protectSockets runs the protector over both address families' sockets.
// Fail-closed: any failure fails the bind, and with it the transport's Up.
func (b *portReportingBind) protectSockets() error {
	if b.protect == nil {
		return nil
	}
	peek, ok := b.Bind.(conn.PeekLookAtSocketFd)
	if !ok {
		return ErrProtectUnsupported
	}
	protected := 0
	for _, fn := range []func() (int, error){peek.PeekLookAtSocketFd4, peek.PeekLookAtSocketFd6} {
		fd, err := fn()
		if err != nil || fd < 0 {
			// That address family is not open (an IPv4-only network has no
			// v6 socket). Not an error as long as one family is.
			continue
		}
		if err := b.protect(fd); err != nil {
			return fmt.Errorf("wireguard: protecting UDP socket: %w", err)
		}
		protected++
	}
	if protected == 0 {
		return fmt.Errorf("wireguard: protecting UDP socket: %w", ErrProtectUnsupported)
	}
	return nil
}

func (b *portReportingBind) open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if port != 0 {
		fns, got, err := b.Bind.Open(port)
		if err == nil && got == 0 {
			got = port
		}
		return fns, got, err
	}

	var lastErr error
	for range maxBindAttempts {
		p, err := randomEphemeralPort()
		if err != nil {
			return nil, 0, err
		}
		fns, got, err := b.Bind.Open(p)
		if errors.Is(err, syscall.EADDRINUSE) {
			lastErr = err
			continue
		}
		if err == nil && got == 0 {
			got = p
		}
		return fns, got, err
	}
	return nil, 0, lastErr
}

func randomEphemeralPort() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	span := uint16(ephemeralPortHigh - ephemeralPortLow + 1)
	return ephemeralPortLow + binary.BigEndian.Uint16(b[:])%span, nil
}
