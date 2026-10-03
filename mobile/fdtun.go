//go:build !windows

package mobile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
)

// fdTun is an engine.TunDevice over the file descriptor the mobile OS hands
// to a VPN process.
//
// Two platform details live here and nowhere else:
//
// Framing. Android's tun fd carries bare IP packets. Apple's utun prefixes
// every packet with a 4-byte protocol-family header (AF_INET or AF_INET6, in
// network byte order) and expects the same on write. Getting this wrong is
// silent on read — the parser just rejects every packet as malformed — and
// fatal on write, where the kernel drops everything. headerLen is 0 or 4 by
// build target; see fdtun_header_*.go.
//
// Shutdown. The engine's tunnel reader blocks in Read with no deadline, and
// the engine's Stop contract depends on Close unblocking it (see
// engine.TunDevice). A blocking fd wrapped in os.NewFile does not get that:
// Read sits in a raw syscall that Close cannot interrupt, so Stop would hang
// until the next packet. Setting O_NONBLOCK *before* os.NewFile makes the
// runtime register the fd with its netpoller, after which Close wakes the
// reader with os.ErrClosed. This is the same thing wireguard-go's
// CreateTUNFromFile does, for the same reason.
type fdTun struct {
	f   *os.File
	mtu int

	// rbuf is the read scratch space for the framed case. Only the engine's
	// single tunnel reader calls ReadPacket, so it needs no lock.
	rbuf []byte

	// wmu serialises writes in the framed case, which share wbuf. The
	// unframed case writes the caller's slice directly.
	wmu  sync.Mutex
	wbuf []byte

	closeOnce sync.Once
	closeErr  error
}

func newFDTun(fd, mtu int) (*fdTun, error) {
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("%w: setting O_NONBLOCK on fd %d: %w", ErrBadFD, fd, err)
	}
	f := os.NewFile(uintptr(fd), "tun")
	if f == nil {
		return nil, fmt.Errorf("%w: %d", ErrBadFD, fd)
	}
	return newFileTun(f, mtu), nil
}

func newFileTun(f *os.File, mtu int) *fdTun {
	t := &fdTun{f: f, mtu: mtu}
	if headerLen > 0 {
		t.rbuf = make([]byte, mtu+headerLen)
		t.wbuf = make([]byte, mtu+headerLen)
	}
	return t
}

// errTunClosed is returned after Close; the engine treats any read error as
// the end of the device, so the exact value matters only to tests.
var errTunClosed = errors.New("mobile: tun closed")

func (t *fdTun) ReadPacket(b []byte) (int, error) {
	for {
		if headerLen == 0 {
			n, err := t.f.Read(b)
			if err != nil {
				return 0, t.mapErr(err)
			}
			return n, nil
		}
		n, err := t.f.Read(t.rbuf)
		if err != nil {
			return 0, t.mapErr(err)
		}
		if n <= headerLen {
			// A frame with no packet in it. Skip it rather than return an
			// empty packet, which the engine would count as traffic.
			continue
		}
		return copy(b, t.rbuf[headerLen:n]), nil
	}
}

func (t *fdTun) WritePacket(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if headerLen == 0 {
		_, err := t.f.Write(p)
		return t.mapErr(err)
	}
	if len(p) > t.mtu {
		// Larger than the interface accepts; the kernel would reject it
		// anyway, and growing wbuf for it would let one oversize packet pin
		// memory for the life of the tunnel.
		return nil
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if !putFamilyHeader(t.wbuf, p) {
		return nil // not IPv4 or IPv6; nothing the OS could route
	}
	n := copy(t.wbuf[headerLen:], p)
	_, err := t.f.Write(t.wbuf[:headerLen+n])
	return t.mapErr(err)
}

func (t *fdTun) MTU() int { return t.mtu }

func (t *fdTun) Close() error {
	t.closeOnce.Do(func() { t.closeErr = t.f.Close() })
	return t.closeErr
}

func (t *fdTun) mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
		return errTunClosed
	}
	return err
}

func closeFD(fd int) error { return syscall.Close(fd) }
