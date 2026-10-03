//go:build windows

package mobile

import "errors"

// ErrUnsupportedPlatform is returned by Start on platforms with no tunnel
// file descriptor to adopt.
//
// Windows hands a VPN a wintun adapter handle, not an fd, so there is
// nothing for Start to wrap. This stub exists so the package — and
// everything that imports it, like the harness — still compiles and vets
// there; a Windows client would need its own TunDevice.
var ErrUnsupportedPlatform = errors.New("mobile: tunnel file descriptors are not supported on windows")

// fdTun mirrors the !windows type's method set so Start type-checks; it is
// never constructed.
type fdTun struct{}

func newFDTun(fd, mtu int) (*fdTun, error) { return nil, ErrUnsupportedPlatform }

func (*fdTun) ReadPacket([]byte) (int, error) { return 0, ErrUnsupportedPlatform }
func (*fdTun) WritePacket([]byte) error       { return ErrUnsupportedPlatform }
func (*fdTun) MTU() int                       { return 0 }
func (*fdTun) Close() error                   { return nil }

// closeFD has nothing to close: an int is not a Windows handle, and
// guessing that it is one would close something the caller still owns.
func closeFD(int) error { return nil }
