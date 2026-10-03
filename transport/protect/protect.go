// Package protect excludes the engine's own sockets from the VPN route.
//
// A full-tunnel VPN routes 0.0.0.0/0 and ::/0 into the tunnel interface. The
// engine's sockets to the exit node are ordinary sockets, so without
// intervention they are routed into the tunnel too: the WireGuard handshake is
// written into the interface it is trying to establish, and nothing ever
// connects. On Android this is solved per socket with VpnService.protect(fd),
// which marks the socket to bypass the VPN; an app that excludes itself with
// addDisallowedApplication gets the same effect for every socket at once.
//
// iOS needs neither: sockets opened inside an NEPacketTunnelProvider bypass
// the tunnel automatically, which is why Func is optional everywhere.
//
// The rule this package enforces is fail-closed. If a protector is installed
// and protecting a socket fails, the dial fails. The alternative — carry on
// with an unprotected socket — produces either a routing loop (the tunnel
// never comes up and the user sees a spinner) or, worse, on a split-tunnel
// configuration, a socket that silently takes the wrong route.
package protect

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// Func protects one socket file descriptor. Nil means no protection is
// needed on this platform.
type Func func(fd int) error

// ErrRefused is returned when the platform declined to protect a socket.
// On Android this means VpnService.protect returned false, which happens when
// the VpnService has been revoked or has not been prepared.
var ErrRefused = errors.New("protect: platform refused to protect socket")

// Control is a net.Dialer / net.ListenConfig Control hook that protects the
// socket before it connects. A nil Func returns a nil hook.
func (f Func) Control() func(network, address string, c syscall.RawConn) error {
	if f == nil {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var perr error
		if err := c.Control(func(fd uintptr) { perr = f(int(fd)) }); err != nil {
			return fmt.Errorf("protect: %s socket to %s: %w", network, address, err)
		}
		if perr != nil {
			return fmt.Errorf("protect: %s socket to %s: %w", network, address, perr)
		}
		return nil
	}
}

// Dialer returns a net.Dialer whose sockets are protected by f.
func (f Func) Dialer() *net.Dialer {
	return &net.Dialer{Control: f.Control()}
}

// FromBool adapts a platform callback that reports success as a bool, which is
// the shape VpnService.protect has and therefore the shape gomobile hands us.
func FromBool(protect func(fd int) bool) Func {
	if protect == nil {
		return nil
	}
	return func(fd int) error {
		if !protect(fd) {
			return fmt.Errorf("%w (fd %d)", ErrRefused, fd)
		}
		return nil
	}
}
