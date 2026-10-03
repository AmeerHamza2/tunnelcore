//go:build !linux

package main

import (
	"errors"
	"fmt"
	"io"
	"runtime"
)

// runTunCmd is Linux-only: attaching to a kernel tun interface goes through
// /dev/net/tun and the TUNSETIFF ioctl, which have no portable equivalent.
// The demo subcommand needs no tun device and runs everywhere.
func runTunCmd(_ []string, _, stderr io.Writer) error {
	fmt.Fprintf(stderr, "tun-harness run: not supported on %s; it needs a Linux tun device.\n", runtime.GOOS)
	fmt.Fprintln(stderr, "Try 'tun-harness demo', which runs the engine end to end without one.")
	return errors.New("unsupported platform")
}
