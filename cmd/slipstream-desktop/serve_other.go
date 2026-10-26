//go:build !linux

package main

import "errors"

func runServe([]string) error {
	return errors.New("serve runs on Linux only (it drives a Linux tun interface); use a Linux VM")
}
