package protect

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

func TestDialerProtectsSocketBeforeConnect(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_ = c.Close()
		}
	}()

	var calls atomic.Int32
	var seenFD atomic.Int64
	f := Func(func(fd int) error {
		calls.Add(1)
		seenFD.Store(int64(fd))
		return nil
	})
	c, err := f.Dialer().DialContext(context.Background(), "tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()
	if calls.Load() != 1 {
		t.Fatalf("protect called %d times, want 1", calls.Load())
	}
	if seenFD.Load() <= 2 {
		t.Fatalf("protect saw fd %d, want a real socket fd", seenFD.Load())
	}
}

// TestDialFailsClosed is the property that matters: a socket that could not be
// protected must never be used, because it would route into the tunnel.
func TestDialFailsClosed(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	f := FromBool(func(int) bool { return false })
	_, err = f.Dialer().DialContext(context.Background(), "tcp4", ln.Addr().String())
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("dial with a refusing protector = %v, want ErrRefused", err)
	}
}

func TestNilFuncIsNoop(t *testing.T) {
	var f Func
	if f.Control() != nil {
		t.Fatal("nil Func must produce a nil Control hook")
	}
	if FromBool(nil) != nil {
		t.Fatal("FromBool(nil) must be nil")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := f.Dialer().Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = c.Close()
}
