package wireguard

import (
	"errors"
	"runtime"
	"testing"

	"github.com/ameerhamza2/tunnelcore/transport/protect"
)

// TestBindReportsRealPort pins the workaround for the upstream wireguard-go
// bug where StdNetBind.Open reports port 0 on hosts without IPv6. Whatever
// the host's IPv6 situation, the port reported back must be the one bound.
func TestBindReportsRealPort(t *testing.T) {
	b := newBind(nil)
	_, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open(0): %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if port < ephemeralPortLow {
		t.Fatalf("Open(0) reported port %d, want one in the dynamic range [%d,%d]",
			port, ephemeralPortLow, ephemeralPortHigh)
	}
}

func TestBindFixedPortIsReported(t *testing.T) {
	first := newBind(nil)
	_, port, err := first.Open(0)
	if err != nil {
		t.Fatalf("Open(0): %v", err)
	}
	_ = first.Close()

	b := newBind(nil)
	_, got, err := b.Open(port)
	if err != nil {
		t.Skipf("port %d was reclaimed between binds: %v", port, err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if got != port {
		t.Fatalf("Open(%d) reported %d", port, got)
	}
}

func TestRandomEphemeralPortRange(t *testing.T) {
	for range 1000 {
		p, err := randomEphemeralPort()
		if err != nil {
			t.Fatal(err)
		}
		if p < ephemeralPortLow {
			t.Fatalf("port %d below dynamic range", p)
		}
	}
}

// TestBindProtectFailsClosed: a protector that cannot be honoured must fail
// the bind, never fall through to an unprotected socket.
func TestBindProtectFailsClosed(t *testing.T) {
	called := false
	b := newBind(func(int) error { called = true; return protect.ErrRefused })
	_, _, err := b.Open(0)
	if err == nil {
		_ = b.Close()
		t.Fatal("Open succeeded with a refusing protector")
	}
	if runtime.GOOS == "android" {
		if !called || !errors.Is(err, protect.ErrRefused) {
			t.Fatalf("Open = %v (called=%v), want ErrRefused", err, called)
		}
		return
	}
	// Off Android the bind cannot expose its descriptors at all.
	if !errors.Is(err, ErrProtectUnsupported) {
		t.Fatalf("Open = %v, want ErrProtectUnsupported", err)
	}
}
