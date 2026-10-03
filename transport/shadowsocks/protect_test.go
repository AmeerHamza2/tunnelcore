package shadowsocks

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport/protect"
)

// TestEverySocketIsProtected: the probe dial, each proxied TCP connection and
// each UDP association must all pass through the protector. One unprotected
// socket on Android is a routing loop for that flow.
func TestEverySocketIsProtected(t *testing.T) {
	srv := newTestServer(t, AES256GCM, testPassword, echoHandler)
	var n atomic.Int32
	tr := newTestTransport(t, srv, Config{Protect: func(int) error { n.Add(1); return nil }})
	upTransport(t, tr)
	afterUp := n.Load()
	if afterUp < 1 {
		t.Fatalf("Up opened an unprotected socket (protect calls = %d)", afterUp)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tr.DialTCP(ctx, testTarget)
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	_ = c.Close()
	if n.Load() != afterUp+1 {
		t.Fatalf("DialTCP protect calls = %d, want 1", n.Load()-afterUp)
	}

	u, err := tr.DialUDP(ctx, testTarget)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	_ = u.Close()
	if n.Load() != afterUp+2 {
		t.Fatalf("DialUDP did not protect its socket")
	}
}

func TestProtectFailureFailsUp(t *testing.T) {
	srv := newTestServer(t, AES256GCM, testPassword, echoHandler)
	tr := newTestTransport(t, srv, Config{Protect: protect.FromBool(func(int) bool { return false })})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tr.Up(ctx); !errors.Is(err, protect.ErrRefused) {
		t.Fatalf("Up with a refusing protector = %v, want ErrRefused", err)
	}
}
