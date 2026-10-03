package wireguard

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport"
)

func clientDatagram(t *testing.T, payload string) []byte {
	t.Helper()
	buf := make([]byte, 1500)
	pkt, err := packet.BuildUDP(buf,
		netip.AddrPortFrom(clientTunIP, 4000),
		netip.AddrPortFrom(serverTunIP, 5000),
		[]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

// TestDeadPeerClosesTransport: a peer that vanishes must not leave the
// engine "connected" forever. Once data goes unanswered past the timeout,
// ReadPacket has to return ErrClosed, and say why.
func TestDeadPeerClosesTransport(t *testing.T) {
	const timeout = 500 * time.Millisecond
	p := newTunnelPairWith(t, func(c *Config) { c.DeadPeerTimeout = timeout })
	p.up(t, 10*time.Second)

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, err := p.client.ReadPacket(buf); err != nil {
				readErr <- err
				return
			}
		}
	}()

	_ = p.server.Close()
	start := time.Now()
	if err := p.client.WritePacket(clientDatagram(t, "anyone there?")); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	select {
	case err := <-readErr:
		if !errors.Is(err, transport.ErrClosed) {
			t.Fatalf("ReadPacket = %v, want ErrClosed", err)
		}
		if !errors.Is(err, ErrPeerUnresponsive) {
			t.Errorf("ReadPacket = %v, want it to wrap ErrPeerUnresponsive", err)
		}
		if el := time.Since(start); el < timeout {
			t.Errorf("declared dead after %s, before the %s timeout", el, timeout)
		}
	case <-time.After(timeout + 3*time.Second):
		t.Fatal("ReadPacket still blocked long after the peer died")
	}
	if err := p.client.WritePacket(clientDatagram(t, "x")); !errors.Is(err, ErrPeerUnresponsive) {
		t.Errorf("WritePacket after death = %v, want ErrPeerUnresponsive", err)
	}
}

// TestIdleTunnelWithKeepaliveStaysUp: persistent keepalives are not data and
// are never answered, so an idle tunnel must not be declared dead however
// long it sits there.
func TestIdleTunnelWithKeepaliveStaysUp(t *testing.T) {
	const timeout = 300 * time.Millisecond
	p := newTunnelPairWith(t, func(c *Config) {
		c.DeadPeerTimeout = timeout
		c.PersistentKeepalive = time.Second
	})
	p.up(t, 10*time.Second)

	readErr := make(chan error, 1)
	go func() {
		_, err := p.client.ReadPacket(make([]byte, 2048))
		readErr <- err
	}()

	// Several timeouts and at least two keepalive intervals.
	select {
	case err := <-readErr:
		t.Fatalf("idle tunnel closed itself: %v", err)
	case <-time.After(2500 * time.Millisecond):
	}

	// And it still carries traffic: a live peer answers, which resets the
	// clock rather than tripping it.
	if err := p.client.WritePacket(clientDatagram(t, "still here")); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}
	if got := readPacketWithin(t, p.server, 5*time.Second); !hasPayload(t, got, "still here") {
		t.Fatal("packet did not arrive")
	}
}

// TestConcurrentUpBuildsOneDevice: a second Up arriving while the first is
// still waiting for the handshake must not build (and leak) a second device.
func TestConcurrentUpBuildsOneDevice(t *testing.T) {
	p := newTunnelPair(t)

	const n = 4
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			errs <- p.client.Up(ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Up: %v", err)
		}
	}
	p.client.mu.Lock()
	created := p.client.devicesCreated
	p.client.mu.Unlock()
	if created != 1 {
		t.Fatalf("%d devices built for one transport; all but one leaked", created)
	}
}

// TestCloseDuringUpFailsUp: Up must not report success for a transport that
// was closed while it waited.
func TestCloseDuringUpFailsUp(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	peer, _ := GeneratePrivateKey()
	tr, err := New(Config{
		PrivateKey:    priv,
		PeerPublicKey: peer.PublicKey(),
		Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(closedUDPPort(t))),
		AllowedIPs:    FullTunnelAllowedIPs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- tr.Up(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	_ = tr.Close()
	select {
	case err := <-done:
		if !errors.Is(err, transport.ErrClosed) {
			t.Fatalf("Up after concurrent Close = %v, want ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Up did not return after Close")
	}
}

func TestDeadPeerTimeoutDefaults(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0:               DefaultDeadPeerTimeout,
		-1:              0,
		5 * time.Second: 5 * time.Second,
	} {
		c := Config{DeadPeerTimeout: in}
		if got := c.deadPeerTimeout(); got != want {
			t.Errorf("deadPeerTimeout(%s) = %s, want %s", in, got, want)
		}
	}
}
