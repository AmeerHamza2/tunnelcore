package wireguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport"
)

// Tunnel addresses used by the end-to-end tests. These are inside the tunnel
// only; nothing is ever assigned to a real interface.
var (
	clientTunIP = netip.MustParseAddr("10.9.0.2")
	serverTunIP = netip.MustParseAddr("10.9.0.1")
)

// tunnelPair stands up two WireGuard transports pointed at each other over
// loopback UDP. Both ends are ordinary Transport values, so this exercises the
// real handshake, the real encryption path and the real cryptokey routing
// without a TUN device, without root, and without a server.
//
// Neither end reserves a port in advance. An earlier version did — ask the OS
// for a free port, close the socket, configure the device to bind it — and it
// was flaky under parallel test runs, because another test could claim the
// port in the window between the release and the bind. Instead both devices
// bind port 0 and the chosen port is read back with Transport.ListenPort, so
// there is no window at all.
//
// It also exercises something real: the server is configured with a
// placeholder peer endpoint and learns the client's actual address from the
// first authenticated handshake. That is WireGuard roaming, and it is the same
// mechanism that lets a tunnel survive a phone changing networks.
type tunnelPair struct {
	client *Transport
	server *Transport

	serverUpErr chan error
}

func newTunnelPair(t *testing.T) *tunnelPair {
	t.Helper()
	return newTunnelPairWith(t, nil)
}

// newTunnelPairWith is newTunnelPair with a hook to adjust the client's
// config before the client transport is built.
func newTunnelPairWith(t *testing.T, tweakClient func(*Config)) *tunnelPair {
	t.Helper()

	clientPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (client): %v", err)
	}
	serverPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (server): %v", err)
	}

	// The server accepts only the client's tunnel address, which is what
	// cryptokey routing means: AllowedIPs is simultaneously the route table
	// and the inbound source-address filter.
	//
	// Its Endpoint is a placeholder. The server never initiates; it learns
	// where the client is from the handshake.
	server, err := New(Config{
		Name:          "wireguard/test-server",
		PrivateKey:    serverPriv,
		PeerPublicKey: clientPriv.PublicKey(),
		Endpoint:      netip.MustParseAddrPort("127.0.0.1:1"),
		Addresses:     []netip.Prefix{netip.PrefixFrom(serverTunIP, 32)},
		AllowedIPs:    []netip.Prefix{netip.PrefixFrom(clientTunIP, 32)},
	})
	if err != nil {
		t.Fatalf("New (server): %v", err)
	}

	// Start the server first so it is listening before the client initiates.
	// Its Up blocks until the client's handshake lands, so it runs in the
	// background and the result is collected by up().
	serverUpErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		serverUpErr <- server.Up(ctx)
	}()

	serverPort := waitForListenPort(t, server, 5*time.Second)

	clientCfg := Config{
		Name:          "wireguard/test-client",
		PrivateKey:    clientPriv,
		PeerPublicKey: serverPriv.PublicKey(),
		Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(serverPort)),
		Addresses:     []netip.Prefix{netip.PrefixFrom(clientTunIP, 32)},
		// The client routes the whole tunnel subnet to the server.
		AllowedIPs:          []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")},
		PersistentKeepalive: time.Second,
	}
	if tweakClient != nil {
		tweakClient(&clientCfg)
	}
	client, err := New(clientCfg)
	if err != nil {
		t.Fatalf("New (client): %v", err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return &tunnelPair{client: client, server: server, serverUpErr: serverUpErr}
}

// waitForListenPort polls until the device reports the ephemeral port it bound.
func waitForListenPort(t *testing.T, tr *Transport, within time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if port := tr.ListenPort(); port != 0 {
			return port
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s never reported a listen port within %s", tr.Name(), within)
	return 0
}

// up completes the handshake from the client side and collects the server's
// result.
func (p *tunnelPair) up(t *testing.T, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := p.client.Up(ctx); err != nil {
		t.Fatalf("client Up: %v", err)
	}

	select {
	case err := <-p.serverUpErr:
		if err != nil {
			t.Fatalf("server Up: %v", err)
		}
	case <-time.After(timeout):
		t.Fatal("the server's Up never returned after the client handshaked")
	}
}

func TestTransportEndToEnd(t *testing.T) {
	p := newTunnelPair(t)
	p.up(t, 10*time.Second)

	// A UDP packet from the client's tunnel address to the server's.
	buf := make([]byte, 1500)
	sent, err := packet.BuildUDP(buf,
		netip.AddrPortFrom(clientTunIP, 12345),
		netip.AddrPortFrom(serverTunIP, 9999),
		[]byte("through the tunnel"))
	if err != nil {
		t.Fatalf("BuildUDP: %v", err)
	}

	if err := p.client.WritePacket(sent); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	got := readPacketWithin(t, p.server, 5*time.Second)

	parsed, err := packet.Parse(got)
	if err != nil {
		t.Fatalf("Parse of received packet: %v", err)
	}
	if parsed.Flow.Src.Addr() != clientTunIP {
		t.Errorf("src = %v, want %v", parsed.Flow.Src.Addr(), clientTunIP)
	}
	if parsed.Flow.Dst.Addr() != serverTunIP {
		t.Errorf("dst = %v, want %v", parsed.Flow.Dst.Addr(), serverTunIP)
	}
	if want, got := "through the tunnel", string(parsed.Payload(got)); got != want {
		t.Errorf("payload = %q, want %q", got, want)
	}

	// The checksum must survive encryption, transit and decryption. This is
	// the assertion that catches an off-by-one in the virtual device's
	// offset handling, which otherwise shows up as "some sites load and some
	// hang" and takes a week to find.
	if err := packet.VerifyL4Checksum(parsed, got); err != nil {
		t.Errorf("L4 checksum after round trip: %v", err)
	}
	if err := packet.VerifyIPv4Checksum(got); err != nil {
		t.Errorf("IPv4 checksum after round trip: %v", err)
	}
}

func TestTransportBidirectional(t *testing.T) {
	p := newTunnelPair(t)
	p.up(t, 10*time.Second)

	// Client to server.
	buf := make([]byte, 1500)
	out, err := packet.BuildUDP(buf,
		netip.AddrPortFrom(clientTunIP, 1111),
		netip.AddrPortFrom(serverTunIP, 2222),
		[]byte("ping"))
	if err != nil {
		t.Fatalf("BuildUDP: %v", err)
	}
	if err := p.client.WritePacket(out); err != nil {
		t.Fatalf("client WritePacket: %v", err)
	}
	if got := readPacketWithin(t, p.server, 5*time.Second); !hasPayload(t, got, "ping") {
		t.Fatal("server did not receive the client's packet intact")
	}

	// Server back to client. The reply must be sourced from the server's
	// tunnel address, because the client's peer AllowedIPs is 10.9.0.0/24 and
	// anything outside it is dropped by cryptokey routing.
	buf2 := make([]byte, 1500)
	reply, err := packet.BuildUDP(buf2,
		netip.AddrPortFrom(serverTunIP, 2222),
		netip.AddrPortFrom(clientTunIP, 1111),
		[]byte("pong"))
	if err != nil {
		t.Fatalf("BuildUDP (reply): %v", err)
	}
	if err := p.server.WritePacket(reply); err != nil {
		t.Fatalf("server WritePacket: %v", err)
	}
	if got := readPacketWithin(t, p.client, 5*time.Second); !hasPayload(t, got, "pong") {
		t.Fatal("client did not receive the server's reply intact")
	}
}

// TestTransportCryptokeyRoutingDropsSpoofedSource is the security property
// that distinguishes WireGuard from a plain tunnel: a peer may only send
// packets whose source address is inside its own AllowedIPs. A packet claiming
// to come from somewhere else is dropped rather than forwarded, so a
// compromised or malicious peer cannot inject traffic as another client.
func TestTransportCryptokeyRoutingDropsSpoofedSource(t *testing.T) {
	p := newTunnelPair(t)
	p.up(t, 10*time.Second)

	buf := make([]byte, 1500)
	spoofed, err := packet.BuildUDP(buf,
		// The client's AllowedIPs on the server is 10.9.0.2/32 only.
		netip.AddrPortFrom(netip.MustParseAddr("10.9.0.99"), 1111),
		netip.AddrPortFrom(serverTunIP, 2222),
		[]byte("spoofed"))
	if err != nil {
		t.Fatalf("BuildUDP: %v", err)
	}
	if err := p.client.WritePacket(spoofed); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	// Follow it with a legitimate packet. If the legitimate one arrives and
	// the spoofed one does not, the filter is working; asserting only on a
	// timeout would pass even if the tunnel were broken outright.
	buf2 := make([]byte, 1500)
	legit, err := packet.BuildUDP(buf2,
		netip.AddrPortFrom(clientTunIP, 1111),
		netip.AddrPortFrom(serverTunIP, 2222),
		[]byte("legitimate"))
	if err != nil {
		t.Fatalf("BuildUDP (legit): %v", err)
	}
	if err := p.client.WritePacket(legit); err != nil {
		t.Fatalf("WritePacket (legit): %v", err)
	}

	got := readPacketWithin(t, p.server, 5*time.Second)
	if !hasPayload(t, got, "legitimate") {
		t.Fatalf("first packet through was not the legitimate one; cryptokey routing did not drop the spoofed source")
	}
}

func TestTransportWriteBeforeUp(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	peer, _ := GeneratePrivateKey()
	tr, err := New(Config{
		PrivateKey:    priv,
		PeerPublicKey: peer.PublicKey(),
		Endpoint:      netip.MustParseAddrPort("127.0.0.1:51820"),
		AllowedIPs:    FullTunnelAllowedIPs(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	if err := tr.WritePacket([]byte{0x45, 0, 0, 20}); !errors.Is(err, transport.ErrClosed) {
		t.Errorf("WritePacket before Up = %v, want ErrClosed", err)
	}
}

func TestTransportHandshakeTimeout(t *testing.T) {
	priv, _ := GeneratePrivateKey()
	peer, _ := GeneratePrivateKey()

	// A port nothing is listening on. The handshake cannot complete, and Up
	// must return rather than hang — this is the failure the racer depends on
	// being fast and detectable.
	tr, err := New(Config{
		Name:          "wireguard/blackhole",
		PrivateKey:    priv,
		PeerPublicKey: peer.PublicKey(),
		Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(closedUDPPort(t))),
		AllowedIPs:    FullTunnelAllowedIPs(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = tr.Up(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, transport.ErrHandshakeTimeout) {
		t.Fatalf("Up = %v, want ErrHandshakeTimeout", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("Up took %s to give up on an unreachable endpoint", elapsed)
	}
}

func TestTransportUpIsIdempotent(t *testing.T) {
	p := newTunnelPair(t)
	p.up(t, 10*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.client.Up(ctx); err != nil {
		t.Errorf("second Up on an established transport = %v, want nil", err)
	}
}

func TestTransportCloseIsIdempotent(t *testing.T) {
	p := newTunnelPair(t)
	p.up(t, 10*time.Second)

	for i := 0; i < 3; i++ {
		if err := p.client.Close(); err != nil {
			t.Fatalf("Close #%d = %v, want nil", i+1, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := p.client.Up(ctx); !errors.Is(err, transport.ErrClosed) {
		t.Errorf("Up after Close = %v, want ErrClosed", err)
	}
}

func TestTransportReadAfterCloseReturnsErrClosed(t *testing.T) {
	p := newTunnelPair(t)
	p.up(t, 10*time.Second)

	done := make(chan error, 1)
	go func() {
		_, err := p.client.ReadPacket(make([]byte, 1500))
		done <- err
	}()

	// Give the reader a moment to block, then close underneath it. A reader
	// that does not wake on Close is a goroutine leak per reconnect, and a
	// mobile client reconnects every time the radio changes state.
	time.Sleep(100 * time.Millisecond)
	_ = p.client.Close()

	select {
	case err := <-done:
		if !errors.Is(err, transport.ErrClosed) {
			t.Errorf("ReadPacket after Close = %v, want ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadPacket did not return after Close; blocked reader leaks a goroutine per reconnect")
	}
}

func TestTransportStats(t *testing.T) {
	p := newTunnelPair(t)
	p.up(t, 10*time.Second)

	s := p.client.Stats()
	if !s.HandshakeOK {
		t.Error("Stats.HandshakeOK = false after a successful Up")
	}
	if s.DroppedInbound != 0 || s.DroppedOutbound != 0 {
		t.Errorf("Stats drops = %d in / %d out on an idle tunnel, want 0",
			s.DroppedInbound, s.DroppedOutbound)
	}
}

// --- helpers ---

// closedUDPPort returns a port with nothing listening on it.
//
// Unlike the removed freeUDPPort, this is used only where the *point* is that
// nothing answers, so the reuse race that made port reservation flaky does not
// matter here: if another test grabs the port, the handshake still fails,
// which is what the caller is asserting.
func closedUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserving a UDP port: %v", err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	if err := c.Close(); err != nil {
		t.Fatalf("releasing reserved port: %v", err)
	}
	return port
}

func readPacketWithin(t *testing.T, tr *Transport, d time.Duration) []byte {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := tr.ReadPacket(buf)
		ch <- result{buf[:n], err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("ReadPacket: %v", r.err)
		}
		return r.b
	case <-time.After(d):
		t.Fatalf("no packet arrived at %s within %s", tr.Name(), d)
		return nil
	}
}

func hasPayload(t *testing.T, pkt []byte, want string) bool {
	t.Helper()
	p, err := packet.Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return string(p.Payload(pkt)) == want
}
