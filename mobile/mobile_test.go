//go:build linux

package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/engine"
	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// --- config ---

func validWGServer(t *testing.T) (serverConfig, wireguard.Key) {
	t.Helper()
	priv, err := wireguard.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer, err := wireguard.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return serverConfig{
		Name:       "fra-01",
		Protocol:   "wireguard",
		Endpoint:   "203.0.113.10:51820",
		PrivateKey: priv.Base64(),
		PublicKey:  peer.PublicKey().Base64(),
	}, peer
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseConfigValid(t *testing.T) {
	srv, _ := validWGServer(t)
	cfg := config{
		Servers:         []serverConfig{srv},
		TunnelAddresses: []string{"10.9.0.2"}, // bare address is accepted
		DNSServers:      []string{"10.9.0.1"},
	}
	got, err := parseConfig(mustJSON(t, cfg))
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	pfx, _ := got.tunnelPrefixes()
	if pfx[0] != netip.MustParsePrefix("10.9.0.2/32") {
		t.Errorf("bare tunnel address parsed as %v, want /32", pfx[0])
	}
	dns, _ := got.dnsUpstreams()
	if dns[0].Port() != 53 {
		t.Errorf("bare DNS server got port %d, want 53", dns[0].Port())
	}
}

func TestParseConfigRejects(t *testing.T) {
	srv, _ := validWGServer(t)
	base := func() config {
		return config{Servers: []serverConfig{srv}, TunnelAddresses: []string{"10.9.0.2/32"}}
	}
	cases := []struct {
		name   string
		mutate func(*config)
		raw    string
		want   error
		substr string
	}{
		{name: "not json", raw: "{", want: ErrBadConfigJSON},
		{name: "unknown field", raw: `{"servers":[],"kill_switch":true}`, want: ErrBadConfigJSON},
		{name: "no servers", mutate: func(c *config) { c.Servers = nil }, want: ErrNoServers},
		{name: "no tunnel addrs", mutate: func(c *config) { c.TunnelAddresses = nil }, want: ErrNoTunnelAddrs},
		{name: "unknown proto", mutate: func(c *config) { c.Servers[0].Protocol = "openvpn" }, want: ErrUnknownProto},
		{name: "hostname endpoint", mutate: func(c *config) { c.Servers[0].Endpoint = "fra.example.com:51820" }, substr: "literal address"},
		{name: "shadowsocks hostname endpoint", mutate: func(c *config) {
			c.Servers[0] = serverConfig{Name: "s", Protocol: "shadowsocks", Endpoint: "sgp.example.com:8388", Password: "0123456789abcdefghijklmnopqrstuv"}
		}, substr: "literal address"},
		{name: "bad mtu", mutate: func(c *config) { c.MTU = 9000 }, want: ErrBadMTU},
		{name: "bad dns", mutate: func(c *config) { c.DNSServers = []string{"dns.google"} }, substr: "dns_servers[0]"},
		{name: "weak ss password", mutate: func(c *config) {
			c.Servers[0] = serverConfig{Name: "s", Protocol: "shadowsocks", Endpoint: "203.0.113.5:8388", Password: "short"}
		}, substr: "password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.raw
			if raw == "" {
				c := base()
				c.Servers = append([]serverConfig(nil), c.Servers...)
				tc.mutate(&c)
				raw = mustJSON(t, c)
			}
			_, err := parseConfig(raw)
			if err == nil {
				t.Fatal("parseConfig accepted an invalid config")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			if tc.substr != "" && !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("err = %v, want it to mention %q", err, tc.substr)
			}
		})
	}
}

// TestOneBadServerDoesNotRejectConfig: a control plane that ships one bad
// record must cost that server, not the whole product.
func TestOneBadServerDoesNotRejectConfig(t *testing.T) {
	good, _ := validWGServer(t)
	bad := good
	bad.Name = "broken"
	bad.PublicKey = "not-base64!"
	cfg := config{Servers: []serverConfig{bad, good}, TunnelAddresses: []string{"10.9.0.2/32"}}
	parsed, err := parseConfig(mustJSON(t, cfg))
	if err != nil {
		t.Fatalf("parseConfig rejected a config with one usable server: %v", err)
	}
	cands, err := (&configProvider{cfg: parsed, mtu: 1420}).Candidates(context.Background())
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(cands) != 1 || cands[0].Name() != "wireguard/fra-01" {
		t.Fatalf("Candidates = %d (%v), want only the good server", len(cands), cands)
	}
}

func TestNewTunnelValidatesBeforePermission(t *testing.T) {
	if _, err := NewTunnel(`{"servers":[]}`); err == nil {
		t.Fatal("NewTunnel accepted an empty config")
	}
}

func TestDenyList(t *testing.T) {
	d := newDenyList([]string{" DoubleClick.net. ", "", "ads.example"})
	for name, want := range map[string]bool{
		"doubleclick.net":       false,
		"x.y.doubleclick.net":   false,
		"notdoubleclick.net":    true,
		"ads.example":           false,
		"example":               true,
		"cdn.ads.example":       false,
		"doubleclick.net.other": true,
	} {
		if got := d.Allow(name, 1); got != want {
			t.Errorf("Allow(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestKeyHelpers(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFor(priv)
	if err != nil {
		t.Fatal(err)
	}
	if pub == priv || len(pub) != 44 {
		t.Fatalf("PublicKeyFor returned %q", pub)
	}
	if _, err := PublicKeyFor("garbage"); err == nil {
		t.Fatal("PublicKeyFor accepted garbage")
	}
	if !strings.Contains(SupportedCiphers(), "chacha20-ietf-poly1305") {
		t.Fatalf("SupportedCiphers = %q", SupportedCiphers())
	}
}

func TestIdleTunnelStats(t *testing.T) {
	srv, _ := validWGServer(t)
	tun, err := NewTunnel(mustJSON(t, config{Servers: []serverConfig{srv}, TunnelAddresses: []string{"10.9.0.2/32"}}))
	if err != nil {
		t.Fatal(err)
	}
	var st statsJSON
	if err := json.Unmarshal([]byte(tun.StatsJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != "idle" || st.OverallSuccessRate != -1 {
		t.Fatalf("idle stats = %+v", st)
	}
	if tun.IsUp() || tun.State() != "idle" {
		t.Fatal("idle tunnel reports up")
	}
	if err := tun.Stop(); err != nil {
		t.Fatalf("Stop on idle tunnel: %v", err)
	}
}

// --- fd ownership ---

func socketpair(t *testing.T) (osSide, engineSide int) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fds[0]) })
	return fds[0], fds[1]
}

func fdIsOpen(fd int) bool {
	var st syscall.Stat_t
	return !errors.Is(syscall.Fstat(fd, &st), syscall.EBADF)
}

// TestStartClosesFDOnError: ownership of the descriptor transfers on every
// call, so an error path must not leak it.
func TestStartClosesFDOnError(t *testing.T) {
	srv, _ := validWGServer(t)
	tun, err := NewTunnel(mustJSON(t, config{Servers: []serverConfig{srv}, TunnelAddresses: []string{"10.9.0.2/32"}}))
	if err != nil {
		t.Fatal(err)
	}
	// Swap in a config that parses at NewTunnel time but not now is not
	// possible through the API, so provoke the running-tunnel error instead.
	_, fd1 := socketpair(t)
	if err := tun.Start(fd1); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = tun.Stop() })

	_, fd2 := socketpair(t)
	if err := tun.Start(fd2); !errors.Is(err, ErrTunnelRunning) {
		t.Fatalf("second Start = %v, want ErrTunnelRunning", err)
	}
	if fdIsOpen(fd2) {
		t.Fatal("Start returned an error but left the descriptor open")
	}
}

// --- fdTun ---

func TestFDTunCloseUnblocksRead(t *testing.T) {
	_, fd := socketpair(t)
	dev, err := newFDTun(fd, 1420)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := dev.ReadPacket(make([]byte, 1500))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = dev.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadPacket returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock ReadPacket; engine.Stop would hang on an idle tunnel")
	}
}

func TestFDTunRoundTrip(t *testing.T) {
	osSide, fd := socketpair(t)
	dev, err := newFDTun(fd, 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	if _, err := syscall.Write(osSide, []byte{0x45, 1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, err := dev.ReadPacket(buf)
	if err != nil || n != 4 || buf[0] != 0x45 {
		t.Fatalf("ReadPacket = %d %v %x", n, err, buf[:n])
	}
	if err := dev.WritePacket([]byte{0x60, 9, 9}); err != nil {
		t.Fatal(err)
	}
	n, err = syscall.Read(osSide, buf)
	if err != nil || n != 3 || buf[0] != 0x60 {
		t.Fatalf("OS side read = %d %v %x", n, err, buf[:n])
	}
}

// --- end to end through the bound API ---

type recordingListener struct {
	mu     sync.Mutex
	states []string
}

func (l *recordingListener) OnStateChange(state, reason, tr, errMsg string) {
	l.mu.Lock()
	l.states = append(l.states, state)
	l.mu.Unlock()
}

func (l *recordingListener) saw(s string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, x := range l.states {
		if x == s {
			return true
		}
	}
	return false
}

// TestTunnelEndToEnd drives the whole product path the way an Android app
// does: JSON config in, a tunnel fd in, state callbacks out, and packets
// written by "the OS" arriving decrypted at a real WireGuard peer.
//
// The fd is one end of a SOCK_DGRAM socketpair, which preserves packet
// boundaries exactly as a tun device does, so no privileges are needed.
func TestTunnelEndToEnd(t *testing.T) {
	clientPriv, _ := wireguard.GeneratePrivateKey()
	serverPriv, _ := wireguard.GeneratePrivateKey()
	clientIP := netip.MustParseAddr("10.9.0.2")
	serverIP := netip.MustParseAddr("10.9.0.1")

	server, err := wireguard.New(wireguard.Config{
		Name:          "wireguard/peer",
		PrivateKey:    serverPriv,
		PeerPublicKey: clientPriv.PublicKey(),
		Endpoint:      netip.MustParseAddrPort("127.0.0.1:1"),
		AllowedIPs:    []netip.Prefix{netip.PrefixFrom(clientIP, 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	serverUp := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		serverUp <- server.Up(ctx)
	}()
	var port int
	for deadline := time.Now().Add(5 * time.Second); port == 0 && time.Now().Before(deadline); {
		port = server.ListenPort()
		time.Sleep(5 * time.Millisecond)
	}
	if port == 0 {
		t.Fatal("peer never bound")
	}

	cfg := config{
		Servers: []serverConfig{{
			Name:             "local",
			Protocol:         "wireguard",
			Endpoint:         fmt.Sprintf("127.0.0.1:%d", port),
			PrivateKey:       clientPriv.Base64(),
			PublicKey:        serverPriv.PublicKey().Base64(),
			AllowedIPs:       []string{"10.9.0.0/24"},
			KeepaliveSeconds: 1,
		}},
		TunnelAddresses: []string{"10.9.0.2/32"},
	}
	tun, err := NewTunnel(mustJSON(t, cfg))
	if err != nil {
		t.Fatalf("NewTunnel: %v", err)
	}
	lis := &recordingListener{}
	tun.SetStateListener(lis)

	osSide, fd := socketpair(t)
	if err := tun.Start(fd); err != nil {
		t.Fatalf("Start: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = tun.Stop()
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for !tun.IsUp() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !tun.IsUp() {
		t.Fatalf("tunnel never came up; state=%s", tun.State())
	}
	if err := <-serverUp; err != nil {
		t.Fatalf("peer Up: %v", err)
	}

	// "The OS" writes a UDP packet into the tunnel.
	buf := make([]byte, 1500)
	pkt, err := packet.BuildUDP(buf, netip.AddrPortFrom(clientIP, 4000), netip.AddrPortFrom(serverIP, 5000), []byte("hello from the app"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := syscall.Write(osSide, pkt); err != nil {
		t.Fatal(err)
	}

	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, 2048)
		n, err := server.ReadPacket(b)
		if err == nil {
			got <- b[:n]
		}
	}()
	select {
	case b := <-got:
		p, err := packet.Parse(b)
		if err != nil {
			t.Fatalf("peer received unparseable packet: %v", err)
		}
		if string(p.Payload(b)) != "hello from the app" {
			t.Fatalf("payload = %q", p.Payload(b))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet written to the tunnel fd never reached the WireGuard peer")
	}

	// Stats must reflect the traffic (this is the Snapshot/Stats regression).
	var st statsJSON
	if err := json.Unmarshal([]byte(tun.StatsJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != "connected" || st.PacketsOut < 1 || st.BytesUp < 1 || st.ActiveTransport != "wireguard/local" {
		t.Fatalf("stats after traffic = %+v", st)
	}

	var stopDone atomic.Bool
	go func() { _ = tun.Stop(); stopDone.Store(true) }()
	for deadline := time.Now().Add(3 * time.Second); !stopDone.Load() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if !stopDone.Load() {
		t.Fatal("Stop did not return")
	}
	stopped = true
	if !lis.saw("connecting") || !lis.saw("connected") || !lis.saw("disconnected") {
		t.Fatalf("listener saw %v", lis.states)
	}

	// After Stop the session's totals must still be readable: "how much did
	// that use" is asked right after the user disconnects.
	var final statsJSON
	if err := json.Unmarshal([]byte(tun.StatsJSON()), &final); err != nil {
		t.Fatal(err)
	}
	if final.State != "disconnected" || final.PacketsOut < st.PacketsOut || final.BytesUp < st.BytesUp || final.BytesUp == 0 {
		t.Fatalf("stats after Stop = %+v, want the session totals (>= %+v) with state disconnected", final, st)
	}
	if fdIsOpen(fd) {
		t.Fatal("Stop did not close the tunnel descriptor")
	}
}

// --- listener delivery ---

// stoppingListener calls Stop from inside OnStateChange, which is what a UI
// does when it reacts to a state by tearing the tunnel down.
type stoppingListener struct {
	tun     *Tunnel
	on      string
	stopped chan error

	recordingListener
	once sync.Once
}

func (l *stoppingListener) OnStateChange(state, reason, tr, errMsg string) {
	l.recordingListener.OnStateChange(state, reason, tr, errMsg)
	if state == l.on {
		l.once.Do(func() { l.stopped <- l.tun.Stop() })
	}
}

// TestStopFromListenerCallback: callbacks used to run on the engine's own
// goroutine, so Stop from a callback waited for the goroutine that was
// running it — a deadlock, with the tunnel fd held open forever.
func TestStopFromListenerCallback(t *testing.T) {
	srv, _ := validWGServer(t) // unreachable: the engine stays "connecting"
	tun, err := NewTunnel(mustJSON(t, config{Servers: []serverConfig{srv}, TunnelAddresses: []string{"10.9.0.2/32"}}))
	if err != nil {
		t.Fatal(err)
	}
	lis := &stoppingListener{tun: tun, on: "connecting", stopped: make(chan error, 1)}
	tun.SetStateListener(lis)

	_, fd := socketpair(t)
	if err := tun.Start(fd); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case err := <-lis.stopped:
		if err != nil {
			t.Fatalf("Stop from callback = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop called from OnStateChange did not return: callback deadlock")
	}

	// The rest of the session's changes still arrive, "disconnected" last.
	deadline := time.Now().Add(2 * time.Second)
	for !lis.saw("disconnected") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	lis.mu.Lock()
	states := append([]string(nil), lis.states...)
	lis.mu.Unlock()
	if len(states) == 0 || states[len(states)-1] != "disconnected" {
		t.Fatalf("listener saw %v, want it to end with disconnected", states)
	}
	if fdIsOpen(fd) {
		t.Fatal("Stop from a callback did not close the tunnel descriptor")
	}
	var st statsJSON
	if err := json.Unmarshal([]byte(tun.StatsJSON()), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != "disconnected" {
		t.Fatalf("StatsJSON state after Stop = %q, want disconnected", st.State)
	}
}

type blockingListener struct {
	release chan struct{}
	recordingListener
}

func (l *blockingListener) OnStateChange(state, reason, tr, errMsg string) {
	<-l.release
	l.recordingListener.OnStateChange(state, reason, tr, errMsg)
}

// TestCallbackPumpNeverBlocksAndKeepsFinal: a stuck listener must not stall
// the engine, and when the backlog overflows the final state survives.
func TestCallbackPumpNeverBlocksAndKeepsFinal(t *testing.T) {
	lis := &blockingListener{release: make(chan struct{})}
	p := newCallbackPump(func() StateListener { return lis })

	posted := make(chan struct{})
	go func() {
		for i := 0; i < 10*callbackQueueDepth; i++ {
			p.post(engine.Change{To: engine.StateReconnecting})
		}
		p.post(engine.Change{To: engine.StateDisconnected})
		close(posted)
	}()
	select {
	case <-posted:
	case <-time.After(2 * time.Second):
		t.Fatal("post blocked behind a stuck listener")
	}

	close(lis.release)
	p.closeAndDrain()
	lis.mu.Lock()
	defer lis.mu.Unlock()
	if n := len(lis.states); n == 0 || n > callbackQueueDepth+2 || lis.states[n-1] != "disconnected" {
		t.Fatalf("delivered %d states ending %v; want a bounded backlog ending in disconnected", n, lis.states[max(0, n-1):])
	}
	// Posting after close is a no-op, not a panic on a closed channel.
	p.post(engine.Change{To: engine.StateConnected})
}
