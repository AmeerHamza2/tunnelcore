//go:build soak && linux

package mobile

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(ents)
}

// TestSoakMobileStartStopCycles runs 200 Start/Stop cycles of the bound API
// over a SOCK_DGRAM socketpair against a real WireGuard peer, with a packet
// through the tunnel on every cycle, and asserts that descriptors and
// goroutines return to baseline. An app toggles the VPN, and the OS restarts
// the extension, many times over a device's life; one leaked fd per cycle
// ends with the process unable to open sockets at all.
func TestSoakMobileStartStopCycles(t *testing.T) {
	cycles := 200
	if testing.Short() {
		cycles = 20
	}
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
	defer server.Close()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		_ = server.Up(ctx)
	}()
	var port int
	for deadline := time.Now().Add(5 * time.Second); port == 0 && time.Now().Before(deadline); {
		port = server.ListenPort()
		time.Sleep(5 * time.Millisecond)
	}
	if port == 0 {
		t.Fatal("peer never bound")
	}
	received := make(chan string, 16)
	go func() {
		b := make([]byte, 2048)
		for {
			n, err := server.ReadPacket(b)
			if err != nil {
				return
			}
			if p, err := packet.Parse(b[:n]); err == nil {
				select {
				case received <- string(p.Payload(b[:n])):
				default:
				}
			}
		}
	}()

	cfg := config{
		Servers: []serverConfig{{
			Name: "local", Protocol: "wireguard",
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", port),
			PrivateKey: clientPriv.Base64(), PublicKey: serverPriv.PublicKey().Base64(),
			AllowedIPs: []string{"10.9.0.0/24"},
		}},
		TunnelAddresses: []string{"10.9.0.2/32"},
		DNSServers:      []string{"10.9.0.1"},
	}
	tun, err := NewTunnel(mustJSON(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	tun.SetStateListener(&recordingListener{})

	var baseFDs, baseG int
	buf := make([]byte, 1500)
	start := time.Now()
	for i := 0; i < cycles; i++ {
		fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
		if err != nil {
			t.Fatal(err)
		}
		osSide, engineSide := fds[0], fds[1]
		if err := tun.Start(engineSide); err != nil {
			t.Fatalf("cycle %d: Start: %v", i, err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for !tun.IsUp() && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if !tun.IsUp() {
			t.Fatalf("cycle %d: tunnel never came up; state=%s", i, tun.State())
		}
		want := fmt.Sprintf("cycle-%d", i)
		pkt, _ := packet.BuildUDP(buf, netip.AddrPortFrom(clientIP, 4000), netip.AddrPortFrom(serverIP, 5000), []byte(want))
		if _, err := syscall.Write(osSide, pkt); err != nil {
			t.Fatal(err)
		}
	wait:
		for {
			select {
			case got := <-received:
				if got == want {
					break wait
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("cycle %d: packet never reached the peer", i)
			}
		}
		if err := tun.Stop(); err != nil {
			t.Fatalf("cycle %d: Stop: %v", i, err)
		}
		if fdIsOpen(engineSide) {
			t.Fatalf("cycle %d: Stop left the tunnel descriptor open", i)
		}
		_ = syscall.Close(osSide)
		_ = tun.StatsJSON()

		if i == 4 {
			time.Sleep(100 * time.Millisecond)
			runtime.GC()
			baseFDs, baseG = openFDs(t), runtime.NumGoroutine()
		}
	}
	elapsed := time.Since(start)

	var fds, g int
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		runtime.GC()
		fds, g = openFDs(t), runtime.NumGoroutine()
		if fds <= baseFDs && g <= baseG+5 {
			break
		}
	}
	t.Logf("%d Start/Stop cycles in %s (%.1f ms each); fds %d -> %d, goroutines %d -> %d",
		cycles, elapsed.Round(time.Millisecond), float64(elapsed.Milliseconds())/float64(cycles), baseFDs, fds, baseG, g)
	if fds > baseFDs {
		t.Errorf("open descriptors grew from %d to %d over %d cycles", baseFDs, fds, cycles)
	}
	if g > baseG+5 {
		t.Errorf("goroutines grew from %d to %d over %d cycles", baseG, g, cycles)
	}
}
