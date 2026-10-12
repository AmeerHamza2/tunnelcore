//go:build linux

package mobile

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
)

// TestProbeServersJSON drives the picker's latency preview through the bound
// API: a WireGuard server whose echo port (endpoint+1) answers, a Shadowsocks
// server whose TCP port accepts, and a WireGuard server with nothing behind it.
func TestProbeServersJSON(t *testing.T) {
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteToUDP(buf[:n], from)
		}
	}()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	deadPort := dead.LocalAddr().(*net.UDPAddr).Port
	_ = dead.Close()

	live, _ := validWGServer(t)
	live.Name, live.Endpoint = "fra-01", fmt.Sprintf("127.0.0.1:%d", echoPort-1)
	down, _ := validWGServer(t)
	down.Name, down.Endpoint = "ams-01", fmt.Sprintf("127.0.0.1:%d", deadPort-1)
	ss := serverConfig{Name: "fra-01-ss", Protocol: "shadowsocks", Endpoint: ln.Addr().String(),
		Password: "0123456789abcdefghijklmnopqrstuv"}

	tun, err := NewTunnel(mustJSON(t, config{Servers: []serverConfig{down, live, ss}, TunnelAddresses: []string{"10.64.0.2/32"}}))
	if err != nil {
		t.Fatal(err)
	}

	var out probeOutJSON
	if err := json.Unmarshal([]byte(tun.ProbeServersJSON(300)), &out); err != nil {
		t.Fatal(err)
	}
	if out.Error != "" || len(out.Results) != 3 {
		t.Fatalf("probe = %+v", out)
	}
	byName := map[string]probeResultJSON{}
	for _, r := range out.Results {
		byName[r.Name] = r
	}
	if r := byName["fra-01"]; !r.Reachable || r.Method != "udp_echo" || r.Protocol != "wireguard" || r.RTTMS < 0 || r.Loss != 0 {
		t.Fatalf("live WireGuard server: %+v", r)
	}
	if r := byName["fra-01-ss"]; !r.Reachable || r.Method != "tcp_connect" || r.Protocol != "shadowsocks" {
		t.Fatalf("Shadowsocks server: %+v", r)
	}
	if r := byName["ams-01"]; r.Reachable || r.RTTMS != -1 || r.Loss != 1 {
		t.Fatalf("dead server: %+v", r)
	}
	if last := out.Results[len(out.Results)-1]; last.Name != "ams-01" {
		t.Fatalf("unreachable server should sort last, got %s", last.Name)
	}
}

func TestProbeServersJSONBadConfigIsValidJSON(t *testing.T) {
	tun := &Tunnel{cfgJSON: "{"}
	var out probeOutJSON
	if err := json.Unmarshal([]byte(tun.ProbeServersJSON(100)), &out); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if out.Error == "" || out.Results == nil {
		t.Fatalf("want an error and an empty (non-null) results array: %+v", out)
	}
}
