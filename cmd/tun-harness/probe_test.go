package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

func TestProbeCommand(t *testing.T) {
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
	priv, _ := wireguard.GeneratePrivateKey()
	peer, _ := wireguard.GeneratePrivateKey()
	cfg := harnessConfig{
		Servers: []harnessServer{{
			Name: "fra-01", Protocol: "wireguard",
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", echo.LocalAddr().(*net.UDPAddr).Port-1),
			PrivateKey: priv.Base64(), PublicKey: peer.PublicKey().Base64(),
		}},
		TunnelAddresses: []string{"10.64.0.2/32"},
	}
	b, _ := json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := realMain([]string{"probe", "-config", path, "-timeout-ms", "300"}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"fra-01", "udp_echo", "up", "1 of 1 servers reachable"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), priv.Base64()) {
		t.Error("probe output contains the private key")
	}
}
