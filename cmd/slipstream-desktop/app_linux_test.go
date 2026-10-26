//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ameerhamza2/tunnelcore/mobile"
)

const testLocation = `{
  "id": "sg", "name": "Singapore", "country": "SG", "public_ip": "203.0.113.7",
  "config": {
    "servers": [
      {"name": "sg-wireguard", "protocol": "wireguard", "endpoint": "203.0.113.7:51820",
       "public_key": "%PUB%", "keepalive_seconds": 25},
      {"name": "sg-shadowsocks", "protocol": "shadowsocks", "endpoint": "203.0.113.7:8388",
       "method": "chacha20-ietf-poly1305", "password": "secret",
       "plugins": [{"type": "tlsfrag", "label": "sni-split"}]}
    ],
    "tunnel_addresses": ["10.66.0.2/32"], "dns_servers": ["1.1.1.1"], "mtu": 1420
  }
}`

func writeLocation(t *testing.T) (dir, priv string) {
	t.Helper()
	priv, err := mobile.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, _ := mobile.GeneratePrivateKey()
	serverPub, _ := mobile.PublicKeyFor(serverPriv)
	dir = t.TempDir()
	body := strings.Replace(testLocation, "%PUB%", serverPub, 1)
	if err := os.WriteFile(filepath.Join(dir, "sg.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "notes.json"), []byte(`{"hello":1}`), 0o600)
	return dir, priv
}

// The location file plus the device key must make a config the engine
// accepts, with the private key only in WireGuard entries.
func TestEngineConfigMergesDeviceKey(t *testing.T) {
	dir, priv := writeLocation(t)
	locs, err := loadLocations(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(locs) != 1 || locs[0].ID != "sg" {
		t.Fatalf("locations = %+v, want just sg (non-location files skipped)", locs)
	}
	a := &app{privKey: priv, locs: locs}
	cfg, err := a.engineConfig(locs[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mobile.NewTunnel(cfg); err != nil {
		t.Fatalf("engine rejected merged config: %v", err)
	}
	var parsed struct {
		Servers []map[string]any `json:"servers"`
	}
	_ = json.Unmarshal([]byte(cfg), &parsed)
	for _, s := range parsed.Servers {
		_, has := s["private_key"]
		if (s["protocol"] == "wireguard") != has {
			t.Errorf("server %v: private_key present=%v", s["name"], has)
		}
	}
	// The location on disk must not have been modified by the merge.
	if _, ok := locs[0].cfg["servers"].([]any)[0].(map[string]any)["private_key"]; ok {
		t.Error("merge leaked the private key into the shared location config")
	}
}

func TestEndpointsAndServerIPs(t *testing.T) {
	dir, _ := writeLocation(t)
	locs, _ := loadLocations(dir)
	l := locs[0]
	if wg := l.endpoints("wireguard"); len(wg) != 1 || wg[0].Port() != 51820 {
		t.Errorf("wireguard endpoints = %v", wg)
	}
	if ips := l.serverIPs(); len(ips) != 1 || ips[0].String() != "203.0.113.7" {
		t.Errorf("server IPs = %v, want one deduplicated address", ips)
	}
}

// The panel's view of a location must never carry the secrets.
func TestLocationViewHasNoSecrets(t *testing.T) {
	dir, _ := writeLocation(t)
	locs, _ := loadLocations(dir)
	b, _ := json.Marshal(viewOf(locs[0]))
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "servers") {
		t.Fatalf("location view exposes config: %s", b)
	}
}
