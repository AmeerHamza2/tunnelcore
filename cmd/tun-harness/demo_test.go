package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/mobile"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// TestDemoScenarios runs every demo scenario in-process and requires all of
// its checks to pass.
//
// This is the harness's own regression test, and also the cheapest
// end-to-end test the engine has: each scenario drives the real racer, real
// WireGuard handshakes, a real Shadowsocks stream and two real gVisor stacks
// through one engine, so a regression anywhere along that path fails here even
// if every package's unit tests still pass.
func TestDemoScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end demo takes a few seconds; skipped with -short")
	}

	// Lines each scenario must print, as evidence that the step actually ran
	// rather than being skipped by a scenario-table mistake.
	want := map[string][]string{
		"all": {
			"abandoned after", "never dialed", "connected via wireguard/ams-02",
			"(network_changed)", "decrypted udp", "connection refused",
			"connected via shadowsocks/sgp-01", "every byte verified", "disconnected",
		},
		"wireguard":   {"connected via wireguard/ams-02", "(network_changed)", "pong 5"},
		"shadowsocks": {"connection refused", "connected via shadowsocks/sgp-01", "every byte verified"},
		"failover":    {"transport_failed", "connected via shadowsocks/sgp-01", "200 OK"},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			var out bytes.Buffer
			start := time.Now()
			err := runDemo(ctx, &out, demoOptions{Scenario: sc.name, Verbose: true})
			if err != nil {
				t.Fatalf("demo %q failed: %v\n--- output ---\n%s", sc.name, err, out.String())
			}
			text := out.String()
			for _, s := range want[sc.name] {
				if !strings.Contains(text, s) {
					t.Errorf("output lacks %q\n--- output ---\n%s", s, text)
				}
			}
			if strings.Contains(text, "\x1b[") {
				t.Error("output contains ANSI escapes with colour disabled")
			}
			t.Logf("scenario %s passed in %s", sc.name, time.Since(start).Round(time.Millisecond))
		})
	}
}

func TestDemoUnknownScenario(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"demo", "-scenario", "nope"}, &out, &errOut); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "unknown scenario") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"frobnicate"}, &out, &errOut); code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if code := realMain(nil, &out, &errOut); code != exitUsage {
		t.Errorf("no-args exit code = %d, want %d", code, exitUsage)
	}
}

func TestKeygen(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"keygen"}, &out, &errOut); code != 0 {
		t.Fatalf("keygen exit code = %d, stderr %q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "secret") {
		t.Error("keygen did not warn on stderr that the private key is secret")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("unexpected keygen line %q", line)
		}
		fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	priv, err := wireguard.ParseKey(fields["private_key"])
	if err != nil {
		t.Fatalf("private_key does not parse: %v", err)
	}
	if got, want := fields["public_key"], priv.PublicKey().Base64(); got != want {
		t.Errorf("public_key = %s, want %s", got, want)
	}

	// The derived public key must agree with what -pubkey computes, and with
	// what the mobile API hands an app.
	var pubOut bytes.Buffer
	if err := derivePublic(strings.NewReader(fields["private_key"]+"\n"), &pubOut); err != nil {
		t.Fatalf("derivePublic: %v", err)
	}
	if got := strings.TrimSpace(pubOut.String()); got != fields["public_key"] {
		t.Errorf("-pubkey = %s, want %s", got, fields["public_key"])
	}
	mobilePub, err := mobile.PublicKeyFor(fields["private_key"])
	if err != nil || mobilePub != fields["public_key"] {
		t.Errorf("mobile.PublicKeyFor = %s, %v; want %s", mobilePub, err, fields["public_key"])
	}
}

func TestValidate(t *testing.T) {
	priv, _ := wireguard.GeneratePrivateKey()
	peer, _ := wireguard.GeneratePrivateKey()
	good := harnessServer{
		Name: "ams-02", Protocol: "wireguard", Endpoint: "192.0.2.10:51820",
		PrivateKey: priv.Base64(), PublicKey: peer.PublicKey().Base64(),
	}
	ss := harnessServer{
		Name: "sgp-01", Protocol: "shadowsocks", Endpoint: "192.0.2.20:8388",
		Method: "chacha20-ietf-poly1305", Password: "0123456789abcdefghijklmnopqrstuv",
	}
	weak := ss
	weak.Name, weak.Password = "lon-03", "short"

	cases := []struct {
		name     string
		cfg      any
		args     []string
		wantCode int
		wantOut  string
	}{
		{"valid", harnessConfig{Servers: []harnessServer{good, ss}, TunnelAddresses: []string{"10.9.0.2/32"}}, nil, 0, "OK: 2 server(s)"},
		{"one bad server", harnessConfig{Servers: []harnessServer{good, weak}, TunnelAddresses: []string{"10.9.0.2/32"}}, nil, 0, "OK with warnings"},
		{"one bad server strict", harnessConfig{Servers: []harnessServer{good, weak}, TunnelAddresses: []string{"10.9.0.2/32"}}, []string{"-strict"}, 1, "INVALID (strict)"},
		{"no tunnel addresses", harnessConfig{Servers: []harnessServer{good}}, nil, 1, "INVALID"},
		{"unknown field", map[string]any{"servers": []any{}, "tunnel_addresses": []string{"10.9.0.2"}, "kill_switch": true}, nil, 1, "INVALID"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			code := realMain(append([]string{"validate", "-config", path}, tc.args...), &out, &errOut)
			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tc.wantCode, out.String(), errOut.String())
			}
			if !strings.Contains(out.String(), tc.wantOut) {
				t.Errorf("stdout lacks %q:\n%s", tc.wantOut, out.String())
			}
			// Whatever validate prints, it must never echo a private key.
			if strings.Contains(out.String()+errOut.String(), priv.Base64()) {
				t.Error("validate output contains the private key")
			}
		})
	}
}

func TestValidateRequiresConfigFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"validate", "stray.json"}, &out, &errOut); code != exitUsage {
		t.Errorf("exit code = %d, want %d (a stray positional argument must not be ignored)", code, exitUsage)
	}
}

// harnessServer and harnessConfig build test configs in the JSON shape
// package mobile parses; its own types are unexported so gomobile does not
// bind them.
type harnessServer struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	Endpoint   string `json:"endpoint"`
	PrivateKey string `json:"private_key,omitempty"`
	PublicKey  string `json:"public_key,omitempty"`
	Method     string `json:"method,omitempty"`
	Password   string `json:"password,omitempty"`
}

type harnessConfig struct {
	Servers         []harnessServer `json:"servers"`
	TunnelAddresses []string        `json:"tunnel_addresses"`
}
