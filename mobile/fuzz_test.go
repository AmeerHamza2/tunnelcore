package mobile

import (
	"context"
	"testing"
)

// Fixed, valid keys for the fuzz seeds (generated once; not secret).
const (
	fuzzPrivA = "YNqHwpcAmVj0lVzPXhKdJr8OIXRBt7ldJBCbTMvMKE0="
	fuzzPubB  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

var fuzzSeeds = []string{
	`{"servers":[{"name":"fra-01","protocol":"wireguard","endpoint":"203.0.113.10:51820","private_key":"` + fuzzPrivA + `","public_key":"` + fuzzPubB + `","keepalive_seconds":25}],"tunnel_addresses":["10.64.0.7/32"],"dns_servers":["10.64.0.1"],"mtu":1420,"blocked_domains":["doubleclick.net"]}`,
	`{"servers":[{"name":"ss","protocol":"shadowsocks","endpoint":"203.0.113.10:8443","method":"chacha20-ietf-poly1305","password":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","plugins":[{"type":"prefix","prefix":"FgMB","label":"tls-record"},{"type":"tlsfrag","split_at":3}]}],"tunnel_addresses":["10.64.0.7","fd00::7/128"],"dns_servers":["10.64.0.1:53","[fd00::1]:53"]}`,
	`{"servers":[{"protocol":"wireguard","endpoint":"[2001:db8::1]:51820","private_key":"` + fuzzPrivA + `","public_key":"` + fuzzPubB + `","allowed_ips":["0.0.0.0/0","::/0"],"preshared_key":"` + fuzzPrivA + `"}],"tunnel_addresses":["10.0.0.2/24"],"race_stagger_ms":100,"race_timeout_ms":5000}`,
	`{"servers":[],"tunnel_addresses":[]}`,
	`{"servers":[{"protocol":"wireguard","keepalive_seconds":-1}],"tunnel_addresses":["x"]}`,
	`{"servers":[{"protocol":"shadowsocks","endpoint":"1.2.3.4:0","password":"short"}],"tunnel_addresses":["10.0.0.1"],"dns_servers":["1.2.3.4:0"]}`,
	`{} {}`,
	`null`,
	`[]`,
	``,
}

// FuzzNewTunnel feeds arbitrary configuration JSON — the one input the app
// passes straight through from the network — to NewTunnel. It must never
// panic, and a config it accepts must be one Start can build transports from:
// "valid at NewTunnel, broken at Start" is the failure mode validation exists
// to rule out.
func FuzzNewTunnel(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		tun, err := NewTunnel(raw)
		if err != nil {
			if tun != nil {
				t.Fatal("NewTunnel returned both a tunnel and an error")
			}
			return
		}
		if err := tun.SetConfig(raw); err != nil {
			t.Fatalf("SetConfig rejected a config NewTunnel accepted: %v", err)
		}
		cfg, err := parseConfig(raw)
		if err != nil {
			t.Fatalf("re-parse failed: %v", err)
		}
		if _, err := cfg.tunnelPrefixes(); err != nil {
			t.Fatalf("accepted config has bad tunnel addresses: %v", err)
		}
		ups, err := cfg.dnsUpstreams()
		if err != nil {
			t.Fatalf("accepted config has bad DNS servers: %v", err)
		}
		for _, u := range ups {
			if !u.IsValid() || u.Port() == 0 || u.Addr().IsUnspecified() {
				t.Fatalf("accepted config has unusable DNS upstream %v", u)
			}
		}
		if d := msDuration(cfg.RaceStaggerMS); d < 0 {
			t.Fatalf("race stagger overflowed to %v", d)
		}
		if d := msDuration(cfg.RaceTimeoutMS); d < 0 {
			t.Fatalf("race timeout overflowed to %v", d)
		}
		p := &configProvider{cfg: cfg, mtu: cfg.mtu()}
		trs, err := p.Candidates(context.Background())
		if err != nil || len(trs) == 0 {
			t.Fatalf("accepted config yields no transports: %v", err)
		}
		for _, tr := range trs {
			_ = tr.Close()
		}
		// Invalid descriptors are refused without touching anything.
		if err := tun.Start(-1); err == nil {
			t.Fatal("Start(-1) succeeded")
		}
		_ = tun.StatsJSON()
		_ = tun.Stop()
	})
}

// TestParseConfigRejectsHostileValues covers values that used to pass
// validation and then misbehave at Start: a DNS upstream on port 0 or the
// unspecified address made dnsproxy.New fail on every session build (an
// endless reconnect loop over a healthy transport); keepalive and race
// timings large enough to overflow time.Duration wrapped to negative or
// arbitrary values; and trailing data after the JSON object was silently
// ignored, contrary to the strict-parsing contract.
func TestParseConfigRejectsHostileValues(t *testing.T) {
	wg := func(extra string) string {
		return `{"servers":[{"name":"a","protocol":"wireguard","endpoint":"203.0.113.10:51820","private_key":"` +
			fuzzPrivA + `","public_key":"` + fuzzPubB + `"` + extra + `}],"tunnel_addresses":["10.64.0.7/32"]`
	}
	ok := wg("") + `}`
	if _, err := parseConfig(ok); err != nil {
		t.Fatalf("baseline config rejected: %v", err)
	}
	cases := map[string]string{
		"dns port 0":              wg("") + `,"dns_servers":["10.64.0.1:0"]}`,
		"dns unspecified":         wg("") + `,"dns_servers":["0.0.0.0"]}`,
		"dns unspecified v6":      wg("") + `,"dns_servers":["[::]:53"]}`,
		"keepalive overflow":      wg(`,"keepalive_seconds":18446744074`) + `}`,
		"keepalive huge":          wg(`,"keepalive_seconds":9223372036854775807`) + `}`,
		"keepalive negative":      wg(`,"keepalive_seconds":-5`) + `}`,
		"race stagger overflow":   wg("") + `,"race_stagger_ms":9223372036854775807}`,
		"race timeout overflow":   wg("") + `,"race_timeout_ms":9223372036854775}`,
		"race timeout negative":   wg("") + `,"race_timeout_ms":-1}`,
		"trailing garbage":        ok + `{"servers":[]}`,
		"trailing junk":           ok + `xyz`,
		"tunnel addr unspecified": `{"servers":[{"name":"a","protocol":"wireguard","endpoint":"203.0.113.10:51820","private_key":"` + fuzzPrivA + `","public_key":"` + fuzzPubB + `"}],"tunnel_addresses":["0.0.0.0/32"]}`,
		"tunnel addr mapped":      `{"servers":[{"name":"a","protocol":"wireguard","endpoint":"203.0.113.10:51820","private_key":"` + fuzzPrivA + `","public_key":"` + fuzzPubB + `"}],"tunnel_addresses":["::ffff:10.0.0.1/128"]}`,
	}
	for name, raw := range cases {
		if _, err := parseConfig(raw); err == nil {
			t.Errorf("%s: config accepted, want an error", name)
		}
	}
	// Trailing whitespace is not trailing data.
	if _, err := parseConfig(ok + " \n\t"); err != nil {
		t.Errorf("trailing whitespace rejected: %v", err)
	}
}
