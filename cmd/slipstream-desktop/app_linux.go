//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ameerhamza2/tunnelcore/mobile"
)

// location is one exit server, as written by deploy/server-setup.sh.
type location struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Country  string          `json:"country"`
	PublicIP string          `json:"public_ip"`
	Config   json.RawMessage `json:"config"`

	cfg map[string]any // Config decoded, for merging the device key
}

type event struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"` // state, info, warn, error
	Text string    `json:"text"`
}

type ipInfo struct {
	IP          string  `json:"ip"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	ISP         string  `json:"isp"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	CheckedAt   string  `json:"checked_at"`
	Error       string  `json:"error,omitempty"`
}

type app struct {
	privKey string
	locs    []*location

	mu        sync.Mutex
	tunnel    *mobile.Tunnel
	net       *netState
	current   *location
	state     string
	transport string
	lastErr   string
	connAt    time.Time
	wgBlocked bool
	events    []event
	original  *ipInfo // public IP before connecting, for the before/after card
	probes    map[string]json.RawMessage
	probedAt  time.Time
	busy      bool
}

func runServe(args []string) error {
	fs := newServeFlags()
	if err := fs.parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("serve needs root to create the tunnel interface: run it with sudo")
	}
	priv, err := loadOrCreateKey(fs.key)
	if err != nil {
		return err
	}
	locs, err := loadLocations(fs.locations)
	if err != nil {
		return err
	}
	a := &app{privKey: priv, locs: locs, state: "disconnected", probes: map[string]json.RawMessage{}}
	cleanupLeftovers()
	go a.refreshOriginal()
	pub, _ := mobile.PublicKeyFor(priv)
	a.logf("info", "engine %s ready · device public key %s… · %d location(s)", mobile.Version(), pub[:10], len(locs))

	srv := &http.Server{Addr: fs.listen, Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second}
	go a.shutdownOnSignal(srv)
	fmt.Fprintf(os.Stderr, "control panel on http://%s (open it from your computer's browser)\n", fs.listen)
	for _, addr := range localAddrs() {
		fmt.Fprintf(os.Stderr, "  http://%s%s\n", addr, portOf(fs.listen))
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func loadLocations(dir string) ([]*location, error) {
	if dir == "" {
		return nil, fmt.Errorf("-locations DIR is required (a folder with the location .json files from server-setup.sh): %w", errUsage)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []*location
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var l location
		if err := json.Unmarshal(b, &l); err != nil || len(l.Config) == 0 {
			fmt.Fprintf(os.Stderr, "skipping %s: not a location file\n", f)
			continue
		}
		if err := json.Unmarshal(l.Config, &l.cfg); err != nil {
			return nil, fmt.Errorf("%s: config: %w", f, err)
		}
		if l.ID == "" {
			l.ID = strings.TrimSuffix(filepath.Base(f), ".json")
		}
		out = append(out, &l)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no location files found in %s", dir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// engineConfig is the location's config with the device private key merged
// into every WireGuard entry, the same merge the phone app does.
func (a *app) engineConfig(l *location) (string, error) {
	cfg := map[string]any{}
	for k, v := range l.cfg {
		cfg[k] = v
	}
	servers, _ := cfg["servers"].([]any)
	merged := make([]any, 0, len(servers))
	for _, s := range servers {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		if c["protocol"] == "wireguard" {
			c["private_key"] = a.privKey
		}
		merged = append(merged, c)
	}
	cfg["servers"] = merged
	b, err := json.Marshal(cfg)
	return string(b), err
}

func (l *location) endpoints(protocol string) []netip.AddrPort {
	var out []netip.AddrPort
	servers, _ := l.cfg["servers"].([]any)
	for _, s := range servers {
		m, _ := s.(map[string]any)
		if m == nil || (protocol != "" && m["protocol"] != protocol) {
			continue
		}
		ep, _ := m["endpoint"].(string)
		if ap, err := netip.ParseAddrPort(ep); err == nil {
			out = append(out, ap)
		}
	}
	return out
}

func (l *location) serverIPs() []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, ep := range l.endpoints("") {
		if !seen[ep.Addr()] {
			seen[ep.Addr()] = true
			out = append(out, ep.Addr())
		}
	}
	return out
}

func (a *app) logf(kind, format string, args ...any) {
	e := event{At: time.Now(), Kind: kind, Text: fmt.Sprintf(format, args...)}
	a.mu.Lock()
	a.events = append(a.events, e)
	if len(a.events) > 200 {
		a.events = a.events[len(a.events)-200:]
	}
	a.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s %-5s %s\n", e.At.Format("15:04:05.000"), kind, e.Text)
}

// OnStateChange implements mobile.StateListener.
func (a *app) OnStateChange(state, reason, transportName, errMsg string) {
	a.mu.Lock()
	a.state = state
	if state == "connected" {
		a.transport = transportName
		if a.connAt.IsZero() {
			a.connAt = time.Now()
		}
	}
	if errMsg != "" {
		a.lastErr = errMsg
	}
	a.mu.Unlock()

	text := "engine: " + state
	if transportName != "" {
		text += " via " + transportName
	}
	if reason != "" {
		text += " (" + reason + ")"
	}
	if errMsg != "" {
		text += " — " + errMsg
	}
	kind := "state"
	if errMsg != "" {
		kind = "warn"
	}
	a.logf(kind, "%s", text)
}

func (a *app) connect(id string) error {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return errors.New("busy, try again in a moment")
	}
	a.busy = true
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.busy = false
		if a.tunnel == nil {
			a.state = "disconnected"
		}
		a.mu.Unlock()
	}()

	var loc *location
	for _, l := range a.locs {
		if l.ID == id {
			loc = l
		}
	}
	if loc == nil {
		return fmt.Errorf("unknown location %q", id)
	}
	a.disconnectLocked()

	a.mu.Lock()
	a.state, a.transport, a.lastErr, a.connAt = "connecting", "", "", time.Time{}
	a.mu.Unlock()

	cfgJSON, err := a.engineConfig(loc)
	if err != nil {
		return err
	}
	t, err := mobile.NewTunnel(cfgJSON)
	if err != nil {
		return fmt.Errorf("config rejected: %w", err)
	}
	t.SetStateListener(a)

	st, err := newNetState(loc.serverIPs())
	if err != nil {
		return err
	}
	var cfg struct {
		Addrs []string `json:"tunnel_addresses"`
		MTU   int      `json:"mtu"`
	}
	_ = json.Unmarshal(loc.Config, &cfg)
	if len(cfg.Addrs) == 0 {
		return errors.New("location has no tunnel_addresses")
	}
	prefix, err := netip.ParsePrefix(cfg.Addrs[0])
	if err != nil {
		return err
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}

	a.logf("info", "connecting to %s · racing %d transports", loc.Name, len(loc.endpoints("")))
	fd, err := createTun(prefix, cfg.MTU)
	if err != nil {
		return err
	}
	// A block chosen before connecting must be in place before the race,
	// so the race sees the same network the user asked for.
	a.mu.Lock()
	blocked := a.wgBlocked
	a.mu.Unlock()
	if blocked {
		if err := setWireGuardBlocked(loc.endpoints("wireguard"), true); err != nil {
			restoreNetwork(st)
			return err
		}
		a.logf("warn", "firewall drops all WireGuard packets to %s, like a censoring network", loc.PublicIP)
	}
	if err := t.Start(fd); err != nil {
		restoreNetwork(st)
		_ = setWireGuardBlocked(nil, false)
		return fmt.Errorf("starting engine: %w", err)
	}
	if err := routeIntoTunnel(st); err != nil {
		_ = t.Stop()
		restoreNetwork(st)
		return err
	}
	a.mu.Lock()
	a.tunnel, a.net, a.current = t, st, loc
	a.mu.Unlock()
	a.logf("info", "routing all traffic through %s (exit IP %s)", tunName, loc.PublicIP)
	return nil
}

func (a *app) disconnect() {
	a.mu.Lock()
	if a.busy {
		a.mu.Unlock()
		return
	}
	a.busy = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); a.busy = false; a.mu.Unlock() }()
	a.disconnectLocked()
}

// disconnectLocked tears down the session. "Locked" refers to the busy flag,
// which the caller holds; a.mu is taken inside.
func (a *app) disconnectLocked() {
	a.mu.Lock()
	t, st, loc := a.tunnel, a.net, a.current
	a.tunnel, a.net = nil, nil
	a.mu.Unlock()
	if t == nil {
		return
	}
	a.logf("info", "disconnecting from %s", loc.Name)
	restoreNetwork(st) // routes first, so nothing is sent into a closing tunnel
	_ = t.Stop()
	_ = setWireGuardBlocked(nil, false)
	a.mu.Lock()
	a.state, a.transport, a.connAt, a.current = "disconnected", "", time.Time{}, nil
	a.mu.Unlock()
	go a.refreshOriginal()
}

// refreshOriginal records the public IP without the VPN, for the before/after
// card. It runs in the background so it never delays a connect, and discards
// its answer if a tunnel came up while it was asking.
func (a *app) refreshOriginal() {
	a.mu.Lock()
	if a.tunnel != nil || a.busy {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()
	info := lookupIP(5 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.tunnel == nil && !a.busy && (info.Error == "" || a.original == nil) {
		a.original = &info
	}
}

func (a *app) setBlock(on bool) error {
	a.mu.Lock()
	a.wgBlocked = on
	t, loc := a.tunnel, a.current
	a.mu.Unlock()
	if !on {
		_ = setWireGuardBlocked(nil, false)
		a.logf("info", "WireGuard unblocked")
	} else if loc != nil {
		if err := setWireGuardBlocked(loc.endpoints("wireguard"), true); err != nil {
			return err
		}
		a.logf("warn", "firewall now drops all WireGuard packets to %s, like a censoring network", loc.PublicIP)
	} else {
		a.logf("info", "WireGuard will be blocked on the next connection")
	}
	if t != nil {
		// A real phone notices this through the dead-peer monitor within
		// seconds; signalling a network change makes the demo immediate.
		a.logf("info", "re-racing transports")
		t.NetworkChanged()
	}
	return nil
}

// stats is what the panel polls.
type stats struct {
	State      string          `json:"state"`
	Transport  string          `json:"transport"`
	Location   *location       `json:"location"`
	Error      string          `json:"error,omitempty"`
	WGBlocked  bool            `json:"wg_blocked"`
	Since      int64           `json:"connected_seconds"`
	Engine     json.RawMessage `json:"engine"`
	Events     []event         `json:"events"`
	Original   *ipInfo         `json:"original_ip"`
	ServerTime int64           `json:"server_time_ms"`
}

func (a *app) snapshot() stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := stats{
		State:      a.state,
		Transport:  a.transport,
		Location:   a.current,
		Error:      a.lastErr,
		WGBlocked:  a.wgBlocked,
		Original:   a.original,
		ServerTime: time.Now().UnixMilli(),
	}
	if !a.connAt.IsZero() {
		s.Since = int64(time.Since(a.connAt).Seconds())
	}
	if a.tunnel != nil {
		s.Engine = json.RawMessage(a.tunnel.StatsJSON())
	}
	n := len(a.events)
	if n > 60 {
		n = 60
	}
	s.Events = append([]event(nil), a.events[len(a.events)-n:]...)
	return s
}

// probeAll measures this machine's latency to every location, through the
// engine's own probe (UDP echo for WireGuard, TCP connect for Shadowsocks).
func (a *app) probeAll() map[string]json.RawMessage {
	a.mu.Lock()
	if time.Since(a.probedAt) < 15*time.Second && len(a.probes) > 0 {
		out := a.probes
		a.mu.Unlock()
		return out
	}
	a.mu.Unlock()

	out := map[string]json.RawMessage{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, l := range a.locs {
		wg.Add(1)
		go func(l *location) {
			defer wg.Done()
			cfg, err := a.engineConfig(l)
			if err != nil {
				return
			}
			t, err := mobile.NewTunnel(cfg)
			if err != nil {
				return
			}
			r := t.ProbeServersJSON(1200)
			mu.Lock()
			out[l.ID] = json.RawMessage(r)
			mu.Unlock()
		}(l)
	}
	wg.Wait()
	a.mu.Lock()
	a.probes, a.probedAt = out, time.Now()
	a.mu.Unlock()
	return out
}

// lookupIP asks a public service which IP and location the internet sees.
// It is an ordinary request from this machine, so while connected it goes
// through the tunnel and reports the exit server's address.
func lookupIP(timeout time.Duration) ipInfo {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp4", addr)
			},
			DisableKeepAlives: true,
		},
	}
	now := time.Now().Format("15:04:05")
	resp, err := client.Get("http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,lat,lon,query")
	if err == nil {
		defer resp.Body.Close()
		var r struct {
			Status, Message, Country, CountryCode, RegionName, City, ISP, Query string
			Lat, Lon                                                            float64
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if json.Unmarshal(b, &r) == nil && r.Status == "success" {
			return ipInfo{IP: r.Query, City: r.City, Region: r.RegionName, Country: r.Country,
				CountryCode: r.CountryCode, ISP: r.ISP, Lat: r.Lat, Lon: r.Lon, CheckedAt: now}
		}
	}
	// Fallback service.
	resp2, err2 := client.Get("https://ipinfo.io/json")
	if err2 != nil {
		msg := "lookup failed"
		if err != nil {
			msg = err.Error()
		}
		return ipInfo{Error: msg, CheckedAt: now}
	}
	defer resp2.Body.Close()
	var r2 struct{ IP, City, Region, Country, Org string }
	b, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<16))
	if json.Unmarshal(b, &r2) != nil || r2.IP == "" {
		return ipInfo{Error: "unexpected response", CheckedAt: now}
	}
	return ipInfo{IP: r2.IP, City: r2.City, Region: r2.Region, Country: r2.Country,
		CountryCode: r2.Country, ISP: r2.Org, CheckedAt: now}
}

// speedTest downloads a fixed amount through whatever route is current.
func speedTest(bytes int) (map[string]any, error) {
	client := &http.Client{Timeout: 25 * time.Second}
	start := time.Now()
	resp, err := client.Get(fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", bytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	ttfb := time.Since(start)
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		return nil, err
	}
	el := time.Since(start)
	return map[string]any{
		"bytes":   n,
		"seconds": el.Seconds(),
		"mbps":    float64(n) * 8 / el.Seconds() / 1e6,
		"ttfb_ms": ttfb.Milliseconds(),
	}, nil
}

func localAddrs() []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Name == tunName {
			continue
		}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.To4() != nil {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out
}

func portOf(listen string) string {
	if i := strings.LastIndex(listen, ":"); i >= 0 {
		return listen[i:]
	}
	return ""
}
