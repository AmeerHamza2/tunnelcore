package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/ameerhamza2/tunnelcore/engine"
	"github.com/ameerhamza2/tunnelcore/metrics"
	"github.com/ameerhamza2/tunnelcore/transport"
	"github.com/ameerhamza2/tunnelcore/transport/shadowsocks"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// Demo tuning. These are shorter than the production defaults so the story
// fits in a few seconds; the production values are argued for in package
// transport and engine/backoff.go.
const (
	demoStagger     = 150 * time.Millisecond
	demoRaceTimeout = 3 * time.Second
	demoMTU         = 1400
	// demoBlobSize is large enough to need many TCP windows and many
	// Shadowsocks chunks, so the transfer exercises flow control on both
	// stacks rather than fitting in a single segment.
	demoBlobSize = 256 << 10
)

// Candidate keys, in the preference order the provider offers them.
const (
	candFra = "fra" // WireGuard, blackholed
	candAms = "ams" // WireGuard, live
	candLon = "lon" // Shadowsocks, decommissioned
	candSgp = "sgp" // Shadowsocks, live
)

// scenario selects which parts of the story run.
type scenario struct {
	name       string
	blurb      string
	candidates []string
	wgTraffic  bool
	handover   bool
	failover   bool
	ssTraffic  bool
}

var scenarios = []scenario{
	{
		name:       "all",
		blurb:      "race, WireGuard traffic, a network handover, an exit-node failure and failover to Shadowsocks",
		candidates: []string{candFra, candAms, candLon, candSgp},
		wgTraffic:  true, handover: true, failover: true, ssTraffic: true,
	},
	{
		name:       "wireguard",
		blurb:      "race past a blackholed server, UDP through WireGuard, and a network handover",
		candidates: []string{candFra, candAms},
		wgTraffic:  true, handover: true,
	},
	{
		name:       "shadowsocks",
		blurb:      "race past a dead server, then real TCP/HTTP through the userspace stack and Shadowsocks",
		candidates: []string{candLon, candSgp},
		ssTraffic:  true,
	},
	{
		name:       "failover",
		blurb:      "connect over WireGuard, kill the exit node, fail over to Shadowsocks without touching the tun",
		candidates: []string{candFra, candAms, candLon, candSgp},
		wgTraffic:  true, failover: true, ssTraffic: true,
	},
}

func scenarioNames() []string {
	var out []string
	for _, s := range scenarios {
		out = append(out, s.name)
	}
	return out
}

func findScenario(name string) (scenario, bool) {
	for _, s := range scenarios {
		if s.name == name {
			return s, true
		}
	}
	return scenario{}, false
}

// demoOptions configures runDemo.
type demoOptions struct {
	Scenario string
	Verbose  bool
	Color    bool
	// Pace is a pause between sections, so a live audience can read along.
	// Zero for tests and pipes.
	Pace time.Duration
}

func runDemoCmd(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("demo", "[-scenario all|wireguard|shadowsocks|failover] [-v] [-pace 400ms] [-color auto|always|never]", stderr)
	sc := fs.String("scenario", "all", "which story to run: "+strings.Join(scenarioNames(), ", "))
	verbose := fs.Bool("v", false, "verbose: trace every packet crossing the tun, and probe traffic")
	tty := stdoutIsTerminal()
	defaultPace := time.Duration(0)
	if tty {
		defaultPace = 400 * time.Millisecond
	}
	pace := fs.Duration("pace", defaultPace, "pause between sections (default 400ms on a terminal, 0 otherwise)")
	colorMode := fs.String("color", "auto", "colourise output: auto (only on a terminal), always, never")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if _, ok := findScenario(*sc); !ok {
		fmt.Fprintf(stderr, "unknown scenario %q (want one of: %s)\n", *sc, strings.Join(scenarioNames(), ", "))
		return errUsage
	}
	var color bool
	switch *colorMode {
	case "auto":
		color = tty
	case "always":
		color = true
	case "never":
		color = false
	default:
		fmt.Fprintf(stderr, "-color must be auto, always or never, not %q\n", *colorMode)
		return errUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runDemo(ctx, stdout, demoOptions{Scenario: *sc, Verbose: *verbose, Color: color, Pace: *pace})
}

// demo holds the state of one run.
type demo struct {
	ctx  context.Context
	opts demoOptions
	sc   scenario
	p    *printer

	phone *phone
	ams   *wgExit
	sgp   *ssExit
	fra   *blackhole

	specs   map[string]candidateSpec
	tracer  *tracer
	watcher *stateWatcher
	eng     *engine.Engine

	echo    *gonet.UDPConn
	pingSeq int

	sectionN int
	checks   []checkResult
}

type checkResult struct {
	name string
	err  error
}

// runDemo runs one scenario end to end and returns an error if any of its
// checks failed. Everything it starts, it stops before returning.
func runDemo(ctx context.Context, w io.Writer, opts demoOptions) (err error) {
	sc, ok := findScenario(opts.Scenario)
	if !ok {
		return fmt.Errorf("unknown scenario %q", opts.Scenario)
	}
	d := &demo{ctx: ctx, opts: opts, sc: sc, p: newPrinter(w, opts.Color, opts.Verbose)}
	defer d.p.close()

	d.p.line(d.p.bold("tunnelcore tun-harness · live engine demo") + d.p.dim(fmt.Sprintf(" · scenario %q", sc.name)))
	d.p.line(d.p.dim("The real engine, end to end, in one process: loopback only, no root, no tun device."))
	d.p.line(d.p.dim("Story: " + sc.blurb + "."))

	defer d.teardown()
	if err := d.setup(); err != nil {
		return fmt.Errorf("setting up the lab: %w", err)
	}
	if err := d.connect(); err != nil {
		return err
	}
	if sc.wgTraffic {
		d.section("Traffic over WireGuard")
		d.pingRound(3)
	}
	if sc.handover {
		d.handover()
	}
	if sc.failover {
		d.failover()
	}
	if sc.ssTraffic {
		d.section("Traffic over Shadowsocks (TCP via the userspace stack)")
		d.httpRound()
	}
	d.shutdown()
	d.report()
	return d.verdict()
}

func (d *demo) section(title string) {
	d.pause()
	d.sectionN++
	d.p.section(d.sectionN, title)
}

func (d *demo) pause() {
	if d.opts.Pace <= 0 {
		return
	}
	t := time.NewTimer(d.opts.Pace)
	defer t.Stop()
	select {
	case <-t.C:
	case <-d.ctx.Done():
	}
}

func (d *demo) check(name string, err error) bool {
	d.checks = append(d.checks, checkResult{name, err})
	return err == nil
}

// needs reports whether the scenario offers candidate key.
func (d *demo) needs(key string) bool {
	for _, c := range d.sc.candidates {
		if c == key {
			return true
		}
	}
	return false
}

// setup starts the exit nodes, the phone and the engine.
func (d *demo) setup() error {
	d.section("Lab")

	clientPriv, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return err
	}
	// The blackholed server's key is never used for anything: it only has to
	// be a well-formed key that nobody holds.
	strangerPriv, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return err
	}

	if d.ams, err = startWGExit("ams-02", clientPriv.PublicKey(), d.p); err != nil {
		return fmt.Errorf("wireguard exit node: %w", err)
	}
	if d.sgp, err = startSSExit("sgp-01", d.p); err != nil {
		return fmt.Errorf("shadowsocks exit node: %w", err)
	}
	if d.fra, err = startBlackhole(); err != nil {
		return fmt.Errorf("blackhole: %w", err)
	}
	dead, err := deadTCPAddr()
	if err != nil {
		return fmt.Errorf("dead endpoint: %w", err)
	}
	if d.phone, err = newPhone(phoneAddr, demoMTU, d.p); err != nil {
		return err
	}

	wgClient := func(name string, peer wireguard.Key, ep netip.AddrPort) func() (transport.Transport, error) {
		return func() (transport.Transport, error) {
			return wireguard.New(wireguard.Config{
				Name:          name,
				PrivateKey:    clientPriv,
				PeerPublicKey: peer,
				Endpoint:      ep,
				Addresses:     []netip.Prefix{netip.PrefixFrom(phoneAddr, 32)},
				AllowedIPs:    wireguard.FullTunnelAllowedIPs(),
			})
		}
	}
	ssClient := func(name string, server netip.AddrPort) func() (transport.Transport, error) {
		return func() (transport.Transport, error) {
			return shadowsocks.New(shadowsocks.Config{
				Name:        name,
				Server:      server.String(),
				Method:      ssMethod,
				Password:    d.sgp.password,
				ProbeTarget: probeTarget,
				DialTimeout: 2 * time.Second,
			})
		}
	}

	d.specs = map[string]candidateSpec{
		candFra: {
			name: "wireguard/fra-01", endpoint: d.fra.Addr().String() + "/udp",
			role:  "blackholed: swallows every packet (DPI-blocked WireGuard)",
			build: wgClient("wireguard/fra-01", strangerPriv.PublicKey(), d.fra.Addr()),
		},
		candAms: {
			name: "wireguard/ams-02", endpoint: d.ams.endpoint.String() + "/udp",
			role:  "live WireGuard exit node, UDP echo on " + udpEchoTarget.String(),
			build: wgClient("wireguard/ams-02", d.ams.pub, d.ams.endpoint),
		},
		candLon: {
			name: "shadowsocks/lon-03", endpoint: dead.String() + "/tcp",
			role:  "decommissioned: nothing listening (connection refused)",
			build: ssClient("shadowsocks/lon-03", dead),
		},
		candSgp: {
			name: "shadowsocks/sgp-01", endpoint: d.sgp.Addr().String() + "/tcp",
			role:  "live Shadowsocks exit node (" + string(ssMethod) + "), HTTP origin behind it",
			build: ssClient("shadowsocks/sgp-01", d.sgp.Addr()),
		},
	}

	var ordered []candidateSpec
	tw := tabwriter.NewWriter(&lineWriter{p: d.p}, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  #\tCANDIDATE\tENDPOINT\tROLE\n")
	for i, key := range d.sc.candidates {
		s := d.specs[key]
		ordered = append(ordered, s)
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\n", i+1, s.name, s.endpoint, s.role)
	}
	_ = tw.Flush()
	d.p.line(fmt.Sprintf("  phone: %s/32, mtu %d, a userspace TCP/IP stack whose network interface is the engine's TunDevice", phoneAddr, demoMTU))

	d.tracer = newTracer(d.p, ordered)
	d.watcher = newStateWatcher(d.p, d.tracer)
	d.eng, err = engine.New(engine.Config{
		Tun:             d.phone.Tun(),
		Provider:        d.tracer.provider(demoStagger, demoRaceTimeout),
		TunnelAddresses: []netip.Prefix{netip.PrefixFrom(phoneAddr, 32)},
		RaceStagger:     demoStagger,
		RaceTimeout:     demoRaceTimeout,
		Backoff:         &engine.Backoff{Base: 200 * time.Millisecond, Max: time.Second},
		OnStateChange:   d.watcher.observe,
	})
	return err
}

func (d *demo) connect() error {
	d.section("Connect: race the candidates")
	if err := d.eng.Start(); err != nil {
		return err
	}
	c, err := d.watcher.awaitConnected(d.ctx, 2*demoRaceTimeout)
	if !d.check("initial connect", err) {
		d.p.event(tagCheck, "%s initial connect: %v", d.p.bad("✗"), err)
		return err
	}
	want := d.specs[d.sc.candidates[len(d.sc.candidates)-1]].name
	if d.needs(candAms) {
		want = d.specs[candAms].name
	}
	d.expectTransport("race winner", c.Transport, want)
	return nil
}

func (d *demo) expectTransport(what, got, want string) {
	var err error
	if got != want {
		err = fmt.Errorf("got %s, want %s", orDash(got), want)
	}
	d.check(what, err)
	if err != nil {
		d.p.event(tagCheck, "%s %s: %v", d.p.bad("✗"), what, err)
	}
}

// pingRound sends n datagrams from an app on the phone to the echo service
// behind the WireGuard exit node and waits for each reply.
func (d *demo) pingRound(n int) {
	if d.echo == nil {
		c, err := d.phone.DialUDP(udpEchoTarget)
		if !d.check("open UDP socket on the phone", err) {
			return
		}
		d.echo = c
	}
	buf := make([]byte, 512)
	var failed error
	for i := 0; i < n; i++ {
		d.pingSeq++
		msg := fmt.Sprintf("ping %d", d.pingSeq)
		want := "pong" + strings.TrimPrefix(msg, "ping")
		d.p.event(tagApp, "▸ udp %s → %s %s", d.echo.LocalAddr(), udpEchoTarget, quote([]byte(msg)))
		start := time.Now()
		if _, err := d.echo.Write([]byte(msg)); err != nil {
			failed = err
			break
		}
		_ = d.echo.SetReadDeadline(time.Now().Add(2 * time.Second))
		nr, err := d.echo.Read(buf)
		if err != nil {
			failed = fmt.Errorf("%s: no reply: %w", msg, err)
			d.p.event(tagApp, "%s no reply to %q: %v", d.p.bad("✗"), msg, err)
			break
		}
		if got := string(buf[:nr]); got != want {
			failed = fmt.Errorf("reply %q, want %q", got, want)
			break
		}
		d.p.event(tagApp, "◂ %s %s round trip %s", d.p.ok("✓"), quote(buf[:nr]), ms(time.Since(start)))
	}
	d.check(fmt.Sprintf("UDP echo through WireGuard (to ping %d)", d.pingSeq), failed)
}

// handover simulates the phone moving from Wi-Fi to cellular.
func (d *demo) handover() {
	d.section("Network handover (Wi-Fi → cellular)")
	d.p.event(tagNet, "OS connectivity callback fired: calling engine.NetworkChanged()")
	start := time.Now()
	d.eng.NetworkChanged()
	c, err := d.watcher.awaitConnected(d.ctx, 2*demoRaceTimeout)
	if !d.check("reconnect after network change", err) {
		d.p.event(tagCheck, "%s reconnect: %v", d.p.bad("✗"), err)
		return
	}
	d.p.event(tagNet, "back up in %s, with no backoff: a network change is not a failure", ms(time.Since(start)))
	d.expectTransport("transport after handover", c.Transport, d.specs[candAms].name)
	d.p.event(tagInfo, "same app socket, new tunnel session and source port: the exit node roams to it")
	d.pingRound(2)
}

// failover kills the WireGuard exit node and expects the engine to land on
// Shadowsocks without the phone noticing anything but a pause.
func (d *demo) failover() {
	d.section("Exit-node failure and failover")
	active := d.eng.Stats().ActiveTransport
	d.p.event(tagFault, "killing exit node %s (socket closed, no goodbye)", active)
	d.ams.Close()
	// WireGuard is silent by design, so a dead peer looks exactly like an
	// idle one; detecting it is a liveness policy (missed keepalives, a
	// failed handshake on rekey) that the engine leaves to its embedder.
	// Closing the transport is what that policy would do on firing.
	d.p.event(tagFault, "liveness check fires: closing the active transport %s", active)
	start := time.Now()
	if !d.tracer.closeActive(active) {
		d.check("inject transport failure", fmt.Errorf("no live instance of %q", active))
		return
	}
	c, err := d.watcher.awaitConnected(d.ctx, 3*demoRaceTimeout)
	if !d.check("failover", err) {
		d.p.event(tagCheck, "%s failover: %v", d.p.bad("✗"), err)
		return
	}
	d.p.event(tagNet, "failed over in %s (backoff + race); the tun device was never touched", ms(time.Since(start)))
	d.expectTransport("transport after failover", c.Transport, d.specs[candSgp].name)
}

// httpRound fetches a page and a larger blob from the phone, over whatever
// stream transport is up.
func (d *demo) httpRound() {
	client := d.phone.HTTPClient(10 * time.Second)
	defer client.CloseIdleConnections()
	base := "http://" + webTarget.String()

	d.p.event(tagApp, "▸ GET %s/  (a TCP connection from the phone's stack)", base)
	start := time.Now()
	body, status, err := d.get(client, base+"/")
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("status %d", status)
	}
	if d.check("HTTP GET through Shadowsocks", err) {
		d.p.event(tagApp, "◂ %s %d %s in %s: %s", d.p.ok("✓"), status, http.StatusText(status),
			ms(time.Since(start)), quote(bytes.TrimSpace(body)))
	} else {
		d.p.event(tagApp, "%s GET /: %v", d.p.bad("✗"), err)
		return
	}

	url := fmt.Sprintf("%s/blob?size=%d", base, demoBlobSize)
	d.p.event(tagApp, "▸ GET %s", url)
	start = time.Now()
	body, status, err = d.get(client, url)
	took := time.Since(start)
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("status %d", status)
	}
	if err == nil && !bytes.Equal(body, blobPattern(demoBlobSize)) {
		err = fmt.Errorf("body corrupted: got %d bytes, want %d matching the pattern", len(body), demoBlobSize)
	}
	if d.check("bulk transfer integrity", err) {
		rate := float64(len(body)) / took.Seconds() / (1 << 20)
		d.p.event(tagApp, "◂ %s %s in %s (%.1f MiB/s), every byte verified",
			d.p.ok("✓"), humanBytes(uint64(len(body))), ms(took), rate)
	} else {
		d.p.event(tagApp, "%s GET /blob: %v", d.p.bad("✗"), err)
	}
}

func (d *demo) get(client *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(d.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func (d *demo) shutdown() {
	d.section("Shutdown")
	if d.echo != nil {
		_ = d.echo.Close()
		d.echo = nil
	}
	start := time.Now()
	err := d.eng.Stop()
	if d.check("clean stop", err) {
		d.p.event(tagState, "engine.Stop returned in %s; every goroutine touching the tun has exited", ms(time.Since(start)))
	}
}

// report prints the metrics the engine collected, merged with the harness's
// own view of the races.
func (d *demo) report() {
	d.section("Metrics")
	snap := d.eng.Snapshot()
	st := d.eng.Stats()
	byName := make(map[string]metrics.TransportSnapshot, len(snap.Transports))
	for _, ts := range snap.Transports {
		byName[ts.Name] = ts
	}

	tw := tabwriter.NewWriter(&lineWriter{p: d.p}, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  CANDIDATE\tOFFERED\tDIALED\tWON\tABANDONED\tFAILED\tSUCCESS\tP50\tP95\t")
	for _, cs := range d.tracer.snapshot() {
		ts, ok := byName[cs.spec.name]
		rate, p50, p95 := "-", "-", "-"
		if ok && !math.IsNaN(ts.SuccessRate) {
			rate = fmt.Sprintf("%.0f%% (%d/%d)", ts.SuccessRate*100, ts.Successes, ts.Attempts)
		}
		if ok && ts.Successes > 0 {
			p50, p95 = "≤"+ms(ts.LatencyP50), "≤"+ms(ts.LatencyP95)
		}
		fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\t%s\t\n",
			cs.spec.name, cs.offered, cs.dialed, cs.won, cs.abandoned, cs.failed+cs.timedOut, rate, p50, p95)
	}
	_ = tw.Flush()

	d.p.line(d.p.dim("  SUCCESS and P50/P95 come from the engine's collector, which excludes abandoned attempts by design;"))
	d.p.line(d.p.dim("  latencies are bucket upper bounds. OFFERED/DIALED/ABANDONED are the harness's own count of the races."))
	d.p.line("")

	overall := "n/a"
	if !math.IsNaN(snap.OverallSuccessRate) {
		overall = fmt.Sprintf("%.0f%%", snap.OverallSuccessRate*100)
	}
	tw = tabwriter.NewWriter(&lineWriter{p: d.p}, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  tunnel up\t%s in %d packets\n", humanBytes(snap.BytesUp), snap.PacketsUp)
	fmt.Fprintf(tw, "  tunnel down\t%s in %d packets\n", humanBytes(snap.BytesDown), snap.PacketsDown)
	fmt.Fprintf(tw, "  reconnects\t%d\n", snap.Reconnects)
	fmt.Fprintf(tw, "  proxied flows\t%d opened, %d failed\n", snap.FlowsOpened, snap.FlowsFailed)
	fmt.Fprintf(tw, "  dropped between sessions\t%d packets\n", st.DroppedNoSession)
	fmt.Fprintf(tw, "  connection success rate\t%s overall\n", overall)
	if d.needs(candFra) {
		fmt.Fprintf(tw, "  blackhole\tswallowed %d handshake packets without a word\n", d.fra.swallowed.Load())
	}
	if d.needs(candAms) {
		fmt.Fprintf(tw, "  wireguard exit\tdecrypted %d UDP packets\n", d.ams.decrypted.Load())
	}
	if d.needs(candSgp) {
		fmt.Fprintf(tw, "  shadowsocks exit\tforwarded %d streams to the origin\n", d.sgp.streams.Load())
	}
	_ = tw.Flush()
}

// verdict prints the check summary and turns failures into an error.
func (d *demo) verdict() error {
	var failed []string
	for _, c := range d.checks {
		if c.err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", c.name, c.err))
		}
	}
	d.p.line("")
	if len(failed) == 0 {
		d.p.line(d.p.ok(fmt.Sprintf("✓ all %d checks passed", len(d.checks))) +
			d.p.dim(fmt.Sprintf(" in %.1fs", d.p.elapsed().Seconds())))
		return nil
	}
	d.p.line(d.p.bad(fmt.Sprintf("✗ %d of %d checks failed:", len(failed), len(d.checks))))
	for _, f := range failed {
		d.p.line("    " + f)
	}
	return errors.New(strings.Join(failed, "; "))
}

// teardown stops everything setup started, in dependency order: the engine
// first (it owns the tun and the client transports), then the exit nodes it
// was talking to, then the phone.
func (d *demo) teardown() {
	if d.echo != nil {
		_ = d.echo.Close()
	}
	if d.eng != nil {
		_ = d.eng.Stop()
	}
	if d.ams != nil {
		d.ams.Close()
	}
	if d.sgp != nil {
		d.sgp.Close()
	}
	if d.fra != nil {
		d.fra.Close()
	}
	if d.phone != nil {
		d.phone.Close()
	}
}

// lineWriter feeds tabwriter output through the printer line by line, so
// tables share the printer's lock with the concurrent event stream.
type lineWriter struct {
	p   *printer
	buf []byte
}

func (lw *lineWriter) Write(b []byte) (int, error) {
	lw.buf = append(lw.buf, b...)
	for {
		i := bytes.IndexByte(lw.buf, '\n')
		if i < 0 {
			return len(b), nil
		}
		lw.p.line(string(lw.buf[:i]))
		lw.buf = lw.buf[i+1:]
	}
}
