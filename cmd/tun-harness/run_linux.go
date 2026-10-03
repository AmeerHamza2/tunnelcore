//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ameerhamza2/tunnelcore/mobile"
)

// runTunCmd drives a real Linux tun interface with the engine.
//
// It goes through the mobile package's bound API — NewTunnel, Start(fd),
// NetworkChanged, StatsJSON, Stop — rather than assembling an engine by hand.
// That is the point of it: on a Linux box it exercises exactly the code path
// an Android app takes, down to fd ownership transfer and the non-blocking fd
// wrapper, with a kernel interface in place of VpnService.
func runTunCmd(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("run", "-config file.json [-tun tun0] [-stats 5s]", stderr)
	path := fs.String("config", "", "path to the JSON config (- for stdin)")
	ifName := fs.String("tun", "tun0", "name of the tun interface to attach to")
	statsEvery := fs.Duration("stats", 5*time.Second, "interval between stats lines (0 disables)")
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: tun-harness run -config file.json [-tun tun0] [-stats 5s]

Attaches the engine to a tun interface and runs until SIGINT or SIGTERM.
Requires root or CAP_NET_ADMIN. Prepare the interface first, with an MTU that
matches the config's "mtu" (default 1420), for example:

  ip tuntap add dev tun0 mode tun
  ip addr add 10.9.0.2/32 dev tun0
  ip link set dev tun0 mtu 1420 up
  ip route add 203.0.113.0/24 dev tun0      # route only a test prefix

Route only test prefixes unless you have policy routing in place: the engine's
own sockets to the exit node are ordinary sockets, and a default route into
the tunnel would send its handshakes into the tunnel it is building.

Send SIGUSR1 to simulate a network change (the engine reconnects at once).

Flags:
`)
		fs.PrintDefaults()
	}
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *path == "" {
		fmt.Fprintln(stderr, "-config is required")
		fs.Usage()
		return errUsage
	}

	raw, err := readConfig(*path)
	if err != nil {
		return err
	}
	tunnel, err := mobile.NewTunnel(raw)
	if err != nil {
		return fmt.Errorf("config rejected: %w", err)
	}

	fd, err := openTun(*ifName)
	if err != nil {
		return err
	}

	// logf is called from the engine's goroutine (state changes) and from
	// this one (signals, stats), so lines are serialised to keep them whole.
	start := time.Now()
	var logMu sync.Mutex
	logf := func(format string, a ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		fmt.Fprintf(stdout, "[%8.3fs] "+format+"\n", append([]any{time.Since(start).Seconds()}, a...)...)
	}
	tunnel.SetStateListener(stateLogger{logf: logf})

	// Start takes ownership of fd, including on failure, so it is not closed
	// here on either path.
	if err := tunnel.Start(fd); err != nil {
		return fmt.Errorf("starting tunnel on %s: %w", *ifName, err)
	}
	logf("attached to %s (fd %d); Ctrl-C to stop, SIGUSR1 to simulate a network change", *ifName, fd)

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
	defer signal.Stop(sigs)

	var tick <-chan time.Time
	if *statsEvery > 0 {
		t := time.NewTicker(*statsEvery)
		defer t.Stop()
		tick = t.C
	}

	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGUSR1 {
				logf("SIGUSR1: signalling a network change")
				tunnel.NetworkChanged()
				continue
			}
			// Stats first: once Stop returns, the mobile Tunnel has released
			// its engine and StatsJSON reports an idle tunnel with no
			// counters, so this is the last moment the session's totals exist.
			logStats(logf, tunnel.StatsJSON())
			logf("%s: stopping", sig)
			return tunnel.Stop()
		case <-tick:
			logStats(logf, tunnel.StatsJSON())
		}
	}
}

// openTun attaches to (or, with CAP_NET_ADMIN, creates) the named tun
// interface and returns its fd.
//
// IFF_NO_PI is essential: without it the kernel prefixes every packet with a
// 4-byte flags+protocol header, which is the Apple utun framing in all but
// name, and the engine — built for Linux/Android framing on this platform —
// would reject every packet as malformed.
func openTun(name string) (int, error) {
	if len(name) >= unix.IFNAMSIZ {
		return -1, fmt.Errorf("interface name %q longer than %d bytes", name, unix.IFNAMSIZ-1)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("opening /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		if err == unix.EPERM {
			return -1, fmt.Errorf("TUNSETIFF %s: %w (run as root or grant CAP_NET_ADMIN)", name, err)
		}
		return -1, fmt.Errorf("TUNSETIFF %s: %w", name, err)
	}
	return fd, nil
}

// stateLogger adapts mobile.StateListener to the harness's line format.
type stateLogger struct {
	logf func(string, ...any)
}

func (l stateLogger) OnStateChange(state, reason, transportName, errMsg string) {
	line := fmt.Sprintf("state  %-13s reason=%s", state, reason)
	if transportName != "" {
		line += " transport=" + transportName
	}
	if errMsg != "" {
		line += " err=" + errMsg
	}
	l.logf("%s", line)
}

// logStats prints the interesting subset of StatsJSON on one line.
//
// It decodes the same JSON the app receives rather than reading engine
// internals, so what is printed here is exactly what a support bundle from a
// phone would contain.
func logStats(logf func(string, ...any), raw string) {
	var s struct {
		State           string  `json:"state"`
		ActiveTransport string  `json:"active_transport"`
		Reconnects      uint64  `json:"reconnects"`
		PacketsIn       uint64  `json:"packets_in"`
		PacketsOut      uint64  `json:"packets_out"`
		BytesUp         uint64  `json:"bytes_up"`
		BytesDown       uint64  `json:"bytes_down"`
		FlowsOpened     uint64  `json:"flows_opened"`
		DNSQueries      uint64  `json:"dns_queries"`
		SuccessRate     float64 `json:"overall_success_rate"`
	}
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		logf("stats  (undecodable: %v)", err)
		return
	}
	rate := "n/a"
	if s.SuccessRate >= 0 {
		rate = fmt.Sprintf("%.0f%%", s.SuccessRate*100)
	}
	logf("stats  state=%s via=%s up=%s/%dpkt down=%s/%dpkt flows=%d dns=%d reconnects=%d success=%s",
		s.State, orDash(s.ActiveTransport), humanBytes(s.BytesUp), s.PacketsOut,
		humanBytes(s.BytesDown), s.PacketsIn, s.FlowsOpened, s.DNSQueries, s.Reconnects, rate)
}
