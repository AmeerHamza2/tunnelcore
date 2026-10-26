//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	tunName    = "slip0"
	blockTag   = "slipstream-demo-block"
	ipv6Sysctl = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
)

// run executes a command and returns its combined output on failure.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func runQuiet(name string, args ...string) { _ = exec.Command(name, args...).Run() }

// uplink is the machine's real route to the internet, captured before the
// tunnel takes over the default route.
type uplink struct {
	Gateway string
	Dev     string
}

func currentUplink() (uplink, error) {
	out, err := exec.Command("ip", "-4", "-j", "route", "show", "default").Output()
	if err != nil {
		return uplink{}, fmt.Errorf("reading default route: %w", err)
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if err := json.Unmarshal(out, &routes); err != nil {
		return uplink{}, fmt.Errorf("parsing default route: %w", err)
	}
	for _, r := range routes {
		if r.Dev != "" && r.Dev != tunName {
			return uplink{Gateway: r.Gateway, Dev: r.Dev}, nil
		}
	}
	return uplink{}, fmt.Errorf("no default route: is the machine online?")
}

// routeTo is how the machine reaches ip right now, before the tunnel exists.
func routeTo(ip netip.Addr) (uplink, error) {
	out, err := exec.Command("ip", "-4", "-j", "route", "get", ip.String()).Output()
	if err != nil {
		return uplink{}, fmt.Errorf("no route to %s: %w", ip, err)
	}
	var routes []struct {
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if err := json.Unmarshal(out, &routes); err != nil || len(routes) == 0 || routes[0].Dev == "" {
		return uplink{}, fmt.Errorf("no route to %s", ip)
	}
	if routes[0].Dev == tunName {
		return uplink{}, fmt.Errorf("route to %s already points into the tunnel", ip)
	}
	return uplink{Gateway: routes[0].Gateway, Dev: routes[0].Dev}, nil
}

// netState records what was changed so it can be put back exactly.
type netState struct {
	up        uplink // default uplink, for DNS settings
	servers   map[netip.Addr]uplink
	serverIPs []netip.Addr
	oldIPv6   string
	dnsSet    bool
}

// newNetState captures the routes to the servers before anything changes.
func newNetState(servers []netip.Addr) (*netState, error) {
	up, err := currentUplink()
	if err != nil {
		return nil, err
	}
	st := &netState{up: up, servers: map[netip.Addr]uplink{}, serverIPs: servers}
	for _, ip := range servers {
		r, err := routeTo(ip)
		if err != nil {
			return nil, err
		}
		st.servers[ip] = r
	}
	return st, nil
}

// createTun makes a persistent tun interface with the tunnel address and MTU,
// and returns an fd attached to it. The engine takes ownership of the fd.
func createTun(addr netip.Prefix, mtu int) (int, error) {
	runQuiet("ip", "link", "del", tunName)
	if err := run("ip", "tuntap", "add", "dev", tunName, "mode", "tun"); err != nil {
		return -1, err
	}
	if err := run("ip", "addr", "add", addr.String(), "dev", tunName); err != nil {
		return -1, err
	}
	if err := run("ip", "link", "set", "dev", tunName, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return -1, err
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("opening /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(tunName)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	// IFF_NO_PI: raw IP packets, the framing the engine expects on Linux.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("TUNSETIFF %s: %w (run with sudo)", tunName, err)
	}
	return fd, nil
}

// routeIntoTunnel sends all IPv4 traffic into the tunnel, except traffic to
// the exit servers themselves.
//
// The exclusion routes do the job VpnService.protect does on Android: the
// engine's own sockets go to the servers, and without them the WireGuard
// handshake would be routed into the tunnel it is trying to build. 0/1 and
// 128/1 are used instead of replacing the default route so that the original
// default route is untouched and comes straight back on disconnect; the local
// subnet stays reachable (the panel keeps working) because its connected route
// is more specific.
func routeIntoTunnel(st *netState) error {
	for _, ip := range st.serverIPs {
		r := st.servers[ip]
		args := []string{"route", "replace", ip.String() + "/32"}
		if r.Gateway != "" {
			args = append(args, "via", r.Gateway)
		}
		args = append(args, "dev", r.Dev)
		if err := run("ip", args...); err != nil {
			return err
		}
	}
	if err := run("ip", "route", "replace", "0.0.0.0/1", "dev", tunName); err != nil {
		return err
	}
	if err := run("ip", "route", "replace", "128.0.0.0/1", "dev", tunName); err != nil {
		return err
	}

	// IPv6 would bypass an IPv4-only tunnel; turn it off for the session.
	if b, err := os.ReadFile(ipv6Sysctl); err == nil {
		st.oldIPv6 = strings.TrimSpace(string(b))
		_ = os.WriteFile(ipv6Sysctl, []byte("1"), 0o644)
	}

	// DNS: send every lookup to the tunnel interface. The engine intercepts
	// port 53 inside the tunnel and resolves over the encrypted transport, so
	// the local network's resolver never sees a query.
	if _, err := exec.LookPath("resolvectl"); err == nil {
		if run("resolvectl", "dns", tunName, "1.1.1.1") == nil {
			runQuiet("resolvectl", "domain", tunName, "~.")
			runQuiet("resolvectl", "default-route", tunName, "true")
			runQuiet("resolvectl", "default-route", st.up.Dev, "false")
			runQuiet("resolvectl", "flush-caches")
			st.dnsSet = true
		}
	}
	return nil
}

// restoreNetwork undoes routeIntoTunnel and removes the interface.
func restoreNetwork(st *netState) {
	if st == nil {
		return
	}
	if st.dnsSet {
		runQuiet("resolvectl", "default-route", st.up.Dev, "true")
		runQuiet("resolvectl", "revert", tunName)
		runQuiet("resolvectl", "flush-caches")
	}
	runQuiet("ip", "route", "del", "0.0.0.0/1", "dev", tunName)
	runQuiet("ip", "route", "del", "128.0.0.0/1", "dev", tunName)
	for _, ip := range st.serverIPs {
		runQuiet("ip", "route", "del", ip.String()+"/32")
	}
	runQuiet("ip", "link", "del", tunName)
	if st.oldIPv6 != "" {
		_ = os.WriteFile(ipv6Sysctl, []byte(st.oldIPv6), 0o644)
	}
}

// cleanupLeftovers removes anything a previous crashed run left behind.
func cleanupLeftovers() {
	runQuiet("ip", "link", "del", tunName)
	setWireGuardBlocked(nil, false)
	if up, err := currentUplink(); err == nil {
		runQuiet("resolvectl", "default-route", up.Dev, "true")
	}
}

// setWireGuardBlocked adds or removes firewall rules that drop WireGuard to
// the given servers, simulating a network that blocks WireGuard. With block
// false and endpoints nil it removes every rule this program added.
func setWireGuardBlocked(endpoints []netip.AddrPort, block bool) error {
	if !block {
		for {
			out, err := exec.Command("iptables", "-S", "OUTPUT").Output()
			if err != nil {
				return nil
			}
			found := false
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, blockTag) && strings.HasPrefix(line, "-A ") {
					args := strings.Fields(strings.Replace(line, "-A ", "-D ", 1))
					for i, a := range args {
						args[i] = strings.Trim(a, `"`)
					}
					runQuiet("iptables", args...)
					found = true
				}
			}
			if !found {
				return nil
			}
		}
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables is not installed (sudo apt install -y iptables)")
	}
	for _, ep := range endpoints {
		if err := run("iptables", "-I", "OUTPUT", "-d", ep.Addr().String(), "-p", "udp",
			"--dport", fmt.Sprint(ep.Port()), "-m", "comment", "--comment", blockTag, "-j", "DROP"); err != nil {
			return err
		}
	}
	return nil
}
