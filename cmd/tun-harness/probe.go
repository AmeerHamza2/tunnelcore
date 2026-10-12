package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/ameerhamza2/tunnelcore/mobile"
)

// runProbe measures latency and loss to every server in a config, through the
// same bound API a server picker in the app calls (Tunnel.ProbeServersJSON).
//
// It answers the question a server list with live numbers is for: from where
// I am, right now, which servers are fast and which are down. WireGuard
// servers are probed on their UDP echo health port, Shadowsocks servers with
// TCP connects; see package probe.
func runProbe(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("probe", "-config file.json [-timeout-ms 1000] [-json]", stderr)
	path := fs.String("config", "", "path to the JSON config (- for stdin)")
	timeoutMS := fs.Int("timeout-ms", 1000, "per-sample timeout in milliseconds")
	asJSON := fs.Bool("json", false, "print the raw JSON the app receives")
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
	tun, err := mobile.NewTunnel(raw)
	if err != nil {
		return fmt.Errorf("config rejected: %w", err)
	}

	out := tun.ProbeServersJSON(*timeoutMS)
	if *asJSON {
		fmt.Fprintln(stdout, out)
		return nil
	}

	var res struct {
		Results []struct {
			Name      string  `json:"name"`
			Protocol  string  `json:"protocol"`
			Method    string  `json:"method"`
			Reachable bool    `json:"reachable"`
			RTTMS     float64 `json:"rtt_ms"`
			RTTP95MS  float64 `json:"rtt_p95_ms"`
			Loss      float64 `json:"loss"`
			Error     string  `json:"error"`
		} `json:"results"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		return fmt.Errorf("decoding probe output: %w", err)
	}
	if res.Error != "" {
		return errors.New(res.Error)
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SERVER\tPROTOCOL\tPROBE\tSTATUS\tRTT p50\tRTT p95\tLOSS")
	up := 0
	for _, r := range res.Results {
		status, p50, p95 := "down", "-", "-"
		if r.Reachable {
			up++
			status = "up"
			p50, p95 = fmt.Sprintf("%.1f ms", r.RTTMS), fmt.Sprintf("%.1f ms", r.RTTP95MS)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%.0f%%\n", r.Name, r.Protocol, r.Method, status, p50, p95, r.Loss*100)
	}
	_ = tw.Flush()
	fmt.Fprintf(stdout, "  %d of %d servers reachable; best first.\n", up, len(res.Results))
	if up == 0 {
		return errors.New("no server reachable")
	}
	return nil
}
