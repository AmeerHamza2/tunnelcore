package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ameerhamza2/tunnelcore/mobile"
)

// runValidate checks a JSON config with the mobile package's own parser.
//
// mobile.NewTunnel is used as the oracle on purpose, rather than a harness
// re-implementation of the rules: the question an operator is asking is "will
// the app accept this", and only the app's code can answer it without drifting.
//
// On top of the whole-config verdict it validates each server on its own. The
// app accepts a config in which some servers are broken (one bad record costs
// that server, not the product), which is the right runtime behaviour and a
// trap at authoring time: the config "validates" while a region is silently
// unreachable. Per-server results make that visible, and -strict turns it into
// a failure for use in CI.
func runValidate(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("validate", "-config file.json [-strict]", stderr)
	path := fs.String("config", "", "path to the JSON config (- for stdin)")
	strict := fs.Bool("strict", false, "fail if any individual server entry is unusable")
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

	if _, err := mobile.NewTunnel(raw); err != nil {
		fmt.Fprintf(stdout, "INVALID: %v\n", err)
		return errors.New("config rejected")
	}

	// The config is valid, so it decodes; that is what lets each server be
	// re-validated in isolation below. Package mobile keeps its config types
	// unexported (gomobile cannot bind their slice fields), so the document
	// is handled generically: each raw server entry is spliced back into the
	// otherwise-unchanged document, which also means no field can be lost
	// in a round trip through a harness-side copy of the schema.
	var doc map[string]json.RawMessage
	var servers []json.RawMessage
	var tunnelAddrs []string
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return fmt.Errorf("re-decoding a config the parser accepted: %w", err)
	}
	if err := json.Unmarshal(doc["servers"], &servers); err != nil {
		return fmt.Errorf("re-decoding a config the parser accepted: %w", err)
	}
	if err := json.Unmarshal(doc["tunnel_addresses"], &tunnelAddrs); err != nil {
		return fmt.Errorf("re-decoding a config the parser accepted: %w", err)
	}

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  #\tNAME\tPROTOCOL\tENDPOINT\tSTATUS")
	bad := 0
	for i, rs := range servers {
		var s struct {
			Name     string `json:"name"`
			Protocol string `json:"protocol"`
			Endpoint string `json:"endpoint"`
		}
		status := "ok"
		if err := json.Unmarshal(rs, &s); err != nil {
			status = "UNUSABLE: " + err.Error()
			bad++
		} else if err := validateOne(doc, rs); err != nil {
			status = "UNUSABLE: " + err.Error()
			bad++
		}
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\n", i, s.Name, s.Protocol, s.Endpoint, status)
	}
	_ = tw.Flush()

	switch {
	case bad == 0:
		fmt.Fprintf(stdout, "OK: %d server(s), tunnel %s\n", len(servers), strings.Join(tunnelAddrs, ", "))
		return nil
	case *strict:
		fmt.Fprintf(stdout, "INVALID (strict): %d of %d server(s) unusable\n", bad, len(servers))
		return errors.New("config has unusable servers")
	default:
		fmt.Fprintf(stdout, "OK with warnings: %d of %d server(s) unusable and will be skipped at connect time\n", bad, len(servers))
		return nil
	}
}

// validateOne runs the app's parser over a copy of doc reduced to one server.
func validateOne(doc map[string]json.RawMessage, server json.RawMessage) error {
	one := make(map[string]json.RawMessage, len(doc))
	for k, v := range doc {
		one[k] = v
	}
	list, err := json.Marshal([]json.RawMessage{server})
	if err != nil {
		return err
	}
	one["servers"] = list
	b, err := json.Marshal(one)
	if err != nil {
		return err
	}
	_, err = mobile.NewTunnel(string(b))
	return err
}

func readConfig(path string) (string, error) {
	var (
		b   []byte
		err error
	)
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return "", fmt.Errorf("reading config: %w", err)
	}
	return string(b), nil
}
