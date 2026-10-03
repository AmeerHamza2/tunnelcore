// Command tun-harness drives the tunnelcore engine from a terminal.
//
// The engine is a library built to be embedded in a mobile app, which makes it
// awkward to look at: on a phone the only observable is a shield icon. This
// command is the other way in. Its centrepiece, `demo`, stands up a complete
// miniature VPN deployment inside one process — a WireGuard exit node, a
// Shadowsocks exit node, a blackholed server and a decommissioned one, plus a
// userspace "phone" generating real UDP and TCP traffic — and runs the real
// engine against it, narrating the transport race, a network handover and a
// failover as they happen. None of it needs root or a TUN device, because the
// engine only ever sees its TunDevice interface.
//
// Subcommands:
//
//	keygen     generate a WireGuard keypair (like `wg genkey | wg pubkey`)
//	validate   check a mobile JSON config with the app's own parser
//	demo       the in-process end-to-end showcase
//	run        drive a real Linux tun interface from a JSON config (root)
//
// Flags are parsed with the standard library's flag package, one FlagSet per
// subcommand, so the binary has no dependencies beyond the engine's own.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// exitUsage is the conventional exit status for a command-line usage error,
// kept distinct from 1 so a script can tell "you called it wrong" from "it
// ran and failed".
const exitUsage = 2

type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) error
}

func commands() []command {
	return []command{
		{"keygen", "generate a WireGuard private key and print it with its public key", runKeygen},
		{"validate", "validate a mobile JSON config exactly as the app would", runValidate},
		{"demo", "run the in-process end-to-end demo (no root needed)", runDemoCmd},
		{"run", "drive a real tun interface from a JSON config (Linux, needs CAP_NET_ADMIN)", runTunCmd},
	}
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

// realMain is main without the os.Exit, so tests can drive the whole CLI.
func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	name := args[0]
	if name == "-h" || name == "-help" || name == "--help" || name == "help" {
		usage(stdout)
		return 0
	}
	for _, c := range commands() {
		if c.name != name {
			continue
		}
		err := c.run(args[1:], stdout, stderr)
		switch {
		case err == nil:
			return 0
		case errors.Is(err, flag.ErrHelp):
			return 0
		case errors.Is(err, errUsage):
			return exitUsage
		default:
			fmt.Fprintf(stderr, "tun-harness %s: %v\n", name, err)
			return 1
		}
	}
	fmt.Fprintf(stderr, "tun-harness: unknown command %q\n\n", name)
	usage(stderr)
	return exitUsage
}

// errUsage marks an error whose message has already been printed alongside
// the subcommand's usage.
var errUsage = errors.New("usage error")

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: tun-harness <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'tun-harness <command> -h' for the flags of one command.")
}

// newFlagSet builds a FlagSet that reports errors instead of exiting, writing
// its usage to stderr.
func newFlagSet(name, synopsis string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("tun-harness "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: tun-harness %s %s\n\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses args and rejects stray positional arguments, which
// otherwise get silently ignored — `validate config.json` without -config
// would "succeed" by validating nothing.
func parseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return errUsage
	}
	return nil
}
