// Command slipstream-desktop runs the TunnelCore engine as a real VPN on a
// Linux machine, with a web control panel.
//
// It is the phone app's job done on a desktop: it owns a tun interface, hands
// the fd to the same mobile.Tunnel API the Android and iOS apps call, and
// routes the machine's traffic into it. The panel shows the connection state,
// the transport that won the race, the public IP before and after, and live
// throughput, and can block WireGuard with a firewall rule to show the engine
// falling back to Shadowsocks.
//
//	slipstream-desktop keygen                      # once: create the device key, print the public key
//	sudo slipstream-desktop serve -locations DIR   # run the VPN client and the panel on :8080
//
// DIR holds one location file per exit server, as printed by
// deploy/server-setup.sh.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

var errUsage = errors.New("usage")

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if errors.Is(err, errUsage) || errors.Is(err, flag.ErrHelp) {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `slipstream-desktop: the TunnelCore VPN engine with a web control panel

  slipstream-desktop keygen [-key FILE]
      Create the device's WireGuard private key (if missing) and print its
      public key. Give the public key to server-setup.sh.

  sudo slipstream-desktop serve -locations DIR [-key FILE] [-listen :8080]
      Run the VPN client and serve the control panel.
`)
}
