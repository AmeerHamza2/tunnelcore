package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// runKeygen prints a fresh WireGuard keypair, or with -pubkey derives the
// public key of a private key read from stdin, mirroring `wg genkey` and
// `wg pubkey`.
//
// It goes through package wireguard rather than calling curve25519 directly so
// that what it prints is byte-for-byte what the engine will derive from the
// same private key. A harness that computed keys its own way would be a second
// implementation to keep in agreement, and a disagreement presents as a
// handshake that silently never completes.
func runKeygen(args []string, stdout, stderr io.Writer) error {
	fs := newFlagSet("keygen", "[-pubkey]", stderr)
	pubOnly := fs.Bool("pubkey", false, "read a base64 private key from stdin and print only its public key (like `wg pubkey`)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}

	if *pubOnly {
		return derivePublic(os.Stdin, stdout)
	}

	priv, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return err
	}
	// The warning goes to stderr so that stdout stays machine-readable and a
	// redirect into a file does not capture it.
	fmt.Fprintln(stderr, "warning: the private key below is a secret. It belongs in the device keystore only;")
	fmt.Fprintln(stderr, "         register just the public key with the control plane, and never log or commit the private one.")
	fmt.Fprintf(stdout, "private_key = %s\n", priv.Base64())
	fmt.Fprintf(stdout, "public_key  = %s\n", priv.PublicKey().Base64())
	return nil
}

func derivePublic(r io.Reader, w io.Writer) error {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("reading private key from stdin: %w", err)
	}
	priv, err := wireguard.ParseKey(strings.TrimSpace(line))
	if err != nil {
		// Deliberately not echoing the input: it is, or is meant to be, a
		// private key.
		return fmt.Errorf("stdin does not hold a valid WireGuard key: %w", err)
	}
	fmt.Fprintln(w, priv.PublicKey().Base64())
	return nil
}
