package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ameerhamza2/tunnelcore/mobile"
)

func defaultKeyPath() string {
	if home, err := os.UserHomeDir(); err == nil {
		// Under sudo, keep using the invoking user's key, not root's.
		if u := os.Getenv("SUDO_USER"); u != "" && os.Geteuid() == 0 {
			home = filepath.Join("/home", u)
		}
		return filepath.Join(home, ".slipstream", "device.key")
	}
	return "device.key"
}

// runKeygen creates the device private key once and prints the public key.
// The private key never leaves this machine; only the public key goes to the
// server, exactly as on the phone.
func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := fs.String("key", defaultKeyPath(), "device private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, err := loadOrCreateKey(*path)
	if err != nil {
		return err
	}
	pub, err := mobile.PublicKeyFor(priv)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "device key: %s (private, never shared)\npublic key:\n", *path)
	fmt.Println(pub)
	return nil
}

func loadOrCreateKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		k := strings.TrimSpace(string(b))
		if _, err := mobile.PublicKeyFor(k); err != nil {
			return "", fmt.Errorf("%s does not hold a valid key: %w", path, err)
		}
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	priv, err := mobile.GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(priv+"\n"), 0o600); err != nil {
		return "", err
	}
	return priv, nil
}
