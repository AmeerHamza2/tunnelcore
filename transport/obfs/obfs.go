// Package obfs provides pluggable obfuscation layers that wrap a transport's
// underlying connection.
//
// The threat model is a network operator running deep packet inspection that
// classifies and blocks traffic it believes is a VPN. Encryption alone does
// not defeat it: DPI does not need to read the payload, it only needs a
// signature, and a protocol's handshake, its first-packet length, its byte
// distribution and its SNI are all signatures. Obfuscation removes or
// disguises those.
//
// Plugins compose. Chain applies them innermost-first, so the configuration
//
//	Plugins: []obfs.Plugin{obfs.TLSFragment{...}, obfs.Prefix{...}}
//
// yields a connection where Prefix's bytes are written first and the fragmenter
// then splits whatever is handed down to it. Keeping the layers independent is
// deliberate: censorship techniques change, and the useful unit of change is
// one small, separately-testable wrapper rather than a fork of the transport.
//
// What is deliberately *not* here: anything that claims to make traffic
// unblockable. Every technique in this package raises the cost of
// classification; none of them makes it impossible. The honest framing is that
// these buy time against a specific deployed classifier, and the engine's job
// is to notice when one stops working (via connection success rate per
// transport) and fail over to another.
package obfs

import (
	"errors"
	"fmt"
	"net"
)

// Plugin wraps a connection in an obfuscation layer.
type Plugin interface {
	// Name identifies the plugin in logs and metrics. It must not contain
	// secrets: plugin parameters are frequently shared secrets.
	Name() string

	// Wrap returns a connection that applies this plugin's transformation.
	// If Wrap returns an error the caller closes the underlying connection.
	Wrap(c net.Conn) (net.Conn, error)
}

// ErrNilConn is returned when Wrap is handed a nil connection.
var ErrNilConn = errors.New("obfs: nil connection")

// Chain applies plugins to c, innermost first.
//
// A nil or empty slice returns c unchanged, so a transport can call this
// unconditionally rather than branching on whether obfuscation is configured.
func Chain(c net.Conn, plugins []Plugin) (net.Conn, error) {
	if c == nil {
		return nil, ErrNilConn
	}
	for _, p := range plugins {
		if p == nil {
			continue
		}
		wrapped, err := p.Wrap(c)
		if err != nil {
			return nil, fmt.Errorf("obfs: plugin %s: %w", p.Name(), err)
		}
		if wrapped == nil {
			return nil, fmt.Errorf("obfs: plugin %s returned a nil connection", p.Name())
		}
		c = wrapped
	}
	return c, nil
}

// Names returns the plugin names in chain order, for logging.
func Names(plugins []Plugin) []string {
	out := make([]string, 0, len(plugins))
	for _, p := range plugins {
		if p != nil {
			out = append(out, p.Name())
		}
	}
	return out
}
