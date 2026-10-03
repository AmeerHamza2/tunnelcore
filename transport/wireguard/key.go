package wireguard

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Key is a 32-byte Curve25519 or pre-shared key.
//
// Private keys, public keys and pre-shared keys share this type because
// WireGuard's wire format does, but they are not interchangeable in handling:
// see the String method.
type Key [32]byte

// ErrBadKeyLength means a decoded key was not 32 bytes.
var ErrBadKeyLength = errors.New("wireguard: key is not 32 bytes")

// GeneratePrivateKey returns a new Curve25519 private key read from the
// system CSPRNG.
//
// Note what this function is *not*: it is not clamped. WireGuard performs
// clamping inside its X25519 implementation, and pre-clamping here would
// produce a key that round-trips through base64 differently than the one the
// peer is configured with — a mismatch that presents as a handshake that
// never completes, with no error anywhere.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, fmt.Errorf("wireguard: reading CSPRNG: %w", err)
	}
	return k, nil
}

// PublicKey derives the Curve25519 public key for a private key.
func (k Key) PublicKey() Key {
	var pub Key
	// curve25519.ScalarBaseMult is deprecated in favour of X25519 with the
	// Basepoint, but the deprecated form is the one that matches WireGuard's
	// own derivation byte for byte, so it is what we use.
	priv := k
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		// X25519 only errors on a low-order result, which for a
		// CSPRNG-generated scalar does not happen. Returning the zero key
		// here would be worse than useless: it would look like a valid key.
		panic("wireguard: deriving public key: " + err.Error())
	}
	copy(pub[:], p)
	return pub
}

// IsZero reports whether k is the all-zero key, which is never a valid
// configured key and is the value a struct has before it is populated.
func (k Key) IsZero() bool {
	var zero Key
	return subtle.ConstantTimeCompare(k[:], zero[:]) == 1
}

// Equal compares two keys in constant time.
func (k Key) Equal(other Key) bool {
	return subtle.ConstantTimeCompare(k[:], other[:]) == 1
}

// Base64 returns the standard WireGuard textual encoding of the key.
//
// This is the only way to get the raw bytes of a key out as text. It is
// deliberately a distinct, awkwardly-named method rather than String, so that
// every place a key is serialised is a place somebody had to type "Base64"
// and could be asked why in review.
func (k Key) Base64() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// Hex returns the lower-case hex encoding used by WireGuard's UAPI.
func (k Key) Hex() string {
	return hex.EncodeToString(k[:])
}

// String deliberately does not reveal the key.
//
// Every real credential leak this guards against has the same shape: someone
// adds a %v or a structured-log field for a config struct while debugging a
// handshake, that line survives review because it reads as harmless, and from
// then on the device's private key is in whatever log sink the app ships to.
// Since Key carries private keys, the safe default is for the formatting verbs
// to be useless, and for a 32-bit hash *fingerprint* (see fingerprint) to be
// the most anyone gets by accident.
func (k Key) String() string {
	if k.IsZero() {
		return "wgkey:unset"
	}
	return "wgkey:" + k.fingerprint()
}

// GoString makes %#v redacted too, which %v alone does not cover.
func (k Key) GoString() string { return k.String() }

// MarshalText refuses to serialise. A Key must never end up in JSON by
// accident: the control plane's API returns public keys as explicit strings,
// and private keys never leave the device at all.
func (k Key) MarshalText() ([]byte, error) {
	return nil, errors.New("wireguard: refusing to marshal a Key; call Base64 explicitly if this is a public key")
}

// fingerprintDomain separates key fingerprints from every other use of
// SHA-256 over key material, so a fingerprint can never be mistaken for (or
// precomputed as) a hash some other protocol publishes.
const fingerprintDomain = "tunnelcore wireguard key fingerprint v1\x00"

// fingerprint returns a short, non-reversible identifier suitable for logs.
//
// It is a truncated hash rather than a prefix of the key. A prefix of a
// private key or PSK is 32 bits of the secret itself sitting in every log
// sink the app ships to, and four such prefixes from different builds or log
// lines are not even needed to make it worse — one already cuts the work of a
// brute force by 2^32. A hash prefix identifies the key just as well for
// "is this the key I think it is" and reveals nothing about its bytes.
func (k Key) fingerprint() string {
	h := sha256.New()
	h.Write([]byte(fingerprintDomain))
	h.Write(k[:])
	return hex.EncodeToString(h.Sum(nil)[:4])
}

// Key parsing errors.
//
// These are sentinels and never wrap the decoder's own error, because the
// standard decoders quote the offending input: base64.CorruptInputError gives
// an offset into the secret and hex.InvalidByteError the byte itself. Either
// one in an error string puts part of a private key into whatever log or
// crash report that error reaches.
var (
	// ErrBadKeyEncoding wraps ErrBadKeyLength so callers that matched on
	// the length error for a wrong-sized input keep working.
	ErrBadKeyEncoding = fmt.Errorf("%w: want 44-character base64 or 64-character hex", ErrBadKeyLength)
	ErrBadKeyBase64   = errors.New("wireguard: key is not valid base64")
	ErrBadKeyHex      = errors.New("wireguard: key is not valid hex")
)

// ParseKey decodes a key from its base64 or hex textual form.
//
// The encoding is chosen by length, not by trial: a 32-byte key is exactly 44
// characters of padded base64 or 64 of hex, and every 64-character hex string
// is also valid base64 (it decodes to 48 bytes), so "try base64 first" would
// reject every hex key with a misleading length error.
func ParseKey(s string) (Key, error) {
	var k Key
	var (
		b   []byte
		err error
	)
	switch len(s) {
	case base64.StdEncoding.EncodedLen(len(k)):
		b, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return Key{}, ErrBadKeyBase64
		}
	case hex.EncodedLen(len(k)):
		b, err = hex.DecodeString(s)
		if err != nil {
			return Key{}, ErrBadKeyHex
		}
	default:
		return Key{}, ErrBadKeyEncoding
	}
	if len(b) != len(k) {
		// Unreachable for the two lengths above, but the copy below must
		// never silently produce a truncated or zero-padded key.
		return Key{}, ErrBadKeyLength
	}
	copy(k[:], b)
	return k, nil
}
