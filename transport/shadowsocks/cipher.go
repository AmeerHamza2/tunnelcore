// Package shadowsocks implements a KindStream transport speaking the
// Shadowsocks AEAD protocol (the "AEAD-2018" ciphers, which is what deployed
// servers and clients overwhelmingly run).
//
// Shadowsocks earns its place next to WireGuard in this engine for one reason:
// it looks like nothing. WireGuard has a fixed, recognisable handshake on UDP,
// and a network that wants to block VPNs blocks it in an afternoon. A
// Shadowsocks stream is a salt followed by AEAD ciphertext over TCP — no
// handshake, no version byte, no fixed-length header, nothing for a DPI
// signature to match. That is why it is the transport that still works in the
// networks where WireGuard does not, and why the obfs plugin chain in
// ../obfs hangs off this transport rather than that one.
//
// Wire format, TCP:
//
//	[16/32-byte random salt][encrypted chunk][encrypted chunk]...
//
//	chunk := [2-byte big-endian payload length + 16-byte tag]
//	         [payload + 16-byte tag]
//
// The session subkey is HKDF-SHA1(master key, salt, "ss-subkey"), and the
// nonce is a little-endian counter starting at zero, incremented once per
// seal. Length and payload are sealed separately, each consuming a nonce,
// which is why a chunk costs 32 bytes of overhead.
//
// The first payload bytes of a connection are the SOCKS5-form target address
// (see socks.go); after that the stream is the application's bytes verbatim.
package shadowsocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Method is a Shadowsocks AEAD cipher.
type Method string

const (
	AES128GCM        Method = "aes-128-gcm"
	AES256GCM        Method = "aes-256-gcm"
	ChaCha20Poly1305 Method = "chacha20-ietf-poly1305"
)

// Cipher errors.
var (
	ErrUnknownMethod = errors.New("shadowsocks: unknown cipher method")
	ErrNoPassword    = errors.New("shadowsocks: password is empty")
	ErrShortSalt     = errors.New("shadowsocks: salt shorter than the cipher requires")
)

// subkeyInfo is the HKDF info string fixed by the Shadowsocks AEAD spec.
var subkeyInfo = []byte("ss-subkey")

// Cipher holds the master key for one server and constructs per-session AEADs.
type Cipher struct {
	method  Method
	key     []byte
	keySize int
	// saltSize equals keySize for every AEAD method in the spec.
	saltSize int
}

// NewCipher derives a master key from password for the given method.
//
// The key derivation is MD5-based EVP_BytesToKey. That is not a defensible
// choice in 2026 — it is unsalted, uniterated, and MD5 — but it is what the
// Shadowsocks AEAD spec mandates and what every deployed server implements, so
// a client that "improves" it cannot talk to anything. The mitigation belongs
// elsewhere and is enforced by the control plane rather than here: server
// passwords are 32 bytes of CSPRNG output provisioned per user, never
// human-chosen, so there is no low-entropy input for the weak KDF to fail to
// protect. Config.Validate below refuses anything shorter than 16 bytes for
// exactly that reason.
func NewCipher(method Method, password string) (*Cipher, error) {
	if password == "" {
		return nil, ErrNoPassword
	}
	keySize, err := keySizeFor(method)
	if err != nil {
		return nil, err
	}
	return &Cipher{
		method:   method,
		key:      evpBytesToKey(password, keySize),
		keySize:  keySize,
		saltSize: keySize,
	}, nil
}

func keySizeFor(m Method) (int, error) {
	switch m {
	case AES128GCM:
		return 16, nil
	case AES256GCM:
		return 32, nil
	case ChaCha20Poly1305:
		return 32, nil
	default:
		return 0, fmt.Errorf("%w: %q (supported: %s)", ErrUnknownMethod, m, strings.Join(SupportedMethods(), ", "))
	}
}

// SupportedMethods lists the cipher method names this package accepts.
func SupportedMethods() []string {
	return []string{string(AES128GCM), string(AES256GCM), string(ChaCha20Poly1305)}
}

// Method returns the cipher method.
func (c *Cipher) Method() Method { return c.method }

// SaltSize is the number of random bytes prefixed to each stream.
func (c *Cipher) SaltSize() int { return c.saltSize }

// Overhead is the AEAD tag length.
func (c *Cipher) Overhead() int { return 16 }

// AEAD derives the session subkey from salt and returns the AEAD for it.
func (c *Cipher) AEAD(salt []byte) (cipher.AEAD, error) {
	if len(salt) < c.saltSize {
		return nil, fmt.Errorf("%w: got %d, need %d", ErrShortSalt, len(salt), c.saltSize)
	}
	subkey := make([]byte, c.keySize)
	r := hkdf.New(sha1.New, c.key, salt[:c.saltSize], subkeyInfo)
	if _, err := io.ReadFull(r, subkey); err != nil {
		return nil, fmt.Errorf("shadowsocks: deriving session subkey: %w", err)
	}

	switch c.method {
	case AES128GCM, AES256GCM:
		blk, err := aes.NewCipher(subkey)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: constructing AES cipher: %w", err)
		}
		aead, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: constructing GCM: %w", err)
		}
		return aead, nil
	case ChaCha20Poly1305:
		aead, err := chacha20poly1305.New(subkey)
		if err != nil {
			return nil, fmt.Errorf("shadowsocks: constructing ChaCha20-Poly1305: %w", err)
		}
		return aead, nil
	default:
		return nil, ErrUnknownMethod
	}
}

// evpBytesToKey is OpenSSL's EVP_BytesToKey with MD5 and one iteration, which
// is the key derivation the Shadowsocks AEAD spec specifies.
func evpBytesToKey(password string, keyLen int) []byte {
	const md5Len = md5.Size
	count := (keyLen + md5Len - 1) / md5Len
	out := make([]byte, count*md5Len)

	sum := md5.Sum([]byte(password))
	copy(out, sum[:])

	// Each subsequent block hashes the previous block followed by the
	// password, so the chain length depends only on the requested key size.
	buf := make([]byte, md5Len+len(password))
	for i := 1; i < count; i++ {
		copy(buf, out[(i-1)*md5Len:i*md5Len])
		copy(buf[md5Len:], password)
		sum = md5.Sum(buf)
		copy(out[i*md5Len:], sum[:])
	}
	return out[:keyLen]
}

// nonce is the little-endian counter the AEAD chunk format uses.
//
// It is a type rather than a bare slice so that the increment cannot be
// forgotten at a call site. Reusing a nonce with the same key in GCM is
// catastrophic — it leaks the authentication subkey and lets an attacker forge
// arbitrary chunks — so this is the one place in the package where the
// invariant lives.
type nonce []byte

func newNonce(size int) nonce { return make(nonce, size) }

// increment adds one to the little-endian counter.
func (n nonce) increment() {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}
