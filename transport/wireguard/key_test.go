package wireguard

import (
	"errors"
	"strings"
	"testing"
)

// TestKeyStringRevealsNoKeyBytes: String is what ends up in logs via %v, so
// it must not contain any run of the raw key. Checking every 4-byte window
// rather than just the prefix catches a "fix" that merely moves which bytes
// leak.
func TestKeyStringRevealsNoKeyBytes(t *testing.T) {
	for i := 0; i < 64; i++ {
		k, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		s := k.String()
		if !strings.HasPrefix(s, "wgkey:") || len(s) != len("wgkey:")+8 {
			t.Fatalf("String() = %q, want wgkey: and an 8-hex-digit fingerprint", s)
		}
		raw := k.Hex()
		for w := 0; w+8 <= len(raw); w += 2 {
			if strings.Contains(s, raw[w:w+8]) {
				t.Fatalf("String() = %q contains key bytes %d..%d (%s)", s, w/2, w/2+4, raw[w:w+8])
			}
		}
		// Stable: the same key always fingerprints the same, or the
		// fingerprint is useless for matching log lines.
		if k.String() != s {
			t.Fatal("String() is not deterministic")
		}
	}
}

func TestParseKeyHexAndBase64(t *testing.T) {
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{"base64": k.Base64(), "hex": k.Hex(), "HEX": strings.ToUpper(k.Hex())} {
		got, err := ParseKey(in)
		if err != nil {
			t.Fatalf("ParseKey(%s) = %v", name, err)
		}
		if !got.Equal(k) {
			t.Fatalf("ParseKey(%s) decoded a different key", name)
		}
	}
}

// TestParseKeyErrorsDoNotQuoteInput: a malformed key is usually a real key
// with a copy-paste error, so its characters are secret. The standard
// decoders' errors quote them (hex.InvalidByteError) or point at them
// (base64.CorruptInputError); none of that may reach the error string.
func TestParseKeyErrorsDoNotQuoteInput(t *testing.T) {
	k, _ := GeneratePrivateKey()
	b64 := k.Base64()
	hx := k.Hex()
	cases := map[string]string{
		"base64 bad char": b64[:10] + "!" + b64[11:],
		"base64 bad pad":  b64[:43] + "A",
		"hex bad char":    hx[:20] + "zz" + hx[22:],
		"hex odd":         hx[:63] + "q",
		"short":           "QUJD",
		"long":            b64 + b64,
		"garbage":         "not-base64!",
		"48-byte base64":  strings.Repeat("A", 64)[:60] + "Zz9_",
		"unicode":         strings.Repeat("é", 22),
	}
	sentinels := map[string]bool{
		ErrBadKeyEncoding.Error(): true,
		ErrBadKeyBase64.Error():   true,
		ErrBadKeyHex.Error():      true,
		ErrBadKeyLength.Error():   true,
	}
	for name, in := range cases {
		_, err := ParseKey(in)
		if err == nil {
			t.Errorf("%s: ParseKey accepted %q", name, in)
			continue
		}
		// The strongest form of "quotes nothing from the input": the message
		// is exactly one of the fixed sentinel texts, so no decoder detail
		// (offset, byte value, character) can have been appended.
		if !sentinels[err.Error()] {
			t.Errorf("%s: err = %q, want exactly a sentinel message", name, err)
		}
	}
	// Short input of the old "valid base64, wrong length" shape still
	// matches ErrBadKeyLength for callers written against the old API.
	if _, err := ParseKey("QUJD"); !errors.Is(err, ErrBadKeyLength) {
		t.Errorf("ParseKey(short) = %v, want ErrBadKeyLength", err)
	}
}
