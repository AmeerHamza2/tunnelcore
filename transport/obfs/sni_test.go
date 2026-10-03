package obfs

import (
	"encoding/binary"
	"testing"
)

func TestFindSNI(t *testing.T) {
	tests := []string{
		"example.com",
		"a.b",
		"very-long-subdomain.with.several.labels.example.co.uk",
		"xn--80ak6aa92e.com", // punycode
	}
	for _, host := range tests {
		t.Run(host, func(t *testing.T) {
			hello := clientHello(host)
			start, end, ok := findSNI(hello)
			if !ok {
				t.Fatal("findSNI did not locate the SNI in a valid ClientHello")
			}
			if got := string(hello[start : end+1]); got != host {
				t.Errorf("findSNI returned %q, want %q", got, host)
			}
		})
	}
}

func TestFindSNIRejectsNonClientHello(t *testing.T) {
	valid := clientHello("example.com")

	tests := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"shorter than a record header", valid[:4]},
		{"not a handshake record", func() []byte {
			b := append([]byte(nil), valid...)
			b[0] = 0x17 // application_data
			return b
		}()},
		{"not a client_hello", func() []byte {
			b := append([]byte(nil), valid...)
			b[5] = 0x02 // server_hello
			return b
		}()},
		{"truncated inside the random", valid[:20]},
		{"truncated before the extensions", valid[:45]},
		{"no extensions at all", func() []byte {
			// A ClientHello with an empty extensions block.
			var body []byte
			body = append(body, 0x03, 0x03)
			for i := 0; i < 32; i++ {
				body = append(body, byte(i))
			}
			body = append(body, 0x00)
			body = binary.BigEndian.AppendUint16(body, 2)
			body = append(body, 0x13, 0x01)
			body = append(body, 0x01, 0x00)
			body = binary.BigEndian.AppendUint16(body, 0)
			hs := []byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}
			hs = append(hs, body...)
			return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, ok := findSNI(tt.b); ok {
				t.Error("findSNI = ok on input that has no locatable SNI")
			}
		})
	}
}

// TestFindSNISkipsOtherExtensions checks the extension walk: the SNI is rarely
// the first extension in a real ClientHello.
func TestFindSNISkipsOtherExtensions(t *testing.T) {
	const host = "target.example.com"

	// supported_versions, then server_name, then ALPN.
	var extensions []byte
	extensions = binary.BigEndian.AppendUint16(extensions, 0x002b) // supported_versions
	extensions = binary.BigEndian.AppendUint16(extensions, 3)
	extensions = append(extensions, 0x02, 0x03, 0x04)

	var sni []byte
	sni = append(sni, 0x00)
	sni = binary.BigEndian.AppendUint16(sni, uint16(len(host)))
	sni = append(sni, host...)
	var sniData []byte
	sniData = binary.BigEndian.AppendUint16(sniData, uint16(len(sni)))
	sniData = append(sniData, sni...)
	extensions = binary.BigEndian.AppendUint16(extensions, 0x0000)
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(sniData)))
	extensions = append(extensions, sniData...)

	extensions = binary.BigEndian.AppendUint16(extensions, 0x0010) // ALPN
	extensions = binary.BigEndian.AppendUint16(extensions, 5)
	extensions = append(extensions, 0x00, 0x03, 0x02, 'h', '2')

	var body []byte
	body = append(body, 0x03, 0x03)
	for i := 0; i < 32; i++ {
		body = append(body, byte(i))
	}
	body = append(body, 0x00)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	hello := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)

	start, end, ok := findSNI(hello)
	if !ok {
		t.Fatal("findSNI did not locate an SNI that was not the first extension")
	}
	if got := string(hello[start : end+1]); got != host {
		t.Errorf("findSNI returned %q, want %q", got, host)
	}
}

// TestFindSNIWithSessionID covers a resumption-style ClientHello, where a
// 32-byte session ID shifts every subsequent offset. A parser that assumed an
// empty session ID would read the cipher list from the wrong place.
func TestFindSNIWithSessionID(t *testing.T) {
	const host = "resumed.example.com"
	hello := clientHello(host)

	// Rebuild with a 32-byte session ID inserted.
	sessionIDOffset := 5 + 4 + 2 + 32 // record + handshake + version + random
	withID := append([]byte(nil), hello[:sessionIDOffset]...)
	withID = append(withID, 32)
	withID = append(withID, make([]byte, 32)...)
	withID = append(withID, hello[sessionIDOffset+1:]...)

	// Fix up the two length fields that now describe more bytes.
	hsLen := len(withID) - 5 - 4
	withID[5+1] = byte(hsLen >> 16)
	withID[5+2] = byte(hsLen >> 8)
	withID[5+3] = byte(hsLen)
	recLen := len(withID) - 5
	withID[3] = byte(recLen >> 8)
	withID[4] = byte(recLen)

	start, end, ok := findSNI(withID)
	if !ok {
		t.Fatal("findSNI did not locate the SNI past a 32-byte session ID")
	}
	if got := string(withID[start : end+1]); got != host {
		t.Errorf("findSNI returned %q, want %q", got, host)
	}
}

// FuzzFindSNI asserts the parser's only two obligations: never panic, and
// never return offsets outside the buffer.
//
// This function walks six nested attacker-controlled length fields over bytes
// written by whatever application is using the tunnel. An out-of-range slice
// here panics the whole VPN process, which drops the tunnel and sends the
// user's traffic out in the clear.
func FuzzFindSNI(f *testing.F) {
	f.Add(clientHello("example.com"))
	f.Add(clientHello("a"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{0x16})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		start, end, ok := findSNI(b)
		if !ok {
			return
		}
		if start < 0 || end < start || end >= len(b) {
			t.Fatalf("findSNI returned [%d, %d] for a %d-byte buffer", start, end, len(b))
		}
		// Taking the slice is what turns a bad offset into a visible failure.
		_ = len(b[start : end+1])
	})
}

// FuzzTLSFragmentWrite checks the plugin end to end: whatever it does to the
// buffer, the bytes on the wire must be byte-identical to the input. An
// obfuscation layer that corrupts traffic is worse than no obfuscation.
func FuzzTLSFragmentWrite(f *testing.F) {
	f.Add(clientHello("example.com"), 0)
	f.Add([]byte("plain bytes, not TLS at all, but long enough to be split"), 0)
	f.Add([]byte("short"), 0)
	f.Add(clientHello("example.com"), 8)

	f.Fuzz(func(t *testing.T, payload []byte, splitAt int) {
		if splitAt < 0 || splitAt > 1<<16 {
			splitAt = 0
		}
		c := newRecordingConn()
		conn, err := TLSFragment{SplitAt: splitAt}.Wrap(c)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}

		n, err := conn.Write(payload)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("Write returned %d, want %d; a short write breaks every io.Copy above this", n, len(payload))
		}
		if got := c.joined(); string(got) != string(payload) {
			t.Fatalf("wire bytes differ from the payload (%d vs %d bytes)", len(got), len(payload))
		}
	})
}
