package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestChecksumKnownVector(t *testing.T) {
	// RFC 1071 section 3 worked example: the bytes 00 01 f2 03 f4 f5 f6 f7
	// sum to 0xddf2, complement 0x220d.
	b := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got, want := Fold(Checksum(b, 0)), uint16(0x220d); got != want {
		t.Errorf("Fold(Checksum(...)) = %#04x, want %#04x", got, want)
	}
}

func TestChecksumOddLength(t *testing.T) {
	// A trailing odd byte is padded on the right, so these must agree.
	odd := []byte{0x12, 0x34, 0x56}
	padded := []byte{0x12, 0x34, 0x56, 0x00}
	if Fold(Checksum(odd, 0)) != Fold(Checksum(padded, 0)) {
		t.Error("odd-length checksum disagrees with explicitly zero-padded input")
	}
}

func TestChecksumIncrementalEqualsWhole(t *testing.T) {
	// Seeding one call with the running sum of another must equal checksumming
	// the concatenation. The pseudo-header path depends on this.
	a := []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46}
	b := []byte{0x40, 0x00, 0x40, 0x06, 0xb1, 0xe6}
	whole := append(append([]byte{}, a...), b...)

	if Fold(Checksum(b, Checksum(a, 0))) != Fold(Checksum(whole, 0)) {
		t.Error("incremental checksum != whole-buffer checksum")
	}
}

func TestVerifyIPv4Checksum(t *testing.T) {
	pkt := ipv4UDP(t, []byte("payload"))

	if err := VerifyIPv4Checksum(pkt); err != nil {
		t.Fatalf("VerifyIPv4Checksum on freshly built packet: %v", err)
	}

	// Flip a bit in the TTL and the header checksum must stop verifying.
	corrupt := make([]byte, len(pkt))
	copy(corrupt, pkt)
	corrupt[8] ^= 0x01
	if err := VerifyIPv4Checksum(corrupt); !errors.Is(err, ErrBadChecksum) {
		t.Errorf("VerifyIPv4Checksum on corrupted packet = %v, want ErrBadChecksum", err)
	}
}

func TestVerifyL4ChecksumUDP(t *testing.T) {
	for _, family := range []struct {
		name     string
		src, dst string
	}{
		{"ipv4", "10.0.0.2:4444", "1.1.1.1:53"},
		{"ipv6", "[fd00::2]:4444", "[2606:4700:4700::1111]:53"},
	} {
		t.Run(family.name, func(t *testing.T) {
			buf := make([]byte, 1500)
			pkt, err := BuildUDP(buf,
				netip.MustParseAddrPort(family.src),
				netip.MustParseAddrPort(family.dst),
				[]byte("checksum me"))
			if err != nil {
				t.Fatalf("BuildUDP: %v", err)
			}
			p, err := Parse(pkt)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if err := VerifyL4Checksum(p, pkt); err != nil {
				t.Fatalf("VerifyL4Checksum on built packet: %v", err)
			}

			corrupt := make([]byte, len(pkt))
			copy(corrupt, pkt)
			corrupt[len(corrupt)-1] ^= 0xff
			cp, err := Parse(corrupt)
			if err != nil {
				t.Fatalf("Parse corrupt: %v", err)
			}
			if err := VerifyL4Checksum(cp, corrupt); !errors.Is(err, ErrBadChecksum) {
				t.Errorf("VerifyL4Checksum on corrupted payload = %v, want ErrBadChecksum", err)
			}
		})
	}
}

func TestVerifyL4ChecksumZeroUDPChecksum(t *testing.T) {
	// Zero means "not computed" in IPv4 and is legal; the same value is
	// illegal in IPv6 and must be rejected.
	t.Run("ipv4 accepts zero", func(t *testing.T) {
		buf := make([]byte, 1500)
		pkt, _ := BuildUDP(buf,
			netip.MustParseAddrPort("10.0.0.2:4444"),
			netip.MustParseAddrPort("1.1.1.1:53"),
			[]byte("x"))
		binary.BigEndian.PutUint16(pkt[ipv4MinHeaderLen+6:ipv4MinHeaderLen+8], 0)
		p, _ := Parse(pkt)
		if err := VerifyL4Checksum(p, pkt); err != nil {
			t.Errorf("VerifyL4Checksum = %v, want nil for zero IPv4 UDP checksum", err)
		}
	})

	t.Run("ipv6 rejects zero", func(t *testing.T) {
		buf := make([]byte, 1500)
		pkt, _ := BuildUDP(buf,
			netip.MustParseAddrPort("[fd00::2]:4444"),
			netip.MustParseAddrPort("[fd00::1]:53"),
			[]byte("x"))
		binary.BigEndian.PutUint16(pkt[ipv6HeaderLen+6:ipv6HeaderLen+8], 0)
		p, _ := Parse(pkt)
		if err := VerifyL4Checksum(p, pkt); !errors.Is(err, ErrBadChecksum) {
			t.Errorf("VerifyL4Checksum = %v, want ErrBadChecksum for zero IPv6 UDP checksum", err)
		}
	})
}

func TestVerifyL4ChecksumTCP(t *testing.T) {
	pkt := tcpSegment(t, PSH|ACK, []byte{2, 4, 0x05, 0xb4}, []byte("GET / HTTP/1.1\r\n\r\n"))
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := VerifyL4Checksum(p, pkt); err != nil {
		t.Fatalf("VerifyL4Checksum on built segment: %v", err)
	}

	corrupt := make([]byte, len(pkt))
	copy(corrupt, pkt)
	corrupt[len(corrupt)-3] ^= 0x20
	cp, _ := Parse(corrupt)
	if err := VerifyL4Checksum(cp, corrupt); !errors.Is(err, ErrBadChecksum) {
		t.Errorf("VerifyL4Checksum on corrupted segment = %v, want ErrBadChecksum", err)
	}
}

func TestBuildUDPFamilyMismatch(t *testing.T) {
	buf := make([]byte, 1500)
	_, err := BuildUDP(buf,
		netip.MustParseAddrPort("10.0.0.2:4444"),
		netip.MustParseAddrPort("[fd00::1]:53"),
		nil)
	if !errors.Is(err, ErrAddrFamilyMismatch) {
		t.Errorf("BuildUDP err = %v, want ErrAddrFamilyMismatch", err)
	}
}

func TestBuildUDPBufferTooSmall(t *testing.T) {
	buf := make([]byte, 20)
	_, err := BuildUDP(buf,
		netip.MustParseAddrPort("10.0.0.2:4444"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		[]byte("too long for the buffer"))
	if !errors.Is(err, ErrTooShort) {
		t.Errorf("BuildUDP err = %v, want ErrTooShort", err)
	}
}

func TestBuildUDPRoundTrip(t *testing.T) {
	payload := []byte("round trip")
	buf := make([]byte, 1500)
	src := netip.MustParseAddrPort("10.0.0.2:4444")
	dst := netip.MustParseAddrPort("1.1.1.1:53")

	pkt, err := BuildUDP(buf, src, dst, payload)
	if err != nil {
		t.Fatalf("BuildUDP: %v", err)
	}
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Flow.Src != src {
		t.Errorf("Src = %v, want %v", p.Flow.Src, src)
	}
	if p.Flow.Dst != dst {
		t.Errorf("Dst = %v, want %v", p.Flow.Dst, dst)
	}
	if got := string(p.Payload(pkt)); got != string(payload) {
		t.Errorf("Payload = %q, want %q", got, payload)
	}
}

func BenchmarkParse(b *testing.B) {
	buf := make([]byte, 1500)
	pkt, err := BuildUDP(buf,
		netip.MustParseAddrPort("10.0.0.2:4444"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		make([]byte, 512))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		if _, err := Parse(pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChecksum1400(b *testing.B) {
	buf := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))
	for b.Loop() {
		Fold(Checksum(buf, 0))
	}
}
