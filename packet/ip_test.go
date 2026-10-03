package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

// ipv4UDP builds a minimal valid IPv4/UDP packet for tests. It writes the
// declared lengths honestly; the mutation helpers below are what make them
// dishonest.
func ipv4UDP(t *testing.T, payload []byte) []byte {
	t.Helper()
	buf := make([]byte, 1500)
	b, err := BuildUDP(buf,
		netip.MustParseAddrPort("10.0.0.2:4444"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		payload)
	if err != nil {
		t.Fatalf("BuildUDP: %v", err)
	}
	return b
}

func TestParseIPv4(t *testing.T) {
	pkt := ipv4UDP(t, []byte("hello"))

	h, err := ParseIP(pkt)
	if err != nil {
		t.Fatalf("ParseIP: %v", err)
	}
	if h.Version != IPv4 {
		t.Errorf("Version = %v, want IPv4", h.Version)
	}
	if h.Proto != ProtoUDP {
		t.Errorf("Proto = %v, want udp", h.Proto)
	}
	if got, want := h.Src.String(), "10.0.0.2"; got != want {
		t.Errorf("Src = %s, want %s", got, want)
	}
	if got, want := h.Dst.String(), "1.1.1.1"; got != want {
		t.Errorf("Dst = %s, want %s", got, want)
	}
	if h.HeaderLen != 20 {
		t.Errorf("HeaderLen = %d, want 20", h.HeaderLen)
	}
	if want := 20 + 8 + 5; h.TotalLen != want {
		t.Errorf("TotalLen = %d, want %d", h.TotalLen, want)
	}
	if h.PayloadLen != 13 {
		t.Errorf("PayloadLen = %d, want 13", h.PayloadLen)
	}
	if h.Fragmented {
		t.Error("Fragmented = true, want false")
	}
}

func TestParseIPMalformed(t *testing.T) {
	valid := ipv4UDP(t, []byte("x"))

	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr error
	}{
		{
			name:    "empty buffer",
			mutate:  func([]byte) []byte { return nil },
			wantErr: ErrTooShort,
		},
		{
			name:    "one byte",
			mutate:  func(b []byte) []byte { return b[:1] },
			wantErr: ErrTooShort,
		},
		{
			name:    "truncated below minimum header",
			mutate:  func(b []byte) []byte { return b[:19] },
			wantErr: ErrTooShort,
		},
		{
			name:    "version 7",
			mutate:  func(b []byte) []byte { b[0] = 0x75; return b },
			wantErr: ErrBadVersion,
		},
		{
			name:    "version 0",
			mutate:  func(b []byte) []byte { b[0] = 0x05; return b },
			wantErr: ErrBadVersion,
		},
		{
			name:    "IHL below 5",
			mutate:  func(b []byte) []byte { b[0] = 0x44; return b },
			wantErr: ErrBadHeaderLength,
		},
		{
			name: "IHL beyond buffer",
			mutate: func(b []byte) []byte {
				b[0] = 0x4f // IHL 15 = 60 bytes, buffer is 29
				return b
			},
			wantErr: ErrLengthMismatch,
		},
		{
			name: "total length below header length",
			mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint16(b[2:4], 10)
				return b
			},
			wantErr: ErrBadHeaderLength,
		},
		{
			name: "total length beyond buffer",
			mutate: func(b []byte) []byte {
				binary.BigEndian.PutUint16(b[2:4], 2000)
				return b
			},
			wantErr: ErrLengthMismatch,
		},
		{
			name:    "IPv6 truncated",
			mutate:  func(b []byte) []byte { b[0] = 0x60; return b },
			wantErr: ErrTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := make([]byte, len(valid))
			copy(b, valid)
			_, err := ParseIP(tt.mutate(b))
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseIP err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseIPv4Fragment(t *testing.T) {
	pkt := ipv4UDP(t, []byte("fragmented"))

	t.Run("first fragment parses", func(t *testing.T) {
		b := make([]byte, len(pkt))
		copy(b, pkt)
		binary.BigEndian.PutUint16(b[6:8], 0x2000) // MF set, offset 0
		p, err := Parse(b)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !p.IP.Fragmented {
			t.Error("Fragmented = false, want true")
		}
		if p.IP.FragOffset != 0 {
			t.Errorf("FragOffset = %d, want 0", p.IP.FragOffset)
		}
	})

	t.Run("non-initial fragment rejected", func(t *testing.T) {
		b := make([]byte, len(pkt))
		copy(b, pkt)
		binary.BigEndian.PutUint16(b[6:8], 185) // offset 185*8 = 1480
		_, err := Parse(b)
		if !errors.Is(err, ErrFragmented) {
			t.Fatalf("Parse err = %v, want ErrFragmented", err)
		}
	})
}

func TestParseIPv6ExtensionHeaders(t *testing.T) {
	// 40-byte IPv6 header, then a hop-by-hop header, then a destination
	// options header, then UDP.
	hopByHop := []byte{
		byte(protoDestOpts), 0, // next = dest opts, len = (0+1)*8 = 8
		0, 0, 0, 0, 0, 0,
	}
	destOpts := []byte{
		byte(ProtoUDP), 0,
		0, 0, 0, 0, 0, 0,
	}
	udp := []byte{0x11, 0x5c, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 'a', 'b', 'c', 'd'}

	payload := append(append(append([]byte{}, hopByHop...), destOpts...), udp...)

	b := make([]byte, ipv6HeaderLen+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = byte(protoHopByHop)
	b[7] = 64
	copy(b[8:24], netip.MustParseAddr("fd00::2").AsSlice())
	copy(b[24:40], netip.MustParseAddr("2606:4700:4700::1111").AsSlice())
	copy(b[ipv6HeaderLen:], payload)

	p, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.IP.Proto != ProtoUDP {
		t.Errorf("Proto = %v, want udp", p.IP.Proto)
	}
	if want := ipv6HeaderLen + 16; p.IP.HeaderLen != want {
		t.Errorf("HeaderLen = %d, want %d (base + 2 ext headers)", p.IP.HeaderLen, want)
	}
	if p.Flow.Dst.Port() != 53 {
		t.Errorf("Dst port = %d, want 53", p.Flow.Dst.Port())
	}
	if got, want := p.Flow.Src.Addr().String(), "fd00::2"; got != want {
		t.Errorf("Src = %s, want %s", got, want)
	}
}

func TestParseIPv6ExtensionHeaderChainBounded(t *testing.T) {
	// A chain of destination-options headers each pointing at another, longer
	// than maxExtHeaders. A parser without a hop budget walks this forever
	// when the chain is made to loop; one with a budget rejects it.
	const chain = maxExtHeaders + 4
	payload := make([]byte, 0, chain*8)
	for i := 0; i < chain; i++ {
		next := byte(protoDestOpts)
		if i == chain-1 {
			next = byte(protoNoNextHdr)
		}
		payload = append(payload, next, 0, 0, 0, 0, 0, 0, 0)
	}

	b := make([]byte, ipv6HeaderLen+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = byte(protoDestOpts)
	copy(b[ipv6HeaderLen:], payload)

	if _, err := ParseIP(b); !errors.Is(err, ErrExtHeaderChain) {
		t.Fatalf("ParseIP err = %v, want ErrExtHeaderChain", err)
	}
}

func TestParseIPv6ExtensionHeaderOverrun(t *testing.T) {
	// An extension header whose declared length runs past the end of the
	// packet must be rejected, not read out of bounds.
	b := make([]byte, ipv6HeaderLen+8)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], 8)
	b[6] = byte(protoDestOpts)
	b[ipv6HeaderLen] = byte(ProtoUDP)
	b[ipv6HeaderLen+1] = 200 // claims (200+1)*8 bytes

	if _, err := ParseIP(b); !errors.Is(err, ErrExtHeaderChain) {
		t.Fatalf("ParseIP err = %v, want ErrExtHeaderChain", err)
	}
}
