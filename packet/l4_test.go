package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestParseUDP(t *testing.T) {
	pkt := ipv4UDP(t, []byte("query"))
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.L4.Proto != ProtoUDP {
		t.Errorf("Proto = %v, want udp", p.L4.Proto)
	}
	if p.L4.SrcPort != 4444 || p.L4.DstPort != 53 {
		t.Errorf("ports = %d -> %d, want 4444 -> 53", p.L4.SrcPort, p.L4.DstPort)
	}
	if want := udpHeaderLen + 5; p.L4.DeclaredLen != want {
		t.Errorf("DeclaredLen = %d, want %d", p.L4.DeclaredLen, want)
	}
	if got := string(p.Payload(pkt)); got != "query" {
		t.Errorf("Payload = %q, want %q", got, "query")
	}
	if !p.Flow.IsDNS() {
		t.Error("IsDNS = false, want true for port 53")
	}
}

func TestParseUDPMalformed(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
	}{
		{"too short", []byte{0, 1, 2, 3, 4, 5, 6}, ErrTooShort},
		{
			name:    "declared length below header",
			b:       []byte{0, 53, 0, 53, 0, 4, 0, 0},
			wantErr: ErrBadHeaderLength,
		},
		{
			name:    "declared length beyond buffer",
			b:       []byte{0, 53, 0, 53, 0xff, 0xff, 0, 0},
			wantErr: ErrLengthMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseL4(ProtoUDP, tt.b); !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseL4 err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// tcpSegment builds an IPv4/TCP packet with the given options area and flags.
func tcpSegment(t *testing.T, flags TCPFlags, opts []byte, payload []byte) []byte {
	t.Helper()
	if len(opts)%4 != 0 {
		t.Fatalf("options must be a multiple of 4 bytes, got %d", len(opts))
	}
	tcpLen := tcpMinHeaderLen + len(opts) + len(payload)
	total := ipv4MinHeaderLen + tcpLen
	b := make([]byte, total)

	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8] = 64
	b[9] = byte(ProtoTCP)
	copy(b[12:16], netip.MustParseAddr("10.0.0.2").AsSlice())
	copy(b[16:20], netip.MustParseAddr("93.184.216.34").AsSlice())
	binary.BigEndian.PutUint16(b[10:12], Fold(Checksum(b[:ipv4MinHeaderLen], 0)))

	tcp := b[ipv4MinHeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 51000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], 0xdeadbeef)
	binary.BigEndian.PutUint32(tcp[8:12], 0x0badf00d)
	tcp[12] = byte((tcpMinHeaderLen+len(opts))/4) << 4
	tcp[13] = byte(flags)
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[tcpMinHeaderLen:], opts)
	copy(tcp[tcpMinHeaderLen+len(opts):], payload)

	ip, err := parseIPv4(b)
	if err != nil {
		t.Fatalf("parseIPv4: %v", err)
	}
	sum := pseudoHeaderSum(ip, ProtoTCP, tcpLen)
	binary.BigEndian.PutUint16(tcp[16:18], Fold(Checksum(tcp, sum)))
	return b
}

func TestParseTCP(t *testing.T) {
	pkt := tcpSegment(t, SYN, nil, nil)
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.L4.Flags != SYN {
		t.Errorf("Flags = %v, want SYN", p.L4.Flags)
	}
	if p.L4.Seq != 0xdeadbeef {
		t.Errorf("Seq = %#x, want 0xdeadbeef", p.L4.Seq)
	}
	if p.L4.Ack != 0x0badf00d {
		t.Errorf("Ack = %#x, want 0x0badf00d", p.L4.Ack)
	}
	if p.L4.HeaderLen != tcpMinHeaderLen {
		t.Errorf("HeaderLen = %d, want %d", p.L4.HeaderLen, tcpMinHeaderLen)
	}
	if got, want := p.Flow.String(), "tcp 10.0.0.2:51000 -> 93.184.216.34:443"; got != want {
		t.Errorf("Flow = %q, want %q", got, want)
	}
}

func TestTCPFlagsString(t *testing.T) {
	tests := []struct {
		flags TCPFlags
		want  string
	}{
		{0, "-"},
		{SYN, "SYN"},
		{SYN | ACK, "SYN|ACK"},
		{FIN | ACK, "FIN|ACK"},
		{RST, "RST"},
		{PSH | ACK, "PSH|ACK"},
	}
	for _, tt := range tests {
		if got := tt.flags.String(); got != tt.want {
			t.Errorf("TCPFlags(%#x).String() = %q, want %q", uint8(tt.flags), got, tt.want)
		}
	}
}

func TestFindMSSOption(t *testing.T) {
	tests := []struct {
		name string
		opts []byte
		want uint16
	}{
		{"no options", nil, 0},
		{
			name: "MSS first",
			opts: []byte{2, 4, 0x05, 0xb4, 0, 0, 0, 0}, // MSS 1460
			want: 1460,
		},
		{
			name: "MSS after NOPs",
			opts: []byte{1, 1, 2, 4, 0x05, 0x14, 0, 0}, // MSS 1300
			want: 1300,
		},
		{
			name: "MSS after window scale",
			opts: []byte{3, 3, 7, 2, 4, 0x04, 0xd0, 0}, // wscale, then MSS 1232
			want: 1232,
		},
		{
			name: "end-of-list before MSS",
			opts: []byte{0, 2, 4, 0x05, 0xb4, 0, 0, 0},
			want: 0,
		},
		{
			name: "option length zero does not loop",
			opts: []byte{8, 0, 0, 0},
			want: 0,
		},
		{
			name: "option length overruns buffer",
			opts: []byte{8, 200, 0, 0},
			want: 0,
		},
		{
			name: "truncated option header",
			opts: []byte{8},
			want: 0,
		},
		{
			name: "MSS with wrong length ignored",
			opts: []byte{2, 6, 0x05, 0xb4, 0, 0, 0, 0},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findMSSOption(tt.opts); got != tt.want {
				t.Errorf("findMSSOption = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseTCPWithMSSOption(t *testing.T) {
	pkt := tcpSegment(t, SYN, []byte{2, 4, 0x05, 0xb4}, nil)
	p, err := Parse(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.L4.MSS != 1460 {
		t.Errorf("MSS = %d, want 1460", p.L4.MSS)
	}
	if p.L4.HeaderLen != 24 {
		t.Errorf("HeaderLen = %d, want 24", p.L4.HeaderLen)
	}
}

func TestParseTCPMalformed(t *testing.T) {
	tests := []struct {
		name    string
		b       []byte
		wantErr error
	}{
		{"too short", make([]byte, 19), ErrTooShort},
		{
			name: "data offset below minimum",
			b: func() []byte {
				b := make([]byte, 20)
				b[12] = 0x40 // offset 4 = 16 bytes
				return b
			}(),
			wantErr: ErrBadHeaderLength,
		},
		{
			name: "data offset beyond buffer",
			b: func() []byte {
				b := make([]byte, 24)
				b[12] = 0xf0 // offset 15 = 60 bytes
				return b
			}(),
			wantErr: ErrLengthMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseL4(ProtoTCP, tt.b); !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseL4 err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseUnsupportedProto(t *testing.T) {
	// SCTP. The IP header must still come back populated so a packet
	// transport can forward what a stream transport cannot handle.
	pkt := ipv4UDP(t, []byte("x"))
	pkt[9] = 132
	binary.BigEndian.PutUint16(pkt[10:12], 0)

	p, err := Parse(pkt)
	if !errors.Is(err, ErrUnsupportedProto) {
		t.Fatalf("Parse err = %v, want ErrUnsupportedProto", err)
	}
	if p.IP.Version != IPv4 {
		t.Error("IP header not populated on ErrUnsupportedProto")
	}
	if p.IP.Proto != 132 {
		t.Errorf("IP.Proto = %d, want 132", p.IP.Proto)
	}
}

func TestFlowReverse(t *testing.T) {
	f := Flow{
		Proto: ProtoTCP,
		Src:   netip.MustParseAddrPort("10.0.0.2:51000"),
		Dst:   netip.MustParseAddrPort("93.184.216.34:443"),
	}
	r := f.Reverse()
	if r.Src != f.Dst || r.Dst != f.Src {
		t.Errorf("Reverse = %v, want src/dst swapped", r)
	}
	if r.Reverse() != f {
		t.Error("Reverse is not an involution")
	}
}
