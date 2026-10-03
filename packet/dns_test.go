package packet

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// dnsQuery builds a wire-format DNS query for name with the given qtype.
func dnsQuery(id uint16, name string, qtype uint16) []byte {
	b := make([]byte, 0, dnsHeaderLen+len(name)+6)
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // standard query, RD set
	b = binary.BigEndian.AppendUint16(b, 1)      // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ANCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // NSCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ARCOUNT
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	return b
}

func TestParseDNSQuestion(t *testing.T) {
	tests := []struct {
		name  string
		query string
		qtype uint16
		want  string
	}{
		{"simple", "example.com", QTypeA, "example.com"},
		{"subdomain", "api.v2.example.com", QTypeAAAA, "api.v2.example.com"},
		{"uppercase normalised", "EXAMPLE.COM", QTypeA, "example.com"},
		{"mixed case normalised", "Api.Example.Com", QTypeHTTPS, "api.example.com"},
		{"single label", "localhost", QTypeA, "localhost"},
		{"hyphen and digits", "cdn-3.example-site.com", QTypeA, "cdn-3.example-site.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := ParseDNSQuestion(dnsQuery(0x1234, tt.query, tt.qtype))
			if err != nil {
				t.Fatalf("ParseDNSQuestion: %v", err)
			}
			if q.Name != tt.want {
				t.Errorf("Name = %q, want %q", q.Name, tt.want)
			}
			if q.QType != tt.qtype {
				t.Errorf("QType = %d, want %d", q.QType, tt.qtype)
			}
			if q.ID != 0x1234 {
				t.Errorf("ID = %#x, want 0x1234", q.ID)
			}
			if q.Response {
				t.Error("Response = true, want false for a query")
			}
			if q.Class != 1 {
				t.Errorf("Class = %d, want 1 (IN)", q.Class)
			}
		})
	}
}

func TestParseDNSQuestionResponseBit(t *testing.T) {
	msg := dnsQuery(1, "example.com", QTypeA)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180) // QR set, RA set, NOERROR
	q, err := ParseDNSQuestion(msg)
	if err != nil {
		t.Fatalf("ParseDNSQuestion: %v", err)
	}
	if !q.Response {
		t.Error("Response = false, want true when QR is set")
	}
	if q.RCode != 0 {
		t.Errorf("RCode = %d, want 0", q.RCode)
	}
}

func TestParseDNSQuestionMalformed(t *testing.T) {
	valid := dnsQuery(1, "example.com", QTypeA)

	tests := []struct {
		name    string
		msg     []byte
		wantErr error
	}{
		{"empty", nil, ErrDNSTooShort},
		{"header only truncated", valid[:11], ErrDNSTooShort},
		{
			name: "zero question count",
			msg: func() []byte {
				b := append([]byte{}, valid...)
				binary.BigEndian.PutUint16(b[4:6], 0)
				return b
			}(),
			wantErr: ErrDNSNoQuestion,
		},
		{
			name:    "name runs off the end",
			msg:     valid[:len(valid)-8],
			wantErr: ErrDNSTooShort,
		},
		{
			name: "compression pointer in question",
			msg: func() []byte {
				b := append([]byte{}, valid[:dnsHeaderLen]...)
				return append(b, 0xc0, 0x0c, 0, 1, 0, 1)
			}(),
			wantErr: ErrDNSBadName,
		},
		{
			name: "reserved label type",
			msg: func() []byte {
				b := append([]byte{}, valid[:dnsHeaderLen]...)
				return append(b, 0x40, 0x00, 0, 1, 0, 1)
			}(),
			wantErr: ErrDNSBadName,
		},
		{
			name: "label length overruns message",
			msg: func() []byte {
				b := append([]byte{}, valid[:dnsHeaderLen]...)
				return append(b, 60, 'a', 'b', 'c')
			}(),
			wantErr: ErrDNSTooShort,
		},
		{
			name: "question missing type and class",
			msg: func() []byte {
				b := append([]byte{}, valid[:dnsHeaderLen]...)
				return append(b, 3, 'c', 'o', 'm', 0)
			}(),
			wantErr: ErrDNSTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseDNSQuestion(tt.msg); !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseDNSQuestion err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDNSQuestionNameTooLong(t *testing.T) {
	// 40 labels of 8 bytes each exceeds the 255-byte presentation limit.
	b := append([]byte{}, dnsQuery(1, "x", QTypeA)[:dnsHeaderLen]...)
	for i := 0; i < 40; i++ {
		b = append(b, 8)
		b = append(b, "abcdefgh"...)
	}
	b = append(b, 0, 0, 1, 0, 1)

	if _, err := ParseDNSQuestion(b); !errors.Is(err, ErrDNSBadName) {
		t.Errorf("ParseDNSQuestion err = %v, want ErrDNSBadName", err)
	}
}

func TestParseDNSQuestionManyEmptyLabelsTerminates(t *testing.T) {
	// A long run of zero-length... is actually a terminator, so instead use
	// 1-byte labels, which exercise the label budget without the length
	// budget firing first.
	b := append([]byte{}, dnsQuery(1, "x", QTypeA)[:dnsHeaderLen]...)
	for i := 0; i < maxDNSLabels+10; i++ {
		b = append(b, 1, 'a')
	}
	b = append(b, 0, 0, 1, 0, 1)

	// Either budget may trip first; what matters is that it returns.
	if _, err := ParseDNSQuestion(b); err == nil {
		t.Error("ParseDNSQuestion err = nil, want a name error")
	}
}

func BenchmarkParseDNSQuestion(b *testing.B) {
	msg := dnsQuery(1, "telemetry.api.example.com", QTypeA)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseDNSQuestion(msg); err != nil {
			b.Fatal(err)
		}
	}
}

// dnsQueryLabels builds a query from explicit wire labels, so a test can put a
// '.' inside a label — which dnsQuery, splitting on dots, cannot express.
func dnsQueryLabels(id uint16, labels []string, qtype uint16) []byte {
	b := append([]byte{}, dnsQuery(id, "x", qtype)[:dnsHeaderLen]...)
	for _, label := range labels {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 1)
}

// TestParseDNSQuestionEscapesLabelDots: Name keys the proxy's cache and its
// blocklist, so two different wire names must never decode to the same
// string. Joining labels with an unescaped '.' made the single label
// "www.example.com" indistinguishable from the real three-label name.
func TestParseDNSQuestionEscapesLabelDots(t *testing.T) {
	tests := []struct {
		name   string
		labels []string
		want   string
	}{
		{"ordinary name unchanged", []string{"www", "example", "com"}, "www.example.com"},
		{"dot inside a single label", []string{"www.example.com"}, `www\.example\.com`},
		{"dot inside one of several labels", []string{"www.example", "com"}, `www\.example.com`},
		{"backslash escaped", []string{`a\b`, "com"}, `a\\b.com`},
		{"escaped backslash cannot forge an escaped dot", []string{`a\`, "b"}, `a\\.b`},
		{"lower-casing still applies", []string{"WWW.Example", "COM"}, `www\.example.com`},
	}
	seen := map[string]string{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := ParseDNSQuestion(dnsQueryLabels(1, tt.labels, QTypeA))
			if err != nil {
				t.Fatalf("ParseDNSQuestion: %v", err)
			}
			if q.Name != tt.want {
				t.Errorf("Name = %q, want %q", q.Name, tt.want)
			}
			wire := strings.ToLower(strings.Join(tt.labels, "\x00"))
			if other, dup := seen[q.Name]; dup && other != wire {
				t.Errorf("labels %q and %q both decode to %q", tt.labels, other, q.Name)
			}
			seen[q.Name] = wire
		})
	}
}

// TestParseDNSQuestionEscapedNameRespectsLengthLimit: escaping grows the
// string, and the 255-byte bound is on what callers store, not on the wire.
func TestParseDNSQuestionEscapedNameRespectsLengthLimit(t *testing.T) {
	// Three 63-byte labels of dots fit on the wire (192 bytes) but escape to
	// 3*126+2 = 380 bytes.
	dots := strings.Repeat(".", 63)
	_, err := ParseDNSQuestion(dnsQueryLabels(1, []string{dots, dots, dots}, QTypeA))
	if !errors.Is(err, ErrDNSBadName) {
		t.Errorf("ParseDNSQuestion err = %v, want ErrDNSBadName", err)
	}
}
