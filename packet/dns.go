package packet

import (
	"encoding/binary"
	"errors"
	"strings"
)

// DNS parse errors.
var (
	ErrDNSTooShort   = errors.New("packet: DNS message shorter than header")
	ErrDNSNoQuestion = errors.New("packet: DNS message has no question section")
	ErrDNSBadName    = errors.New("packet: malformed DNS name")
)

const (
	dnsHeaderLen = 12

	// maxDNSNameLen is the RFC 1035 limit on a presentation-format name.
	maxDNSNameLen = 255
	// maxDNSLabels bounds the label walk independently of the name length, so
	// a pathological run of 1-byte labels terminates.
	maxDNSLabels = 128
)

// DNSQuestion is the first question of a DNS message.
type DNSQuestion struct {
	ID uint16
	// Name is in RFC 4343 presentation format: lower-cased, no trailing
	// dot, and with any '.' or '\' inside a label escaped as `\.` and
	// `\\`. The escaping is what makes Name injective: without it the
	// single label "www.example.com" and the three labels www/example/com
	// would produce the same string, and the proxy keys both its cache and
	// its policy on this field.
	Name  string
	QType uint16
	Class uint16
	// Response reports whether the QR bit was set.
	Response bool
	// Opcode and RCode are kept because the DNS proxy's SERVFAIL path needs
	// to echo the opcode back.
	Opcode uint8
	RCode  uint8
}

// Common QTYPE values the DNS proxy special-cases.
const (
	QTypeA     uint16 = 1
	QTypeAAAA  uint16 = 28
	QTypeCNAME uint16 = 5
	QTypeHTTPS uint16 = 65
	QTypePTR   uint16 = 12
)

// ParseDNSQuestion parses the header and first question of a wire-format DNS
// message. It does not follow compression pointers: a pointer in the question
// section is always malformed, since there is nothing earlier in the message
// for it to point at.
//
// Name compression is where hand-rolled DNS parsers grow their pointer loops
// and their CVEs. Refusing pointers here means this function cannot loop, and
// the DNS proxy never needs to parse the answer section at all — it forwards
// responses opaquely and only reads questions.
func ParseDNSQuestion(b []byte) (DNSQuestion, error) {
	if len(b) < dnsHeaderLen {
		return DNSQuestion{}, ErrDNSTooShort
	}
	qdCount := binary.BigEndian.Uint16(b[4:6])
	if qdCount == 0 {
		return DNSQuestion{}, ErrDNSNoQuestion
	}

	flags := binary.BigEndian.Uint16(b[2:4])
	q := DNSQuestion{
		ID:       binary.BigEndian.Uint16(b[0:2]),
		Response: flags&0x8000 != 0,
		Opcode:   uint8((flags >> 11) & 0x0f),
		RCode:    uint8(flags & 0x0f),
	}

	name, off, err := decodeName(b, dnsHeaderLen)
	if err != nil {
		return DNSQuestion{}, err
	}
	if off+4 > len(b) {
		return DNSQuestion{}, ErrDNSTooShort
	}
	q.Name = name
	q.QType = binary.BigEndian.Uint16(b[off : off+2])
	q.Class = binary.BigEndian.Uint16(b[off+2 : off+4])
	return q, nil
}

func decodeName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	for labels := 0; ; labels++ {
		if labels > maxDNSLabels {
			return "", 0, ErrDNSBadName
		}
		if off >= len(b) {
			return "", 0, ErrDNSTooShort
		}
		n := int(b[off])
		switch {
		case n == 0:
			return sb.String(), off + 1, nil
		case n&0xc0 == 0xc0:
			// Compression pointer: see the doc comment on ParseDNSQuestion.
			return "", 0, ErrDNSBadName
		case n&0xc0 != 0:
			// Reserved label types (0b01, 0b10) have no defined meaning.
			return "", 0, ErrDNSBadName
		}
		off++
		if off+n > len(b) {
			return "", 0, ErrDNSTooShort
		}
		label := b[off : off+n]
		// The length budget is applied to the escaped form, because that is
		// the string callers store and compare. A name full of escaped dots
		// is rejected slightly earlier than its wire length alone would
		// require, which costs nothing: no real name looks like that.
		if sb.Len()+escapedLen(label)+1 > maxDNSNameLen {
			return "", 0, ErrDNSBadName
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for _, c := range label {
			switch {
			case c >= 'A' && c <= 'Z':
				c += 'a' - 'A'
			case c == '.' || c == '\\':
				// Escape rather than reject: a label containing a dot is
				// legal on the wire and some resolvers answer it, so
				// refusing it would be a functional change. What matters is
				// only that it can never render the same as a name whose
				// labels are split at that dot.
				sb.WriteByte('\\')
			}
			sb.WriteByte(c)
		}
		off += n
	}
}

// escapedLen is the length of label once decodeName has escaped it.
func escapedLen(label []byte) int {
	n := len(label)
	for _, c := range label {
		if c == '.' || c == '\\' {
			n++
		}
	}
	return n
}
