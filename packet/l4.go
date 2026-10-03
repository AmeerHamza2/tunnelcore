package packet

import (
	"encoding/binary"
	"strings"
)

const (
	udpHeaderLen    = 8
	tcpMinHeaderLen = 20
)

// TCPFlags is the TCP control-bit field.
type TCPFlags uint8

const (
	FIN TCPFlags = 1 << 0
	SYN TCPFlags = 1 << 1
	RST TCPFlags = 1 << 2
	PSH TCPFlags = 1 << 3
	ACK TCPFlags = 1 << 4
	URG TCPFlags = 1 << 5
	ECE TCPFlags = 1 << 6
	CWR TCPFlags = 1 << 7
)

func (f TCPFlags) Has(x TCPFlags) bool { return f&x != 0 }

func (f TCPFlags) String() string {
	if f == 0 {
		return "-"
	}
	var sb strings.Builder
	for _, p := range []struct {
		bit  TCPFlags
		name string
	}{
		{FIN, "FIN"}, {SYN, "SYN"}, {RST, "RST"}, {PSH, "PSH"},
		{ACK, "ACK"}, {URG, "URG"}, {ECE, "ECE"}, {CWR, "CWR"},
	} {
		if f.Has(p.bit) {
			if sb.Len() > 0 {
				sb.WriteByte('|')
			}
			sb.WriteString(p.name)
		}
	}
	return sb.String()
}

// L4Header describes a parsed TCP or UDP header.
type L4Header struct {
	Proto   Proto
	SrcPort uint16
	DstPort uint16

	// HeaderLen is the L4 header length in bytes (8 for UDP, 20..60 for TCP).
	HeaderLen int
	// DeclaredLen is the UDP length field, or 0 for TCP (which has none).
	DeclaredLen int

	// TCP only.
	Flags  TCPFlags
	Seq    uint32
	Ack    uint32
	Window uint16
	// MSS is the value of the TCP MSS option if present, else 0. The engine
	// clamps this when the negotiated tunnel MTU is smaller than the path the
	// client assumed, which is the difference between "the VPN is slow" and
	// "the VPN silently blackholes large responses".
	MSS uint16
}

// ParseL4 parses the TCP or UDP header at the start of b.
func ParseL4(proto Proto, b []byte) (L4Header, error) {
	switch proto {
	case ProtoUDP:
		return parseUDP(b)
	case ProtoTCP:
		return parseTCP(b)
	default:
		return L4Header{}, ErrUnsupportedProto
	}
}

func parseUDP(b []byte) (L4Header, error) {
	if len(b) < udpHeaderLen {
		return L4Header{}, ErrTooShort
	}
	declared := int(binary.BigEndian.Uint16(b[4:6]))
	// The UDP length field covers the header plus payload, so anything below
	// the header size is malformed regardless of the buffer.
	if declared < udpHeaderLen {
		return L4Header{}, ErrBadHeaderLength
	}
	if declared > len(b) {
		return L4Header{}, ErrLengthMismatch
	}
	return L4Header{
		Proto:       ProtoUDP,
		SrcPort:     binary.BigEndian.Uint16(b[0:2]),
		DstPort:     binary.BigEndian.Uint16(b[2:4]),
		HeaderLen:   udpHeaderLen,
		DeclaredLen: declared,
	}, nil
}

func parseTCP(b []byte) (L4Header, error) {
	if len(b) < tcpMinHeaderLen {
		return L4Header{}, ErrTooShort
	}
	dataOff := int(b[12]>>4) * 4
	if dataOff < tcpMinHeaderLen {
		return L4Header{}, ErrBadHeaderLength
	}
	if dataOff > len(b) {
		return L4Header{}, ErrLengthMismatch
	}
	h := L4Header{
		Proto:     ProtoTCP,
		SrcPort:   binary.BigEndian.Uint16(b[0:2]),
		DstPort:   binary.BigEndian.Uint16(b[2:4]),
		HeaderLen: dataOff,
		Seq:       binary.BigEndian.Uint32(b[4:8]),
		Ack:       binary.BigEndian.Uint32(b[8:12]),
		Flags:     TCPFlags(b[13]),
		Window:    binary.BigEndian.Uint16(b[14:16]),
	}
	if dataOff > tcpMinHeaderLen {
		h.MSS = findMSSOption(b[tcpMinHeaderLen:dataOff])
	}
	return h, nil
}

// findMSSOption walks the TCP options area looking for kind 2 (MSS). Malformed
// option runs terminate the walk rather than erroring: a bad option does not
// make the segment unroutable, and the engine would rather forward a segment
// with an unknown MSS than drop a connection attempt.
func findMSSOption(opts []byte) uint16 {
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case 0: // end of option list
			return 0
		case 1: // no-op
			i++
			continue
		}
		if i+1 >= len(opts) {
			return 0
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return 0
		}
		if kind == 2 && optLen == 4 {
			return binary.BigEndian.Uint16(opts[i+2 : i+4])
		}
		i += optLen
	}
	return 0
}

// Payload returns the L4 payload of b as described by h.
func (h L4Header) Payload(b []byte) []byte {
	end := len(b)
	if h.Proto == ProtoUDP && h.DeclaredLen > 0 && h.DeclaredLen <= len(b) {
		end = h.DeclaredLen
	}
	if h.HeaderLen > end {
		return nil
	}
	return b[h.HeaderLen:end]
}
