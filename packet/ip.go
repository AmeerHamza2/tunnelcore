package packet

import (
	"encoding/binary"
	"net/netip"
)

// Version is the IP version nibble.
type Version uint8

const (
	IPv4 Version = 4
	IPv6 Version = 6
)

func (v Version) String() string {
	switch v {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	default:
		return "IP?"
	}
}

// Proto is an IP protocol number (IPv4 "protocol" / IPv6 "next header").
type Proto uint8

const (
	ProtoICMPv4 Proto = 1
	ProtoTCP    Proto = 6
	ProtoUDP    Proto = 17
	ProtoICMPv6 Proto = 58

	// IPv6 extension headers we walk past rather than treat as upper layer.
	protoHopByHop  Proto = 0
	protoRouting   Proto = 43
	protoFragment  Proto = 44
	protoDestOpts  Proto = 60
	protoNoNextHdr Proto = 59
)

func (p Proto) String() string {
	switch p {
	case ProtoICMPv4:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmp6"
	default:
		return "proto?"
	}
}

const (
	ipv4MinHeaderLen = 20
	ipv6HeaderLen    = 40

	// maxExtHeaders bounds the IPv6 extension-header walk. RFC 8200 places no
	// limit, so we impose one: a chain longer than this is either an attack or
	// something no mobile app will ever legitimately send.
	maxExtHeaders = 8
)

// IPHeader describes a parsed IP header. Offsets index into the buffer passed
// to ParseIP; the struct borrows that buffer and must not outlive it.
type IPHeader struct {
	Version Version
	// Proto is the upper-layer protocol, i.e. the next-header value after any
	// IPv6 extension headers have been walked.
	Proto Proto
	Src   netip.Addr
	Dst   netip.Addr

	// HeaderLen is the number of bytes from the start of the buffer to the
	// upper-layer header, including IPv6 extension headers.
	HeaderLen int
	// TotalLen is the full on-wire packet length as declared by the header.
	TotalLen int
	// PayloadLen is TotalLen - HeaderLen.
	PayloadLen int

	TTL uint8
	// Fragmented reports whether this packet is part of a fragmented
	// datagram. FragOffset is zero for the first fragment.
	Fragmented bool
	FragOffset uint16
	// DSCP is the top 6 bits of the IPv4 ToS byte / IPv6 traffic class. The
	// engine preserves it when re-emitting packets so QoS markings survive
	// the tunnel.
	DSCP uint8
}

// ParseIP parses the IP header at the start of b. It does not verify
// checksums; see VerifyIPv4Checksum.
func ParseIP(b []byte) (IPHeader, error) {
	if len(b) < 1 {
		return IPHeader{}, ErrTooShort
	}
	switch Version(b[0] >> 4) {
	case IPv4:
		return parseIPv4(b)
	case IPv6:
		return parseIPv6(b)
	default:
		return IPHeader{}, ErrBadVersion
	}
}

func parseIPv4(b []byte) (IPHeader, error) {
	if len(b) < ipv4MinHeaderLen {
		return IPHeader{}, ErrTooShort
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipv4MinHeaderLen {
		return IPHeader{}, ErrBadHeaderLength
	}
	if ihl > len(b) {
		return IPHeader{}, ErrLengthMismatch
	}

	total := int(binary.BigEndian.Uint16(b[2:4]))
	// A declared total smaller than the header itself is nonsense.
	if total < ihl {
		return IPHeader{}, ErrBadHeaderLength
	}
	if total > len(b) {
		return IPHeader{}, ErrLengthMismatch
	}

	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	fragOffset := (flagsFrag & 0x1fff) * 8
	moreFragments := flagsFrag&0x2000 != 0

	h := IPHeader{
		Version:    IPv4,
		Proto:      Proto(b[9]),
		Src:        netip.AddrFrom4([4]byte(b[12:16])),
		Dst:        netip.AddrFrom4([4]byte(b[16:20])),
		HeaderLen:  ihl,
		TotalLen:   total,
		PayloadLen: total - ihl,
		TTL:        b[8],
		Fragmented: moreFragments || fragOffset != 0,
		FragOffset: fragOffset,
		DSCP:       b[1] >> 2,
	}
	return h, nil
}

func parseIPv6(b []byte) (IPHeader, error) {
	if len(b) < ipv6HeaderLen {
		return IPHeader{}, ErrTooShort
	}
	payloadLen := int(binary.BigEndian.Uint16(b[4:6]))
	total := ipv6HeaderLen + payloadLen
	if total > len(b) {
		return IPHeader{}, ErrLengthMismatch
	}

	h := IPHeader{
		Version:   IPv6,
		Src:       netip.AddrFrom16([16]byte(b[8:24])),
		Dst:       netip.AddrFrom16([16]byte(b[24:40])),
		HeaderLen: ipv6HeaderLen,
		TotalLen:  total,
		TTL:       b[7], // hop limit
		DSCP:      ((b[0] & 0x0f) << 2) | (b[1] >> 6),
	}

	next := Proto(b[6])
	off := ipv6HeaderLen
	for hops := 0; ; hops++ {
		if hops > maxExtHeaders {
			return IPHeader{}, ErrExtHeaderChain
		}
		switch next {
		case protoHopByHop, protoRouting, protoDestOpts:
			// Generic TLV extension header: next header, then length in
			// 8-octet units not counting the first 8 octets.
			if off+2 > total {
				return IPHeader{}, ErrExtHeaderChain
			}
			extLen := (int(b[off+1]) + 1) * 8
			if off+extLen > total {
				return IPHeader{}, ErrExtHeaderChain
			}
			next = Proto(b[off])
			off += extLen
		case protoFragment:
			// Fixed 8-byte fragment header.
			if off+8 > total {
				return IPHeader{}, ErrExtHeaderChain
			}
			fragField := binary.BigEndian.Uint16(b[off+2 : off+4])
			h.FragOffset = fragField & 0xfff8
			h.Fragmented = true
			next = Proto(b[off])
			off += 8
		case protoNoNextHdr:
			h.Proto = protoNoNextHdr
			h.HeaderLen = off
			h.PayloadLen = total - off
			return h, nil
		default:
			h.Proto = next
			h.HeaderLen = off
			h.PayloadLen = total - off
			return h, nil
		}
	}
}

// Payload returns the upper-layer bytes of b as described by h.
func (h IPHeader) Payload(b []byte) []byte {
	if h.HeaderLen > len(b) || h.TotalLen > len(b) || h.HeaderLen > h.TotalLen {
		return nil
	}
	return b[h.HeaderLen:h.TotalLen]
}
