package packet

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ErrAddrFamilyMismatch means a builder was given a source and destination
// from different address families.
var ErrAddrFamilyMismatch = errors.New("packet: source and destination address families differ")

// BuildUDP serialises a complete IP+UDP packet into dst and returns the
// written prefix. dst must be large enough for the headers plus payload;
// otherwise ErrTooShort is returned and dst is untouched.
//
// This is how the DNS proxy returns answers: it never writes to a socket, it
// synthesises the response packet and injects it back into the tunnel, so the
// querying app sees a reply from the resolver it thinks it is talking to.
func BuildUDP(dst []byte, src, dstAddr netip.AddrPort, payload []byte) ([]byte, error) {
	if src.Addr().Is4() != dstAddr.Addr().Is4() {
		return nil, ErrAddrFamilyMismatch
	}
	if src.Addr().Is4() {
		return buildIPv4UDP(dst, src, dstAddr, payload)
	}
	return buildIPv6UDP(dst, src, dstAddr, payload)
}

func buildIPv4UDP(dst []byte, src, dstAddr netip.AddrPort, payload []byte) ([]byte, error) {
	udpLen := udpHeaderLen + len(payload)
	total := ipv4MinHeaderLen + udpLen
	if total > 0xffff {
		return nil, ErrLengthMismatch
	}
	if len(dst) < total {
		return nil, ErrTooShort
	}
	b := dst[:total]
	clear(b)

	b[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[8] = 64 // TTL
	b[9] = byte(ProtoUDP)
	s4, d4 := src.Addr().As4(), dstAddr.Addr().As4()
	copy(b[12:16], s4[:])
	copy(b[16:20], d4[:])
	binary.BigEndian.PutUint16(b[10:12], Fold(Checksum(b[:ipv4MinHeaderLen], 0)))

	u := b[ipv4MinHeaderLen:]
	writeUDP(u, src.Port(), dstAddr.Port(), payload)
	ip, _ := parseIPv4(b)
	binary.BigEndian.PutUint16(u[6:8], udpChecksum(ip, u))
	return b, nil
}

func buildIPv6UDP(dst []byte, src, dstAddr netip.AddrPort, payload []byte) ([]byte, error) {
	udpLen := udpHeaderLen + len(payload)
	total := ipv6HeaderLen + udpLen
	if udpLen > 0xffff {
		return nil, ErrLengthMismatch
	}
	if len(dst) < total {
		return nil, ErrTooShort
	}
	b := dst[:total]
	clear(b)

	b[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(b[4:6], uint16(udpLen))
	b[6] = byte(ProtoUDP)
	b[7] = 64 // hop limit
	s16, d16 := src.Addr().As16(), dstAddr.Addr().As16()
	copy(b[8:24], s16[:])
	copy(b[24:40], d16[:])

	u := b[ipv6HeaderLen:]
	writeUDP(u, src.Port(), dstAddr.Port(), payload)
	ip, _ := parseIPv6(b)
	binary.BigEndian.PutUint16(u[6:8], udpChecksum(ip, u))
	return b, nil
}

func writeUDP(u []byte, srcPort, dstPort uint16, payload []byte) {
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], dstPort)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpHeaderLen+len(payload)))
	copy(u[udpHeaderLen:], payload)
}

func udpChecksum(ip IPHeader, u []byte) uint16 {
	sum := pseudoHeaderSum(ip, ProtoUDP, len(u))
	ck := Fold(Checksum(u, sum))
	// A computed checksum of zero must be transmitted as all ones, because
	// zero is the "no checksum" sentinel. Dropping this line produces a
	// packet that one host in 65536 rejects, which is the sort of defect that
	// reaches production and is then blamed on the carrier.
	if ck == 0 {
		return 0xffff
	}
	return ck
}
