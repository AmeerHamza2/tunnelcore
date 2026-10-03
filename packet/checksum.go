package packet

import "encoding/binary"

// Checksum computes the RFC 1071 one's-complement sum over b, folded to 16
// bits, seeded with initial. Passing the running value of a previous call as
// initial lets the caller checksum a pseudo-header and a payload separately
// without copying them into one buffer.
//
// The returned value is the *sum*, not the complement. Call Fold to get the
// value that goes on the wire.
func Checksum(b []byte, initial uint32) uint32 {
	sum := initial
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		// Odd trailing byte is treated as the high byte of a padded word.
		sum += uint32(b[0]) << 8
	}
	return sum
}

// Fold reduces a one's-complement sum to the 16-bit value carried on the wire.
func Fold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// VerifyIPv4Checksum checks the header checksum of an IPv4 packet.
//
// This is not called on the tunnel read path. The OS has already validated
// what it handed us, and re-checksumming every packet costs throughput for no
// security benefit. It exists for the harness CLI, for tests, and for
// debugging a transport that is suspected of corrupting packets in flight —
// which is exactly the kind of bug that otherwise presents as "the VPN works
// but some sites hang".
func VerifyIPv4Checksum(b []byte) error {
	h, err := parseIPv4(b)
	if err != nil {
		return err
	}
	if Fold(Checksum(b[:h.HeaderLen], 0)) != 0 {
		return ErrBadChecksum
	}
	return nil
}

// pseudoHeaderSum computes the TCP/UDP pseudo-header contribution for a
// parsed packet, for either address family.
func pseudoHeaderSum(ip IPHeader, proto Proto, l4Len int) uint32 {
	var sum uint32
	src, dst := ip.Src.As16(), ip.Dst.As16()
	if ip.Version == IPv4 {
		s4, d4 := ip.Src.As4(), ip.Dst.As4()
		sum = Checksum(s4[:], 0)
		sum = Checksum(d4[:], sum)
	} else {
		sum = Checksum(src[:], 0)
		sum = Checksum(dst[:], sum)
	}
	sum += uint32(proto)
	sum += uint32(uint16(l4Len))
	return sum
}

// VerifyL4Checksum checks the TCP or UDP checksum of a parsed packet.
//
// A UDP checksum of zero means "not computed" in IPv4 and is accepted; the
// same value is illegal in IPv6 and is rejected, which is a real difference
// that a naive implementation gets wrong in the direction of accepting
// corrupt packets.
func VerifyL4Checksum(p Parsed, b []byte) error {
	l4 := p.IP.Payload(b)
	if l4 == nil {
		return ErrLengthMismatch
	}
	l4Len := p.IP.PayloadLen
	if p.L4.Proto == ProtoUDP {
		if p.L4.DeclaredLen > 0 && p.L4.DeclaredLen <= len(l4) {
			l4Len = p.L4.DeclaredLen
		}
		stored := binary.BigEndian.Uint16(l4[6:8])
		if stored == 0 {
			if p.IP.Version == IPv6 {
				return ErrBadChecksum
			}
			return nil
		}
	}
	if l4Len > len(l4) {
		return ErrLengthMismatch
	}
	sum := pseudoHeaderSum(p.IP, p.L4.Proto, l4Len)
	if Fold(Checksum(l4[:l4Len], sum)) != 0 {
		return ErrBadChecksum
	}
	return nil
}
