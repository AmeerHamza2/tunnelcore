package shadowsocks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// SOCKS5 address types, which Shadowsocks reuses verbatim for its target
// address header.
const (
	atypIPv4   byte = 1
	atypDomain byte = 3
	atypIPv6   byte = 4
)

// maxAddrLen is the longest encoded address: type + 255-byte domain + length
// byte + 2-byte port.
const maxAddrLen = 1 + 1 + 255 + 2

// Address errors.
var (
	ErrBadAddrType   = errors.New("shadowsocks: unknown address type")
	ErrAddrTooShort  = errors.New("shadowsocks: address header truncated")
	ErrDomainTooLong = errors.New("shadowsocks: domain name longer than 255 bytes")
)

// appendAddr encodes dst in SOCKS5 address form and appends it to b.
func appendAddr(b []byte, dst netip.AddrPort) []byte {
	addr := dst.Addr().Unmap()
	if addr.Is4() {
		a := addr.As4()
		b = append(b, atypIPv4)
		b = append(b, a[:]...)
	} else {
		a := addr.As16()
		b = append(b, atypIPv6)
		b = append(b, a[:]...)
	}
	return binary.BigEndian.AppendUint16(b, dst.Port())
}

// appendDomainAddr encodes a host:port destination with the host left as a
// name rather than an address.
//
// This is the form the engine prefers when it knows the name, because it
// pushes resolution to the exit node: one fewer round trip, and the local
// network never sees which host the user is reaching even in the DNS metadata.
func appendDomainAddr(b []byte, host string, port uint16) ([]byte, error) {
	if len(host) > 255 {
		return nil, fmt.Errorf("%w: %d bytes", ErrDomainTooLong, len(host))
	}
	b = append(b, atypDomain, byte(len(host)))
	b = append(b, host...)
	return binary.BigEndian.AppendUint16(b, port), nil
}

// parsedAddr is a decoded SOCKS5 address. Either Addr or Host is set.
type parsedAddr struct {
	Addr netip.AddrPort
	Host string
	Port uint16
	// Len is how many bytes of the input the address consumed.
	Len int
}

// parseAddr decodes a SOCKS5 address from the front of b.
//
// This runs on the server side of the protocol, which in this repository means
// the test server and nothing else. It is written as carefully as the client
// anyway: it is the function a real Shadowsocks server would expose to the
// internet, where the length byte is attacker-controlled and a missing bounds
// check is a remote read out of bounds.
func parseAddr(b []byte) (parsedAddr, error) {
	if len(b) < 1 {
		return parsedAddr{}, ErrAddrTooShort
	}
	switch b[0] {
	case atypIPv4:
		const n = 1 + 4 + 2
		if len(b) < n {
			return parsedAddr{}, ErrAddrTooShort
		}
		return parsedAddr{
			Addr: netip.AddrPortFrom(
				netip.AddrFrom4([4]byte(b[1:5])),
				binary.BigEndian.Uint16(b[5:7]),
			),
			Len: n,
		}, nil

	case atypIPv6:
		const n = 1 + 16 + 2
		if len(b) < n {
			return parsedAddr{}, ErrAddrTooShort
		}
		return parsedAddr{
			Addr: netip.AddrPortFrom(
				netip.AddrFrom16([16]byte(b[1:17])),
				binary.BigEndian.Uint16(b[17:19]),
			),
			Len: n,
		}, nil

	case atypDomain:
		if len(b) < 2 {
			return parsedAddr{}, ErrAddrTooShort
		}
		dlen := int(b[1])
		n := 1 + 1 + dlen + 2
		if len(b) < n {
			return parsedAddr{}, ErrAddrTooShort
		}
		return parsedAddr{
			Host: string(b[2 : 2+dlen]),
			Port: binary.BigEndian.Uint16(b[2+dlen : 4+dlen]),
			Len:  n,
		}, nil

	default:
		return parsedAddr{}, fmt.Errorf("%w: %d", ErrBadAddrType, b[0])
	}
}

// String renders the address for logs.
func (p parsedAddr) String() string {
	if p.Host != "" {
		return fmt.Sprintf("%s:%d", p.Host, p.Port)
	}
	return p.Addr.String()
}
