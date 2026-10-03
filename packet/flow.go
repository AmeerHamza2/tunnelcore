package packet

import (
	"net/netip"
	"strings"
)

// Flow is the 5-tuple that identifies a connection as seen on the tunnel
// interface. It is comparable, so it works directly as a map key in the
// stack's flow table without hashing or allocating.
type Flow struct {
	Proto Proto
	Src   netip.AddrPort
	Dst   netip.AddrPort
}

func (f Flow) String() string {
	var sb strings.Builder
	sb.WriteString(f.Proto.String())
	sb.WriteByte(' ')
	sb.WriteString(f.Src.String())
	sb.WriteString(" -> ")
	sb.WriteString(f.Dst.String())
	return sb.String()
}

// Reverse returns the flow for traffic in the opposite direction.
func (f Flow) Reverse() Flow {
	return Flow{Proto: f.Proto, Src: f.Dst, Dst: f.Src}
}

// IsDNS reports whether this flow is a plaintext DNS query by port. The DNS
// proxy uses this to decide what to intercept; it is intentionally port-based
// because that is all the information available before the first byte of
// payload arrives.
func (f Flow) IsDNS() bool {
	return f.Dst.Port() == 53 && (f.Proto == ProtoUDP || f.Proto == ProtoTCP)
}

// Parsed is the full result of parsing one packet off the tunnel.
type Parsed struct {
	IP   IPHeader
	L4   L4Header
	Flow Flow
}

// Parse parses a complete IP packet into its flow and headers. It is the entry
// point used on the tunnel read path.
//
// Non-initial fragments return ErrFragmented: they carry no L4 header, so
// there is nothing to key a flow on. Unsupported upper-layer protocols return
// ErrUnsupportedProto with the IP header still populated, so a packet
// transport can forward them even though a stream transport cannot.
func Parse(b []byte) (Parsed, error) {
	ip, err := ParseIP(b)
	if err != nil {
		return Parsed{}, err
	}
	if ip.Fragmented && ip.FragOffset != 0 {
		return Parsed{IP: ip}, ErrFragmented
	}
	payload := ip.Payload(b)
	if payload == nil {
		return Parsed{IP: ip}, ErrLengthMismatch
	}
	l4, err := ParseL4(ip.Proto, payload)
	if err != nil {
		return Parsed{IP: ip}, err
	}
	return Parsed{
		IP: ip,
		L4: l4,
		Flow: Flow{
			Proto: ip.Proto,
			Src:   netip.AddrPortFrom(ip.Src, l4.SrcPort),
			Dst:   netip.AddrPortFrom(ip.Dst, l4.DstPort),
		},
	}, nil
}

// Payload returns the L4 payload for a parsed packet.
func (p Parsed) Payload(b []byte) []byte {
	ipPayload := p.IP.Payload(b)
	if ipPayload == nil {
		return nil
	}
	return p.L4.Payload(ipPayload)
}
