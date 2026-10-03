package packet

import (
	"net/netip"
	"testing"
)

// The fuzz targets below exist because this package is the attack surface
// between untrusted bytes and a userspace TCP/IP stack. Any application on the
// device can write arbitrary bytes into the tunnel fd. A panic here is a crash
// of the whole VPN process, which on mobile means the tunnel drops and the
// user's traffic goes out in the clear — a parser bug is a privacy bug.
//
// The invariant every target asserts is the same: Parse either returns an
// error, or returns offsets that are in bounds for the buffer it was given.

func FuzzParse(f *testing.F) {
	buf := make([]byte, 1500)
	if pkt, err := BuildUDP(buf,
		netip.MustParseAddrPort("10.0.0.2:4444"),
		netip.MustParseAddrPort("1.1.1.1:53"),
		[]byte("seed")); err == nil {
		f.Add(pkt)
	}
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2})
	f.Add([]byte{0x60, 0, 0, 0, 0, 0, 59, 64})
	f.Add([]byte{0x45})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			// On error the only guarantee is that we did not panic, and that
			// any IP header handed back is still self-consistent.
			if p.IP.Version != 0 {
				assertIPInBounds(t, p.IP, b)
			}
			return
		}

		assertIPInBounds(t, p.IP, b)

		if p.L4.HeaderLen < 0 || p.L4.HeaderLen > p.IP.PayloadLen {
			t.Fatalf("L4 HeaderLen %d outside IP payload of %d", p.L4.HeaderLen, p.IP.PayloadLen)
		}

		// Both payload accessors must stay inside b. Taking len() of the
		// result is what makes an out-of-range slice expression panic here
		// rather than three layers up in the stack.
		_ = len(p.IP.Payload(b))
		_ = len(p.Payload(b))

		// The flow must agree with the headers it was derived from.
		if p.Flow.Src.Addr() != p.IP.Src || p.Flow.Dst.Addr() != p.IP.Dst {
			t.Fatal("flow addresses disagree with IP header")
		}
		if p.Flow.Src.Port() != p.L4.SrcPort || p.Flow.Dst.Port() != p.L4.DstPort {
			t.Fatal("flow ports disagree with L4 header")
		}

		// Verification must never panic on attacker-controlled input either.
		_ = VerifyL4Checksum(p, b)
		if p.IP.Version == IPv4 {
			_ = VerifyIPv4Checksum(b)
		}
	})
}

func assertIPInBounds(t *testing.T, h IPHeader, b []byte) {
	t.Helper()
	if h.HeaderLen < 0 || h.HeaderLen > len(b) {
		t.Fatalf("HeaderLen %d out of bounds for %d-byte buffer", h.HeaderLen, len(b))
	}
	if h.TotalLen < 0 || h.TotalLen > len(b) {
		t.Fatalf("TotalLen %d out of bounds for %d-byte buffer", h.TotalLen, len(b))
	}
	if h.HeaderLen > h.TotalLen {
		t.Fatalf("HeaderLen %d exceeds TotalLen %d", h.HeaderLen, h.TotalLen)
	}
	if h.PayloadLen != h.TotalLen-h.HeaderLen {
		t.Fatalf("PayloadLen %d != TotalLen %d - HeaderLen %d", h.PayloadLen, h.TotalLen, h.HeaderLen)
	}
}

func FuzzParseDNSQuestion(f *testing.F) {
	f.Add(dnsQuery(1, "example.com", QTypeA))
	f.Add(dnsQuery(0xffff, "a.b.c.d.e.f", QTypeAAAA))
	f.Add([]byte{0, 1, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c})
	f.Add(make([]byte, dnsHeaderLen))
	f.Add(dnsQueryLabels(1, []string{"www.example", `c\om`}, QTypeA))

	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := ParseDNSQuestion(b)
		if err != nil {
			return
		}
		if len(q.Name) > maxDNSNameLen {
			t.Fatalf("returned name of %d bytes exceeds the %d-byte limit", len(q.Name), maxDNSNameLen)
		}
		// A successfully parsed name must never contain the wire-format
		// length prefixes or an upper-case byte, since the proxy uses it as a
		// map key for its allow/deny policy.
		for i := 0; i < len(q.Name); i++ {
			if c := q.Name[i]; c >= 'A' && c <= 'Z' {
				t.Fatalf("name %q contains upper-case byte at %d", q.Name, i)
			}
		}
		// Every backslash must begin a `\.` or `\\` escape. A bare one would
		// mean the escaping is ambiguous, and two wire names could share a
		// cache key or policy decision.
		for i := 0; i < len(q.Name); i++ {
			if q.Name[i] != '\\' {
				continue
			}
			if i+1 >= len(q.Name) || (q.Name[i+1] != '.' && q.Name[i+1] != '\\') {
				t.Fatalf("name %q has an unpaired backslash at %d", q.Name, i)
			}
			i++
		}
	})
}

func FuzzBuildUDPRoundTrip(f *testing.F) {
	f.Add([]byte("payload"), uint16(4444), uint16(53), true)
	f.Add([]byte{}, uint16(1), uint16(65535), false)

	f.Fuzz(func(t *testing.T, payload []byte, srcPort, dstPort uint16, v4 bool) {
		if len(payload) > 1200 {
			payload = payload[:1200]
		}
		src, dst := netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("1.1.1.1")
		if !v4 {
			src, dst = netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::1")
		}
		buf := make([]byte, 1500)
		pkt, err := BuildUDP(buf,
			netip.AddrPortFrom(src, srcPort),
			netip.AddrPortFrom(dst, dstPort),
			payload)
		if err != nil {
			return
		}

		// Anything this package builds, this package must be able to parse,
		// and the checksum it wrote must verify.
		p, err := Parse(pkt)
		if err != nil {
			t.Fatalf("Parse of self-built packet failed: %v", err)
		}
		if p.Flow.Src.Port() != srcPort || p.Flow.Dst.Port() != dstPort {
			t.Fatalf("ports round-tripped as %d -> %d, want %d -> %d",
				p.Flow.Src.Port(), p.Flow.Dst.Port(), srcPort, dstPort)
		}
		if got := p.Payload(pkt); string(got) != string(payload) {
			t.Fatalf("payload round-tripped as %d bytes, want %d", len(got), len(payload))
		}
		if err := VerifyL4Checksum(p, pkt); err != nil {
			t.Fatalf("checksum written by BuildUDP does not verify: %v", err)
		}
		if p.IP.Version == IPv4 {
			if err := VerifyIPv4Checksum(pkt); err != nil {
				t.Fatalf("IPv4 header checksum written by BuildUDP does not verify: %v", err)
			}
		}
	})
}
