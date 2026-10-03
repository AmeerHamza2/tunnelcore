// Package packet implements zero-allocation parsing and validation of the raw
// IP packets that a mobile OS hands to a VPN process through its tunnel file
// descriptor.
//
// Everything above this package (the userspace TCP/IP stack, the DNS proxy,
// the transports) assumes it is being handed well-formed, bounds-checked
// packets. This package is the only thing standing between those assumptions
// and whatever bytes an application on the device happens to write into the
// tunnel, so it is deliberately defensive:
//
//   - every field read is bounds checked against the slice it came from
//   - declared lengths are cross-checked against actual lengths, in both
//     directions (a truncated packet and an over-declared packet are different
//     bugs and get different errors)
//   - IPv6 extension-header chains are walked with an explicit hop budget so a
//     crafted chain cannot spin the parser
//   - the IP and L4 parsers do not allocate at all, which is what makes them
//     cheap enough to run on every packet and cheap enough to fuzz hard (see
//     FuzzParse). ParseDNSQuestion is the one exception: it allocates the
//     decoded name, and it only runs on packets the DNS proxy intercepts.
//
// Parsing returns offsets into the caller's buffer rather than copies. The
// caller owns the buffer and must not retain the returned headers past the
// lifetime of the bytes they describe.
//
// Measured on an Apple M2 Pro, Go 1.26:
//
//	BenchmarkParse-10              42.46 ns/op   12717 MB/s   0 allocs/op
//	BenchmarkChecksum1400-10      419.2  ns/op    3339 MB/s   0 allocs/op
//	BenchmarkParseDNSQuestion-10   85.32 ns/op                3 allocs/op
package packet
