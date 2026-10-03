//go:build darwin || ios

package mobile

// headerLen is the utun protocol-family prefix on Apple platforms.
const headerLen = 4

// Apple's AF_INET6 is 30, not Linux's 10: this is the constant to check if
// IPv6 works on Android and silently fails on iOS.
const (
	afInet  = 2
	afInet6 = 30
)

// putFamilyHeader writes the 4-byte big-endian protocol family for packet p
// into dst. It reports false for a packet that is neither IPv4 nor IPv6.
func putFamilyHeader(dst, p []byte) bool {
	var af byte
	switch p[0] >> 4 {
	case 4:
		af = afInet
	case 6:
		af = afInet6
	default:
		return false
	}
	dst[0], dst[1], dst[2], dst[3] = 0, 0, 0, af
	return true
}
