//go:build !darwin && !ios && !windows

package mobile

// headerLen is zero on Android and Linux: the tun fd carries bare IP packets.
const headerLen = 0

func putFamilyHeader(dst, p []byte) bool { return true }
