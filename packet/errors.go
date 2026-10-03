package packet

import "errors"

// Parse errors. These are deliberately distinct: the engine's metrics
// distinguish "the device sent us something we don't support" (benign, count
// and drop) from "the declared length disagrees with the real length"
// (suspicious, count and drop loudly).
var (
	// ErrTooShort means the buffer is smaller than the fixed-size header it
	// is supposed to contain.
	ErrTooShort = errors.New("packet: buffer shorter than fixed header")

	// ErrBadVersion means the IP version nibble was neither 4 nor 6.
	ErrBadVersion = errors.New("packet: unrecognised IP version")

	// ErrBadHeaderLength means an IPv4 IHL was out of range, or a TCP data
	// offset was out of range.
	ErrBadHeaderLength = errors.New("packet: header length out of range")

	// ErrLengthMismatch means the length declared inside the header is
	// larger than the buffer actually provided (a truncated capture, or a
	// lying sender).
	ErrLengthMismatch = errors.New("packet: declared length exceeds buffer")

	// ErrUnsupportedProto means the L4 protocol is one this engine does not
	// terminate in the userspace stack (for example SCTP). Packet transports
	// such as WireGuard forward these untouched; stream transports drop them.
	ErrUnsupportedProto = errors.New("packet: unsupported L4 protocol")

	// ErrExtHeaderChain means an IPv6 extension-header chain was malformed or
	// exceeded maxExtHeaders.
	ErrExtHeaderChain = errors.New("packet: malformed IPv6 extension header chain")

	// ErrFragmented means the packet is a non-initial fragment. The userspace
	// stack does not reassemble on the tunnel side; the engine's MTU logic
	// exists so that this stays rare.
	ErrFragmented = errors.New("packet: non-initial fragment")

	// ErrBadChecksum is returned only by the explicit Verify* helpers, never
	// by the hot-path parsers.
	ErrBadChecksum = errors.New("packet: checksum mismatch")
)
