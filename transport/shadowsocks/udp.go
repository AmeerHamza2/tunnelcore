package shadowsocks

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport"
)

// Shadowsocks UDP wire format, per datagram:
//
//	[salt][AEAD-sealed( [SOCKS5 target address][payload] )]
//
// Each datagram carries its own fresh salt and is sealed with a zero nonce
// under the subkey derived from that salt. That is not nonce reuse: the subkey
// is unique per datagram because the salt is, so each (key, nonce) pair is
// used exactly once. The cost is 32 or 48 bytes of overhead per datagram and
// an HKDF per datagram in each direction, which is why UDP over Shadowsocks is
// measurably more expensive than TCP and why the engine prefers WireGuard when
// a network allows it.
//
// There is no sequence number and no replay window in the protocol. An
// attacker who records a datagram can replay it, and the server will accept
// it. This is a known weakness of the AEAD-2018 UDP format — it is one of the
// problems the 2022 edition exists to fix — and it is recorded as a finding in
// docs/DUE_DILIGENCE_GAPS.md rather than silently tolerated here.

const (
	// maxUDPPayload bounds a single datagram's plaintext. 64 KiB is the
	// theoretical IP limit; anything near it fragments and is lost on a
	// mobile path, so this is sized for the largest datagram that fits a
	// jumbo-free path plus the protocol's own header.
	maxUDPPayload = 64 << 10

	// udpReadTimeout bounds a blocked read so a session whose server has gone
	// away does not pin a goroutine forever.
	udpReadTimeout = 60 * time.Second

	// maxUDPRecvPayload bounds a datagram's payload on the receive side.
	//
	// It is deliberately far smaller than maxUDPPayload. Every session holds
	// its receive buffer for as long as a reader is blocked on it, which for
	// a proxied flow is its whole life, and the userspace stack keeps up to a
	// thousand flows; at 64 KiB each (plus 64 KiB of send buffer) that was
	// 130 MiB of buffers — several times an iOS network extension's entire
	// memory limit — and 130 KiB of garbage per DNS lookup, since dnsproxy
	// opens a session per query. Nothing downstream can use a larger
	// datagram anyway: the tunnel MTU caps what reaches an app, and dnsproxy
	// treats a reply of 4 KiB or more as truncated and retries over TCP. 16
	// KiB still covers jumbo frames and large EDNS answers.
	maxUDPRecvPayload = 16 << 10

	// maxSaltSize and maxTagSize are the largest salt and AEAD tag of any
	// supported method, so one pooled buffer size fits every cipher.
	maxSaltSize = 32
	maxTagSize  = 16
)

// udpSendBufs pools send buffers across sessions. A send never blocks for
// long (it is one sendto), so a handful of buffers serve every session, where
// a buffer per session pinned 64 KiB for each idle flow.
var udpSendBufs = sync.Pool{New: func() any {
	b := make([]byte, maxSaltSize+maxAddrLen+maxUDPPayload+maxTagSize)
	return &b
}}

// UDP errors.
var (
	ErrUDPTooLarge   = errors.New("shadowsocks: UDP payload exceeds the maximum datagram size")
	ErrUDPShort      = errors.New("shadowsocks: UDP datagram shorter than salt plus tag")
	ErrUDPBadAddr    = errors.New("shadowsocks: UDP datagram carries an unparseable address")
	ErrUDPDomainAddr = errors.New("shadowsocks: UDP datagram carries a domain address, which has no numeric form to return")
)

// DialUDP opens a Shadowsocks UDP association.
//
// dst is recorded but not connected to: Shadowsocks UDP carries the target
// address in every datagram, so one association can reach many destinations.
// The engine still creates one per tunnel flow, because that is the unit the
// userspace stack tracks and the unit the idle timeout applies to.
func (t *Transport) DialUDP(ctx context.Context, dst netip.AddrPort) (transport.UDPSession, error) {
	t.mu.Lock()
	closed, up := t.closed, t.up
	t.mu.Unlock()
	if closed {
		return nil, transport.ErrClosed
	}
	if !up {
		return nil, transport.ErrNotReady
	}

	// The UDP association goes straight to the server: obfuscation plugins in
	// this package wrap stream connections only. A network that blocks
	// Shadowsocks UDP but not TCP therefore defeats UDP proxying, and the
	// engine's answer is to fail over rather than to pretend otherwise — see
	// the UDP handling in package netstack, which drops a flow it cannot
	// carry instead of letting it leave the tunnel.
	d := t.cfg.Protect.Dialer()
	if dl, ok := ctx.Deadline(); ok {
		d.Deadline = dl
	}
	c, err := d.DialContext(ctx, "udp", t.cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("shadowsocks: dialing UDP to %s: %w", t.Name(), err)
	}
	udp, ok := c.(*net.UDPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("shadowsocks: expected a *net.UDPConn, got %T", c)
	}

	return &udpSession{
		conn:   udp,
		cipher: t.cipher,
		defDst: dst,
	}, nil
}

type udpSession struct {
	conn   *net.UDPConn
	cipher *Cipher
	defDst netip.AddrPort

	sendMu sync.Mutex

	recvMu sync.Mutex
	// recvBuf is allocated on the first ReadFrom: a session that only sends
	// never needs one. One byte longer than the largest datagram accepted,
	// so a datagram that filled it is known to have been truncated.
	recvBuf []byte

	// oversize counts received datagrams dropped for exceeding
	// maxUDPRecvPayload.
	oversize atomic.Uint64

	closeOnce sync.Once
}

// WriteTo seals b for dst and sends it to the exit node.
func (s *udpSession) WriteTo(b []byte, dst netip.AddrPort) (int, error) {
	if len(b) > maxUDPPayload {
		return 0, fmt.Errorf("%w: %d bytes", ErrUDPTooLarge, len(b))
	}
	if !dst.IsValid() {
		dst = s.defDst
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	bp := udpSendBufs.Get().(*[]byte)
	defer udpSendBufs.Put(bp)
	sendBuf := *bp

	saltSize := s.cipher.SaltSize()
	salt := sendBuf[:saltSize]
	if _, err := rand.Read(salt); err != nil {
		return 0, fmt.Errorf("shadowsocks: generating UDP salt: %w", err)
	}
	aead, err := s.cipher.AEAD(salt)
	if err != nil {
		return 0, err
	}

	// Plaintext is the target address followed by the payload. It is built in
	// a scratch region of the same buffer, after the space the ciphertext
	// will occupy, so a datagram costs no allocation.
	plain := append(sendBuf[saltSize:saltSize], 0)[:0]
	plain = appendAddr(plain, dst)
	plain = append(plain, b...)

	// Nonce is all zeroes: unique because the subkey is, per the note at the
	// top of this file.
	zeroNonce := make([]byte, aead.NonceSize())
	out := aead.Seal(sendBuf[:saltSize], zeroNonce, plain, nil)

	if _, err := s.conn.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ReadFrom receives one datagram, opens it, and reports the address the exit
// node says it came from.
func (s *udpSession) ReadFrom(b []byte) (int, netip.AddrPort, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()

	if s.recvBuf == nil {
		s.recvBuf = make([]byte, s.cipher.SaltSize()+maxAddrLen+maxUDPRecvPayload+s.cipher.Overhead()+1)
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(udpReadTimeout)); err != nil {
		return 0, netip.AddrPort{}, err
	}
	var n int
	for {
		var err error
		n, err = s.conn.Read(s.recvBuf)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		if n < len(s.recvBuf) {
			break
		}
		// Truncated by the kernel: its tag is gone, so it cannot be
		// authenticated, let alone delivered. Drop it and keep reading, as
		// a router drops an over-MTU datagram; failing the read would end
		// the whole flow over one oversized packet.
		s.oversize.Add(1)
	}

	saltSize := s.cipher.SaltSize()
	if n < saltSize+s.cipher.Overhead() {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: %d bytes", ErrUDPShort, n)
	}

	salt := s.recvBuf[:saltSize]
	aead, err := s.cipher.AEAD(salt)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	zeroNonce := make([]byte, aead.NonceSize())
	plain, err := aead.Open(s.recvBuf[saltSize:saltSize], zeroNonce, s.recvBuf[saltSize:n], nil)
	if err != nil {
		// Opaque on purpose; see the comment in streamConn.readChunk.
		return 0, netip.AddrPort{}, ErrAuthFailed
	}

	addr, err := parseAddr(plain)
	if err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("%w: %w", ErrUDPBadAddr, err)
	}
	if addr.Host != "" {
		// A conforming server echoes the numeric address it actually used.
		// A domain here cannot be turned into the netip.AddrPort the
		// interface requires without a resolution that would itself leak, so
		// the datagram is rejected rather than resolved.
		return 0, netip.AddrPort{}, ErrUDPDomainAddr
	}

	payload := plain[addr.Len:]
	return copy(b, payload), addr.Addr, nil
}

func (s *udpSession) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.conn.Close() })
	return err
}

var _ transport.UDPSession = (*udpSession)(nil)
