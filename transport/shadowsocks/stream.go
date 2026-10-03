package shadowsocks

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// maxChunkPayload is the largest payload one AEAD chunk may carry.
//
// The length field is two bytes, but the top two bits must be zero: the spec
// caps a chunk at 0x3FFF so that an implementation can size a fixed receive
// buffer and so that a corrupted length cannot ask it to allocate 64 KiB. A
// length with the high bits set is treated as a protocol violation below
// rather than masked off, because masking would let an attacker-controlled
// length through in a modified form.
const maxChunkPayload = 0x3fff

// Stream errors.
var (
	ErrChunkTooLarge = errors.New("shadowsocks: chunk length exceeds 0x3fff")
	ErrZeroChunk     = errors.New("shadowsocks: zero-length chunk")
	ErrAuthFailed    = errors.New("shadowsocks: AEAD authentication failed")
)

// streamConn wraps a net.Conn with Shadowsocks AEAD framing in both
// directions. It satisfies net.Conn, including CloseWrite, so the userspace
// stack's half-close handling works through it.
type streamConn struct {
	net.Conn
	cipher *Cipher

	writeMu   sync.Mutex
	writeAEAD cipher.AEAD
	writeNnc  nonce
	// pendingSalt is prepended to the first chunk and then dropped; see
	// initWrite for why the salt is not written on its own.
	pendingSalt []byte
	wroteSalt   bool
	writeBuf    []byte
	// writeErr is sticky: once an underlying Write has failed, the stream is
	// broken for good. The nonces for that chunk have already advanced and
	// an unknown prefix of it may be on the wire, so any later chunk would
	// either reuse framing the peer never saw or fail authentication there;
	// failing locally and predictably is the only honest option.
	writeErr error

	// pendingHeader is the target-address header DialTCP queued with
	// setPendingHeader, not yet written. See setPendingHeader. It is
	// guarded by writeMu; headerPending mirrors "pendingHeader != nil" so
	// Read can check it without taking writeMu.
	pendingHeader []byte
	headerPending atomic.Bool
	// headerTimer flushes pendingHeader alone if the application does not
	// write in time. It is set once before the conn is handed out and only
	// read afterwards, so it needs no lock of its own.
	headerTimer *time.Timer

	readMu   sync.Mutex
	readAEAD cipher.AEAD
	readNnc  nonce
	readSalt bool
	// leftover holds decrypted bytes a Read call could not fit in the
	// caller's buffer.
	leftover []byte
	readBuf  []byte
}

func newStreamConn(c net.Conn, ciph *Cipher) *streamConn {
	return &streamConn{
		Conn:   c,
		cipher: ciph,
		// One chunk's worth of ciphertext: length block, payload, two tags.
		readBuf:  make([]byte, 2+ciph.Overhead()+maxChunkPayload+ciph.Overhead()),
		writeBuf: make([]byte, ciph.SaltSize()+2+ciph.Overhead()+maxChunkPayload+ciph.Overhead()),
	}
}

// initWrite generates the salt and derives the sending AEAD. The salt is
// written as part of the first chunk rather than on its own, so that the
// connection's first TCP segment is indistinguishable in size from any other
// — a lone 32-byte write followed by a larger one is itself a signature.
func (s *streamConn) initWrite() error {
	salt := make([]byte, s.cipher.SaltSize())
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("shadowsocks: generating salt: %w", err)
	}
	aead, err := s.cipher.AEAD(salt)
	if err != nil {
		return err
	}
	s.writeAEAD = aead
	s.writeNnc = newNonce(aead.NonceSize())
	copy(s.writeBuf, salt)
	s.wroteSalt = false
	s.pendingSalt = salt
	return nil
}

// headerCoalesceDelay is how long a queued target-address header waits for
// the application's first write before it is sent on its own.
//
// Long enough that the userspace stack's first segment — which for TLS, HTTP
// and most client-speaks-first protocols is already queued when the dial
// returns — reliably lands in the window; short enough that a
// server-speaks-first protocol that never writes before reading (SMTP, SSH
// banners) is not visibly delayed. It is the same order of magnitude
// shadowsocks-rust and outline-ss-client use.
const headerCoalesceDelay = 10 * time.Millisecond

// setPendingHeader queues the target-address header to be sent in the same
// chunk as the application's first write, instead of as a chunk of its own.
//
// A header-only first chunk has a length fixed by the address type alone
// (salt + 2 + tag + 7 + tag for IPv4), which makes every proxied connection's
// first segment the same size — a trivially matched signature for a DPI box,
// and the one the reference servers' probing-resistance work was aimed at.
// Coalescing makes the first segment as variable as the application's data.
//
// If nothing is written within headerCoalesceDelay, or Read or CloseWrite is
// called first, the header is flushed alone: the exit node cannot connect to
// the destination until it has the header, so a protocol where the server
// speaks first would otherwise deadlock.
//
// It must be called before the conn is shared with another goroutine.
func (s *streamConn) setPendingHeader(h []byte) {
	s.setPendingHeaderAfter(h, headerCoalesceDelay)
}

// setPendingHeaderAfter is setPendingHeader with the delay as a parameter,
// so tests can make the timer irrelevant instead of racing it.
func (s *streamConn) setPendingHeaderAfter(h []byte, delay time.Duration) {
	// Under writeMu because the timer's callback takes it and reads
	// headerTimer: a delay short enough to fire before AfterFunc returns
	// would otherwise race the assignment.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.pendingHeader = append([]byte(nil), h...)
	s.headerPending.Store(true)
	s.headerTimer = time.AfterFunc(delay, func() { _ = s.flushHeader() })
}

// flushHeader writes a still-pending header as a chunk of its own. A write
// error is recorded as the sticky writeErr, which is how an error from the
// timer path reaches the application: on its next Write.
func (s *streamConn) flushHeader() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.flushHeaderLocked()
}

func (s *streamConn) flushHeaderLocked() error {
	if s.pendingHeader == nil {
		// Already sent, by a Write or by the timer. A failure there is
		// sticky in writeErr and reported by the next Write; it is not
		// this caller's error.
		return nil
	}
	h := s.takeHeaderLocked()
	_, err := s.writeLocked(h)
	return err
}

// takeHeaderLocked removes and returns the pending header. writeMu must be
// held, and whoever takes the header must write it before releasing writeMu:
// that is the invariant Read relies on when it finds writeMu busy.
func (s *streamConn) takeHeaderLocked() []byte {
	h := s.pendingHeader
	s.pendingHeader = nil
	s.headerPending.Store(false)
	if s.headerTimer != nil {
		s.headerTimer.Stop()
	}
	return h
}

// Write seals p into one or more chunks and writes them.
func (s *streamConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if s.pendingHeader != nil {
		h := s.takeHeaderLocked()
		if len(p) == 0 {
			_, err := s.writeLocked(h)
			return 0, err
		}
		// One buffer so writeLocked seals header and payload into the same
		// chunk (or, for a payload near maxChunkPayload, the header and the
		// payload's head into the first one).
		buf := make([]byte, 0, len(h)+len(p))
		buf = append(append(buf, h...), p...)
		n, err := s.writeLocked(buf)
		// Report progress in terms of p only; the header is ours.
		n -= len(h)
		if n < 0 {
			n = 0
		}
		return n, err
	}
	return s.writeLocked(p)
}

func (s *streamConn) writeLocked(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	if s.writeAEAD == nil {
		if err := s.initWrite(); err != nil {
			return 0, err
		}
	}

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunkPayload {
			chunk = chunk[:maxChunkPayload]
		}

		out := s.writeBuf[:0]
		if !s.wroteSalt {
			out = append(out, s.pendingSalt...)
		}

		// Length block: two big-endian bytes, sealed with its own nonce.
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(chunk)))
		out = s.writeAEAD.Seal(out, s.writeNnc, lenBuf[:], nil)
		s.writeNnc.increment()

		// Payload block.
		out = s.writeAEAD.Seal(out, s.writeNnc, chunk, nil)
		s.writeNnc.increment()

		if _, err := s.Conn.Write(out); err != nil {
			// See writeErr: the nonces above are spent whether or not any
			// byte reached the peer, so there is no retrying this stream.
			s.writeErr = err
			return written, err
		}
		s.wroteSalt = true
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Read decrypts one chunk at a time into p.
func (s *streamConn) Read(p []byte) (int, error) {
	// A read before any write means the application is waiting for the
	// server to speak first, which it cannot do until the exit node has the
	// header, so flush it now.
	//
	// TryLock rather than Lock, because Read must never wait on the write
	// side: a Write blocked on a full send buffer while the peer waits for
	// us to read would otherwise deadlock both directions. If writeMu is
	// busy, its holder is a Write or the timer flush, and either one writes
	// the pending header before releasing it (see takeHeaderLocked), so
	// there is nothing left for Read to do.
	if s.headerPending.Load() && s.writeMu.TryLock() {
		err := s.flushHeaderLocked()
		s.writeMu.Unlock()
		if err != nil {
			return 0, err
		}
	}

	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.leftover) > 0 {
		n := copy(p, s.leftover)
		s.leftover = s.leftover[n:]
		return n, nil
	}

	if !s.readSalt {
		salt := make([]byte, s.cipher.SaltSize())
		if _, err := io.ReadFull(s.Conn, salt); err != nil {
			return 0, err
		}
		aead, err := s.cipher.AEAD(salt)
		if err != nil {
			return 0, err
		}
		s.readAEAD = aead
		s.readNnc = newNonce(aead.NonceSize())
		s.readSalt = true
	}

	plain, err := s.readChunk()
	if err != nil {
		return 0, err
	}
	n := copy(p, plain)
	if n < len(plain) {
		// Keep the remainder; a short caller buffer must not lose data.
		s.leftover = append(s.leftover[:0], plain[n:]...)
	}
	return n, nil
}

func (s *streamConn) readChunk() ([]byte, error) {
	overhead := s.readAEAD.Overhead()

	// Length block.
	lenCipher := s.readBuf[:2+overhead]
	if _, err := io.ReadFull(s.Conn, lenCipher); err != nil {
		return nil, err
	}
	lenPlain, err := s.readAEAD.Open(lenCipher[:0], s.readNnc, lenCipher, nil)
	if err != nil {
		// Do not wrap the AEAD error. cipher.AEAD returns a deliberately
		// opaque "message authentication failed" so that nothing about *why*
		// it failed can be observed; adding detail here would hand an
		// attacker exactly the oracle the AEAD is designed to deny.
		return nil, ErrAuthFailed
	}
	s.readNnc.increment()

	size := int(binary.BigEndian.Uint16(lenPlain))
	if size > maxChunkPayload {
		return nil, fmt.Errorf("%w: %d", ErrChunkTooLarge, size)
	}
	if size == 0 {
		return nil, ErrZeroChunk
	}

	// Payload block.
	payCipher := s.readBuf[:size+overhead]
	if _, err := io.ReadFull(s.Conn, payCipher); err != nil {
		return nil, err
	}
	plain, err := s.readAEAD.Open(payCipher[:0], s.readNnc, payCipher, nil)
	if err != nil {
		return nil, ErrAuthFailed
	}
	s.readNnc.increment()
	return plain, nil
}

// CloseWrite propagates a half-close to the underlying TCP connection.
//
// The userspace stack requires this (see transport.StreamDialer.DialTCP): an
// HTTP/1.0 request ends by closing the write half, and a transport that cannot
// express that truncates the response.
func (s *streamConn) CloseWrite() error {
	// A connection half-closed before any write still has to tell the exit
	// node where it was going, or the server sees EOF in the middle of what
	// should have been the header. Unlike Read, this waits for writeMu,
	// unconditionally: the half-close must come after any write in progress.
	//
	// It used to take writeMu only when headerPending was set. But Read (or
	// the coalescing timer) clears headerPending when it *takes* the header,
	// before writing it, so a CloseWrite racing a server-speaks-first Read saw
	// nothing pending and shut the socket's write half down under the header
	// write: the header failed with EPIPE and the exit node saw EOF before
	// learning the destination. Taking writeMu orders the shutdown after it.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.flushHeaderLocked(); err != nil {
		return err
	}
	if hc, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

// Close stops a pending header flush and closes the underlying connection.
//
// It deliberately does not take writeMu: Close is how a caller unblocks a
// Write stuck on a full send buffer, so waiting for that Write would hang.
// The header timer is only stopped, not raced with — if it has already
// fired, its write fails on the closed conn and nobody is left to see it.
func (s *streamConn) Close() error {
	if s.headerTimer != nil {
		s.headerTimer.Stop()
	}
	return s.Conn.Close()
}

// SetDeadline, SetReadDeadline, SetWriteDeadline, LocalAddr and RemoteAddr
// are inherited from the embedded net.Conn.
var _ net.Conn = (*streamConn)(nil)
