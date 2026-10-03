package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ameerhamza2/tunnelcore/internal/ssserver"
	"github.com/ameerhamza2/tunnelcore/packet"
	"github.com/ameerhamza2/tunnelcore/transport/shadowsocks"
	"github.com/ameerhamza2/tunnelcore/transport/wireguard"
)

// Addresses as the phone sees them. None is ever assigned to a real
// interface; they exist only inside the userspace stacks.
var (
	// phoneAddr is the tunnel interface address, and exitTunAddr the
	// WireGuard exit node's address inside the tunnel.
	phoneAddr   = netip.MustParseAddr("10.9.0.2")
	exitTunAddr = netip.MustParseAddr("10.9.0.1")

	// udpEchoTarget is a UDP echo service on the WireGuard exit node.
	udpEchoTarget = netip.AddrPortFrom(exitTunAddr, 7)

	// webTarget is the "website" the phone's browser fetches over
	// Shadowsocks. It is in TEST-NET-3, so it cannot leak anywhere real: the
	// Shadowsocks exit node routes it to a local HTTP origin.
	webTarget = netip.MustParseAddrPort("203.0.113.80:80")

	// probeTarget is what the Shadowsocks client's Up dials through the proxy
	// to prove the server holds the same key; the exit node answers it with
	// a banner. TEST-NET-2, for the same reason.
	probeTarget = netip.MustParseAddrPort("198.51.100.7:7")
)

const ssMethod = shadowsocks.ChaCha20Poly1305

// wgExit is a WireGuard exit node: an ordinary wireguard.Transport in the
// listening role, plus a loop that plays the network behind it.
//
// Using the engine's own transport as the server is what lets the demo run
// without root or a kernel WireGuard module, and it is the same arrangement
// the wireguard package's end-to-end tests use. The server is configured with
// a placeholder endpoint and learns the client's real address from its first
// authenticated handshake — WireGuard roaming, which is also what lets a fresh
// client socket after a network change pick the session straight back up.
type wgExit struct {
	name     string
	p        *printer
	tr       *wireguard.Transport
	pub      wireguard.Key
	endpoint netip.AddrPort

	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once

	decrypted atomic.Uint64
}

func startWGExit(name string, clientPub wireguard.Key, p *printer) (*wgExit, error) {
	priv, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	tr, err := wireguard.New(wireguard.Config{
		Name:          "exit/" + name,
		PrivateKey:    priv,
		PeerPublicKey: clientPub,
		// A placeholder: the server never initiates, and learns where the
		// client is from the handshake.
		Endpoint:  netip.MustParseAddrPort("127.0.0.1:1"),
		Addresses: []netip.Prefix{netip.PrefixFrom(exitTunAddr, 32)},
		// Cryptokey routing: the client may only send from its own tunnel
		// address, and that is all this peer accepts.
		AllowedIPs: []netip.Prefix{netip.PrefixFrom(phoneAddr, 32)},
	})
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	e := &wgExit{name: name, p: p, tr: tr, pub: priv.PublicKey(), cancel: cancel}

	// Up blocks until the first client handshake lands, so it runs in the
	// background for the life of the node; the packet loop starts once it
	// returns, because the transport refuses traffic before then.
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if err := tr.Up(ctx); err != nil {
			return
		}
		e.serve()
	}()

	// The device binds port 0; the chosen port is read back rather than
	// reserved in advance, which would race any other process for it.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if port := tr.ListenPort(); port != 0 {
			e.endpoint = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
			return e, nil
		}
		if time.Now().After(deadline) {
			e.Close()
			return nil, errors.New("wireguard exit node never bound a UDP port")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// serve reads decrypted IP packets from the tunnel and answers UDP ones, the
// way a host behind the exit node would.
func (e *wgExit) serve() {
	buf := make([]byte, 2048)
	out := make([]byte, 2048)
	for {
		n, err := e.tr.ReadPacket(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]
		pp, err := packet.Parse(pkt)
		if err != nil || pp.Flow.Proto != packet.ProtoUDP {
			e.p.debug(tagExit, "%s ◂ decrypted %s (not answered)", e.name, describePacket(pkt))
			continue
		}
		e.decrypted.Add(1)
		payload := pp.Payload(pkt)

		// Verifying both checksums on the decrypted packet is the visible
		// proof that the bytes the phone wrote are the bytes that came out
		// the other end, offsets and all.
		ck := "checksums ok"
		if packet.VerifyIPv4Checksum(pkt) != nil || packet.VerifyL4Checksum(pp, pkt) != nil {
			ck = e.p.bad("CHECKSUM MISMATCH")
		}
		e.p.event(tagExit, "%s ◂ decrypted udp %s → %s %s  (%d B, %s)",
			e.name, pp.Flow.Src, pp.Flow.Dst, quote(payload), n, ck)

		reply := append([]byte(nil), payload...)
		if bytes.HasPrefix(reply, []byte("ping")) {
			copy(reply, "pong")
		}
		// The reply is sourced from the address the phone sent to, so it
		// falls inside the client's AllowedIPs; anything else would be
		// dropped by cryptokey routing on the way back.
		rp, err := packet.BuildUDP(out, pp.Flow.Dst, pp.Flow.Src, reply)
		if err != nil {
			continue
		}
		if err := e.tr.WritePacket(rp); err != nil {
			return
		}
	}
}

// Close kills the node, abruptly: the UDP socket goes away and nothing is
// sent to the client, which is how a crashed or firewalled server looks.
func (e *wgExit) Close() {
	e.closeOnce.Do(func() {
		e.cancel()
		_ = e.tr.Close()
		e.wg.Wait()
	})
}

// ssExit is a Shadowsocks exit node with a small HTTP origin behind it.
type ssExit struct {
	name     string
	p        *printer
	srv      *ssserver.Server
	password string

	origin   *http.Server
	originLn net.Listener
	wg       sync.WaitGroup

	streams atomic.Uint64
}

func startSSExit(name string, p *printer) (*ssExit, error) {
	// Provisioned as the control plane does it: 32 bytes of CSPRNG output,
	// base64. See shadowsocks.Config.Password for why never a human string.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	e := &ssExit{name: name, p: p, password: base64.StdEncoding.EncodeToString(raw[:])}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	e.originLn = ln
	e.origin = &http.Server{Handler: http.HandlerFunc(e.serveHTTP), ReadHeaderTimeout: 5 * time.Second}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		_ = e.origin.Serve(ln)
	}()

	srv, err := ssserver.Listen(ssserver.Config{
		Addr:     "127.0.0.1:0",
		Method:   ssMethod,
		Password: e.password,
		Handler:  e.handle,
		OnError: func(remote net.Addr, err error) {
			e.p.event(tagExit, "%s ✗ rejected stream from %s: %v", e.name, remote, err)
		},
	})
	if err != nil {
		e.Close()
		return nil, err
	}
	e.srv = srv
	return e, nil
}

func (e *ssExit) Addr() netip.AddrPort { return e.srv.Addr() }

// handle serves one decrypted stream: the probe gets a banner, everything
// else is forwarded to the origin.
func (e *ssExit) handle(target ssserver.Target, c net.Conn) {
	if target.Addr == probeTarget {
		// Only a client holding the same key could have produced a request
		// that decrypted, and only such a client can decrypt this reply —
		// which is why the client's Up treats an answered probe as proof of
		// credentials, not just reachability.
		e.p.debug(tagExit, "%s ◂ probe to %s decrypted; answering", e.name, target)
		_, _ = c.Write([]byte("tunnelcore-probe-ok\n"))
		return
	}

	e.streams.Add(1)
	e.p.event(tagExit, "%s ◂ decrypted stream: CONNECT %s → forwarding to origin", e.name, target)
	var d net.Dialer
	up, err := d.Dial("tcp", e.originLn.Addr().String())
	if err != nil {
		e.p.event(tagExit, "%s ✗ origin unreachable: %v", e.name, err)
		return
	}
	if !e.srv.Track(up) {
		return
	}
	defer e.srv.Untrack(up)
	defer up.Close()
	ssserver.Splice(c, up)
}

// serveHTTP is the origin: "/" says hello, "/blob?size=N" returns N bytes of
// a fixed pattern that the client verifies, which is what turns "some bytes
// arrived" into "the stream arrived intact".
func (e *ssExit) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "hello from the origin behind shadowsocks/%s (you asked for Host: %s)\n", e.name, r.Host)
	case "/blob":
		size, err := strconv.Atoi(r.URL.Query().Get("size"))
		if err != nil || size < 0 || size > 16<<20 {
			http.Error(w, "size must be 0..16MiB", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(blobPattern(size))
	default:
		http.NotFound(w, r)
	}
}

// blobPattern is the deterministic payload /blob serves.
func blobPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

// Close kills the node and its origin, tearing live streams down.
func (e *ssExit) Close() {
	if e.srv != nil {
		_ = e.srv.Close()
	}
	if e.origin != nil {
		_ = e.origin.Close()
	}
	e.wg.Wait()
}

// blackhole is a UDP endpoint that reads and discards everything.
//
// It models the failure that matters most in restrictive networks: not a
// refusal but silence, which is what DPI that has fingerprinted WireGuard
// does to the handshake. Reading rather than leaving the port closed matters —
// a closed port can provoke ICMP unreachables, which is a different and much
// easier failure to detect.
type blackhole struct {
	conn      *net.UDPConn
	swallowed atomic.Uint64
	done      chan struct{}
}

func startBlackhole() (*blackhole, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	b := &blackhole{conn: c, done: make(chan struct{})}
	go func() {
		defer close(b.done)
		buf := make([]byte, 2048)
		for {
			if _, _, err := c.ReadFromUDP(buf); err != nil {
				return
			}
			b.swallowed.Add(1)
		}
	}()
	return b, nil
}

func (b *blackhole) Addr() netip.AddrPort { return b.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (b *blackhole) Close() {
	_ = b.conn.Close()
	<-b.done
}

// deadTCPAddr returns a loopback TCP address with nothing listening on it,
// standing in for a decommissioned server.
//
// The port is briefly bound and released. Another process could in principle
// claim it in between, but the cost of that is only that this one candidate
// stops being refused, so the reuse race does not matter here the way it
// would for a port something must actually listen on.
func deadTCPAddr() (netip.AddrPort, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap := ln.Addr().(*net.TCPAddr).AddrPort()
	return ap, ln.Close()
}
