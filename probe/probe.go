// Package probe measures latency and loss from the device to candidate exit
// nodes, so the app can show the user *their own* numbers before they pick a
// server.
//
// Why the phone measures, not the backend: latency depends on where the user
// is. The control plane's prober knows how far Frankfurt is from the prober,
// not from a phone in Lahore on a congested cell. Server-side numbers stay
// useful for ranking; the preview a user sees should come from their network.
//
// What gets probed:
//
//   - WireGuard servers: a UDP echo port beside the WireGuard port (by
//     convention wg_port+1, the same health port the fleet prober uses).
//     WireGuard itself is silent to unauthenticated packets by design, so a
//     healthy node and a blackholed one look identical from outside; the echo
//     port is the standard workaround. UDP, because WireGuard is UDP: the
//     probe takes the path the tunnel will.
//   - Shadowsocks servers: TCP connect time to the server port, because that
//     transport is TCP.
//
// Samples are paced rather than sent in a burst, each with its own timeout,
// and the median is reported: mobile networks are noisy, and one slow sample
// should not paint a good server red. On Android every socket goes through
// the protector, so a probe taken while the tunnel is up measures the real
// path instead of being routed into the tunnel it is measuring.
package probe

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/ameerhamza2/tunnelcore/transport/protect"
)

// Method is how a target is measured.
type Method string

const (
	// UDPEcho sends nonces to an echo port and times the replies.
	UDPEcho Method = "udp_echo"
	// TCPConnect times TCP handshakes.
	TCPConnect Method = "tcp_connect"
)

// Target is one thing to measure.
type Target struct {
	Name   string
	Addr   netip.AddrPort
	Method Method
}

// Result is the measurement for one target.
type Result struct {
	Name      string
	Addr      netip.AddrPort
	Method    Method
	Reachable bool
	// Median and P95 are over successful samples; zero when unreachable.
	Median time.Duration
	P95    time.Duration
	// Loss is the fraction of samples that got no reply, 0..1.
	Loss float64
	// Err explains an unreachable result; it never contains user data.
	Err string
}

// Config tunes a probe run. Zero values select the defaults.
type Config struct {
	// Samples per target. Default 5.
	Samples int
	// Interval between sample sends to one target. Default 50ms.
	Interval time.Duration
	// Timeout per sample. Default 1s.
	Timeout time.Duration
	// Concurrency bounds targets probed at once. Default 8: enough to probe a
	// typical server list in about one sample timeout, without opening dozens
	// of sockets at once on a phone.
	Concurrency int
	// Protect, if set, is applied to every probe socket (Android).
	Protect protect.Func
}

func (c Config) withDefaults() Config {
	if c.Samples <= 0 {
		c.Samples = 5
	}
	if c.Interval <= 0 {
		c.Interval = 50 * time.Millisecond
	}
	if c.Timeout <= 0 {
		c.Timeout = time.Second
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 8
	}
	return c
}

// ErrNoTargets is returned when there is nothing to probe.
var ErrNoTargets = errors.New("probe: no targets")

// Run measures every target and returns results sorted best first: reachable
// before unreachable, then by median RTT, then by loss. It returns early only
// if ctx is cancelled; a target that fails is reported, not returned as an
// error.
func Run(ctx context.Context, cfg Config, targets []Target) ([]Result, error) {
	if len(targets) == 0 {
		return nil, ErrNoTargets
	}
	cfg = cfg.withDefaults()

	results := make([]Result, len(targets))
	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = Result{Name: t.Name, Addr: t.Addr, Method: t.Method, Loss: 1, Err: ctx.Err().Error()}
				return
			}
			results[i] = probeOne(ctx, cfg, t)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return results, err
	}
	Sort(results)
	return results, nil
}

// Sort orders results best first.
func Sort(rs []Result) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Reachable != b.Reachable {
			return a.Reachable
		}
		if a.Median != b.Median {
			return a.Median < b.Median
		}
		return a.Loss < b.Loss
	})
}

func probeOne(ctx context.Context, cfg Config, t Target) Result {
	res := Result{Name: t.Name, Addr: t.Addr, Method: t.Method}
	if !t.Addr.IsValid() {
		res.Loss, res.Err = 1, "invalid address"
		return res
	}
	var (
		rtts []time.Duration
		err  error
	)
	switch t.Method {
	case UDPEcho:
		rtts, err = udpSamples(ctx, cfg, t.Addr)
	case TCPConnect:
		rtts, err = tcpSamples(ctx, cfg, t.Addr)
	default:
		err = fmt.Errorf("unknown method %q", t.Method)
	}
	res.Loss = 1 - float64(len(rtts))/float64(cfg.Samples)
	if len(rtts) == 0 {
		res.Loss = 1
		if err == nil {
			err = errors.New("no replies")
		}
		res.Err = err.Error()
		return res
	}
	res.Reachable = true
	res.Median, res.P95 = percentiles(rtts)
	return res
}

// percentiles returns the median and p95 (nearest rank) of rtts.
func percentiles(rtts []time.Duration) (median, p95 time.Duration) {
	s := append([]time.Duration(nil), rtts...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	median = s[(len(s)-1)/2]
	idx := (len(s)*95+99)/100 - 1
	if idx < 0 {
		idx = 0
	}
	return median, s[idx]
}

const nonceLen = 16

// udpSamples sends cfg.Samples nonces, cfg.Interval apart, on one socket and
// matches echoes by nonce. A reply that matches no nonce we sent (a stray
// datagram, a late duplicate) is ignored rather than miscounted, and a reply
// slower than cfg.Timeout counts as lost.
func udpSamples(ctx context.Context, cfg Config, addr netip.AddrPort) ([]time.Duration, error) {
	c, err := cfg.Protect.Dialer().DialContext(ctx, "udp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("udp dial: %w", err)
	}
	defer c.Close()

	var (
		mu      sync.Mutex
		pending = make(map[[nonceLen]byte]time.Time, cfg.Samples)
		rtts    []time.Duration
	)
	answered := make(chan struct{}, cfg.Samples)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 64)
		for {
			n, err := c.Read(buf)
			now := time.Now()
			if err != nil {
				return // closed by the sender side below
			}
			if n != nonceLen {
				continue
			}
			var k [nonceLen]byte
			copy(k[:], buf[:n])
			mu.Lock()
			sent, ok := pending[k]
			if ok {
				delete(pending, k)
				if rtt := now.Sub(sent); rtt <= cfg.Timeout {
					rtts = append(rtts, rtt)
				}
			}
			mu.Unlock()
			if ok {
				answered <- struct{}{}
			}
		}
	}()

	var sendErr error
	sent := 0
	for i := 0; i < cfg.Samples && ctx.Err() == nil; i++ {
		if i > 0 {
			select {
			case <-time.After(cfg.Interval):
			case <-ctx.Done():
				continue
			}
		}
		var k [nonceLen]byte
		if _, err := rand.Read(k[:]); err != nil {
			sendErr = err
			break
		}
		mu.Lock()
		pending[k] = time.Now()
		mu.Unlock()
		sent++
		if _, err := c.Write(k[:]); err != nil {
			// e.g. ICMP port unreachable surfacing on a connected socket:
			// that sample is lost, the rest still go out.
			sendErr = err
		}
	}

	// Wait for every sample to be answered or for the last one to time out,
	// whichever is first, so a healthy server is not held to the full
	// timeout.
	timeout := time.NewTimer(cfg.Timeout)
	defer timeout.Stop()
	for got := 0; got < sent; {
		select {
		case <-answered:
			got++
			continue
		case <-timeout.C:
		case <-ctx.Done():
		}
		break
	}
	_ = c.Close()
	<-readDone

	mu.Lock()
	defer mu.Unlock()
	if len(rtts) == 0 && sendErr != nil {
		return nil, sendErr
	}
	return append([]time.Duration(nil), rtts...), nil
}

// tcpSamples times cfg.Samples TCP handshakes, cfg.Interval apart.
func tcpSamples(ctx context.Context, cfg Config, addr netip.AddrPort) ([]time.Duration, error) {
	var (
		rtts    []time.Duration
		lastErr error
	)
	for i := 0; i < cfg.Samples; i++ {
		if i > 0 {
			select {
			case <-time.After(cfg.Interval):
			case <-ctx.Done():
				return rtts, ctx.Err()
			}
		}
		d := cfg.Protect.Dialer()
		d.Timeout = cfg.Timeout
		start := time.Now()
		c, err := d.DialContext(ctx, "tcp", addr.String())
		if err != nil {
			lastErr = err
			continue
		}
		rtts = append(rtts, time.Since(start))
		_ = c.Close()
	}
	if len(rtts) == 0 {
		return nil, fmt.Errorf("tcp connect: %w", lastErr)
	}
	return rtts, nil
}
