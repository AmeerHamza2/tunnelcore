//go:build soak

package dnsproxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ameerhamza2/tunnelcore/packet"
)

// nameIP is the deterministic address the soak upstream answers for name i,
// so a reply served for the wrong name (a cache mix-up) is detectable.
func nameIP(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

// TestSoakDNSProxyConcurrentQueries sends 10,000 queries from 64 concurrent
// clients over a name space larger than the cache, through an upstream that
// mixes in forged replies, SERVFAILs, truncation (TCP fallback) and large
// answers. Every reply must answer its own question with the right address;
// the cache must stay within its entry and byte bounds; and no goroutine or
// upstream session may outlive the run.
func TestSoakDNSProxyConcurrentQueries(t *testing.T) {
	const (
		queries = 10000
		clients = 64
		names   = 5000 // > maxCacheEntries, so eviction runs constantly
	)
	runtime.GC()
	baseG := runtime.NumGoroutine()

	idx := func(q []byte) int {
		qq, err := packet.ParseDNSQuestion(q)
		if err != nil {
			return -1
		}
		var i int
		if _, err := fmt.Sscanf(qq.Name, "host%d.soak.example", &i); err != nil {
			return -1
		}
		return i
	}
	big := func(q []byte, i int) []byte {
		r := answer(q, 300, nameIP(i))
		return append(r, make([]byte, 3000)...) // trailing bytes: a large answer
	}
	var upstreamQueries atomic.Int64
	tr := &tunnelTransport{}
	tr.onQueryMulti = func(_ netip.AddrPort, q []byte) [][]byte {
		upstreamQueries.Add(1)
		i := idx(q)
		switch {
		case i < 0:
			return nil
		case i%97 == 0:
			return [][]byte{withRcode(answer(q, 60, nameIP(i)), rcodeServFail)}
		case i%13 == 0:
			return [][]byte{truncatedAnswer(q)}
		case i%11 == 0:
			// A forged reply (wrong ID, wrong address) ahead of the real one.
			forged := answer(q, 3600, netip.MustParseAddr("6.6.6.6"))
			binary.BigEndian.PutUint16(forged[0:2], binary.BigEndian.Uint16(q[0:2])^0xffff)
			return [][]byte{forged, answer(q, 60, nameIP(i))}
		case i%7 == 0:
			return [][]byte{big(q, i)}
		default:
			return [][]byte{answer(q, uint32(30+i%600), nameIP(i))}
		}
	}
	tr.onTCPQuery = func(_ netip.AddrPort, q []byte) ([]byte, error) {
		return big(q, idx(q)), nil
	}

	r, err := New(Config{
		Transport:    tr,
		Upstreams:    []netip.AddrPort{netip.MustParseAddrPort("10.64.0.1:53"), netip.MustParseAddrPort("10.64.0.2:53")},
		QueryTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	var next, bad, servfails atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for c := 0; c < clients; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(c)))
			for next.Add(1) <= queries {
				// Zipf-ish: a hot set gets most of the lookups, as a browser does.
				i := rng.Intn(names)
				if rng.Intn(4) != 0 {
					i = rng.Intn(200)
				}
				id := uint16(rng.Intn(65536))
				q := query(id, fmt.Sprintf("host%d.soak.example", i), packet.QTypeA)
				resp, handled, err := r.HandleQuery(context.Background(), netip.AddrPort{}, q)
				if err != nil || !handled {
					bad.Add(1)
					continue
				}
				qq, perr := packet.ParseDNSQuestion(resp)
				if perr != nil || !qq.Response || qq.ID != id || qq.Name != fmt.Sprintf("host%d.soak.example", i) {
					bad.Add(1)
					continue
				}
				if rcode(resp) == rcodeServFail {
					servfails.Add(1)
					if i%97 != 0 {
						bad.Add(1)
					}
					continue
				}
				// The single A record's address sits right after the
				// question: pointer(2) type(2) class(2) ttl(4) rdlen(2).
				off := len(q) + 12
				if len(resp) < off+4 || netip.AddrFrom4([4]byte(resp[off:off+4])) != nameIP(i) {
					bad.Add(1)
				}
			}
		}(c)
	}
	wg.Wait()
	elapsed := time.Since(start)

	size := r.cache.size()
	r.cache.mu.RLock()
	cacheBytes := r.cache.bytes
	r.cache.mu.RUnlock()
	t.Logf("%d queries from %d clients in %s (%.0f q/s); %d reached upstream; cache %d entries / %.1f KiB; %d expected SERVFAILs",
		queries, clients, elapsed.Round(time.Millisecond), float64(queries)/elapsed.Seconds(),
		upstreamQueries.Load(), size, float64(cacheBytes)/1024, servfails.Load())
	if n := bad.Load(); n > 0 {
		t.Errorf("%d replies were wrong (mismatched question, ID or address)", n)
	}
	if size > maxCacheEntries || cacheBytes > maxCacheBytes {
		t.Errorf("cache exceeded its bounds: %d entries, %d bytes", size, cacheBytes)
	}
	if n := tr.openSessions.Load(); n != 0 {
		t.Errorf("%d upstream sessions left open", n)
	}
	_ = r.Close()
	var g int
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if g = runtime.NumGoroutine(); g <= baseG+2 {
			return
		}
	}
	t.Errorf("goroutines %d -> %d", baseG, g)
}
