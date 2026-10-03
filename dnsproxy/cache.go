package dnsproxy

import (
	"encoding/binary"
	"sync"
	"time"
)

// cacheKey identifies a cached answer. Name and qtype only: the class is
// always IN in practice, and including it would just widen the key.
type cacheKey struct {
	name  string
	qtype uint16
}

type cacheEntry struct {
	response  []byte
	storedAt  time.Time
	expiresAt time.Time
	// ttlOffsets locates the TTL field of every answer and authority record
	// in response, so get can age them without re-walking the message.
	ttlOffsets []int
}

// cache is a TTL cache for DNS responses.
//
// The TTL comes from the response's own records, clamped to the configured
// floor and ceiling. Reading it requires walking the record headers of the
// answer and authority sections — the only place in this package that looks
// past the question, and it is written to fail closed: if anything does not
// parse, the answer is cached for the floor rather than not cached or cached
// forever.
//
// Served copies have their TTLs aged by the time spent in the cache. Serving
// the stored TTLs unchanged would let a downstream cache hold the answer for
// its full original lifetime again on top of ours — and, past the ceiling,
// for far longer than this cache was willing to.
type cache struct {
	mu      sync.RWMutex
	entries map[cacheKey]cacheEntry
	// bytes is the total size of every stored response, bounded by
	// maxCacheBytes. See put.
	bytes int

	floor   time.Duration
	ceiling time.Duration

	// now is time.Now; tests replace it to age entries without sleeping.
	now func() time.Time
}

func newCache(floor, ceiling time.Duration) *cache {
	return &cache{
		entries: make(map[cacheKey]cacheEntry, 64),
		floor:   floor,
		ceiling: ceiling,
		now:     time.Now,
	}
}

func (c *cache) get(name string, qtype uint16) ([]byte, bool) {
	key := cacheKey{name: name, qtype: qtype}

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil, false
	}
	now := c.now()
	if now.After(entry.expiresAt) {
		c.mu.Lock()
		// Re-check under the write lock: another goroutine may have refreshed
		// the entry between our read and this delete, and deleting a fresh
		// entry would cost an unnecessary upstream query.
		if cur, still := c.entries[key]; still && c.now().After(cur.expiresAt) {
			c.deleteLocked(key, cur)
		}
		c.mu.Unlock()
		return nil, false
	}
	return entry.aged(now), true
}

// aged returns a copy of the response with every TTL reduced by the time the
// entry has been cached, and capped at the entry's remaining lifetime so a
// client never caches it past the point this cache would have dropped it.
func (e cacheEntry) aged(now time.Time) []byte {
	resp := append([]byte(nil), e.response...)
	elapsed := uint32(now.Sub(e.storedAt) / time.Second)
	remaining := uint32(e.expiresAt.Sub(now) / time.Second)
	for _, off := range e.ttlOffsets {
		ttl := binary.BigEndian.Uint32(resp[off : off+4])
		if ttl > 0x7fffffff { // RFC 2181: treat as zero
			ttl = 0
		}
		if ttl > elapsed {
			ttl -= elapsed
		} else {
			ttl = 0
		}
		ttl = min(ttl, remaining)
		binary.BigEndian.PutUint32(resp[off:off+4], ttl)
	}
	return resp
}

func (c *cache) put(name string, qtype uint16, response []byte) {
	offsets, answers := ttlOffsets(response)
	ttl := c.clampTTL(minTTL(response, offsets[:answers]))
	now := c.now()

	key := cacheKey{name: name, qtype: qtype}
	size := entrySize(name, response, offsets)
	if size > maxCacheBytes/8 {
		// One answer this large would evict a large share of everything
		// else to make room. It is served, just not kept.
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.entries[key]; ok {
		c.deleteLocked(key, old)
	}
	if len(c.entries) >= maxCacheEntries || c.bytes+size > maxCacheBytes {
		c.evictLocked(size)
	}
	c.entries[key] = cacheEntry{
		response:   append([]byte(nil), response...),
		storedAt:   now,
		expiresAt:  now.Add(ttl),
		ttlOffsets: offsets,
	}
	c.bytes += size
}

// entrySize approximates the memory one entry holds: the response copy, the
// name in the key, the offsets slice and a fixed overhead for the map slot and
// entry header.
func entrySize(name string, response []byte, offsets []int) int {
	return len(response) + len(name) + 8*len(offsets) + 96
}

func (c *cache) deleteLocked(key cacheKey, e cacheEntry) {
	delete(c.entries, key)
	c.bytes -= entrySize(key.name, e.response, e.ttlOffsets)
}

// evictLocked frees space in the cache.
//
// It first drops everything already expired, which on a real workload is
// usually enough. If the cache is still full it drops a random sample instead
// of implementing an LRU: at this size the bookkeeping an exact LRU needs
// (an intrusive list, and a write lock taken on every *read* to reorder it)
// costs more than the occasional extra upstream query from evicting a
// slightly-warmer entry.
//
// The cache is bounded in bytes as well as in entries. A count alone was not a
// memory bound: an answer fetched over TCP can be 64 KiB, and any web page can
// make the device resolve names whose answers an attacker controls, so 2048
// entries could pin 128 MiB — several times an iOS network extension's entire
// memory budget. need is the size of the entry about to be inserted.
func (c *cache) evictLocked(need int) {
	now := c.now()
	for k, v := range c.entries {
		if now.After(v.expiresAt) {
			c.deleteLocked(k, v)
		}
	}
	fits := func() bool {
		return len(c.entries) < maxCacheEntries && c.bytes+need <= maxCacheBytes
	}
	if fits() {
		return
	}

	// Drop at least an eighth of the cache so this does not run on every
	// insertion, and keep going until the new entry fits.
	target := len(c.entries) / 8
	if target == 0 {
		target = 1
	}
	dropped := 0
	for k, v := range c.entries { // Go randomises map iteration order
		c.deleteLocked(k, v)
		dropped++
		if dropped >= target && fits() {
			return
		}
	}
}

func (c *cache) clampTTL(ttl time.Duration) time.Duration {
	if ttl < c.floor {
		return c.floor
	}
	if ttl > c.ceiling {
		return c.ceiling
	}
	return ttl
}

func (c *cache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[cacheKey]cacheEntry, 64)
	c.bytes = 0
}

func (c *cache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// responseTTL returns the smallest TTL among the answer records.
//
// The minimum, not the first: the first answer is routinely a CNAME with a
// long TTL in front of a short-lived A record, and caching the pair for the
// CNAME's lifetime serves the A record long after its owner said to drop it.
//
// Returns 0 when the response has no answers or cannot be walked, which the
// caller clamps up to the floor. Failing closed like this is deliberate: the
// alternatives are not caching at all (losing the benefit on exactly the
// malformed-but-working responses some CDNs emit) or caching forever (pinning
// a bad answer).
func responseTTL(msg []byte) time.Duration {
	offsets, answers := ttlOffsets(msg)
	return minTTL(msg, offsets[:answers])
}

func minTTL(msg []byte, offsets []int) time.Duration {
	if len(offsets) == 0 {
		return 0
	}
	lowest := uint32(0x7fffffff)
	for _, off := range offsets {
		ttl := binary.BigEndian.Uint32(msg[off : off+4])
		// A TTL with the top bit set is, per RFC 2181, to be treated as
		// zero: the field is signed in some implementations and a
		// "negative" TTL has been used as a cache-poisoning trick.
		if ttl > 0x7fffffff {
			ttl = 0
		}
		lowest = min(lowest, ttl)
	}
	return time.Duration(lowest) * time.Second
}

// ttlOffsets returns the offset of the TTL field of every answer and
// authority record, and how many of those are answers. The additional
// section is deliberately excluded: an OPT record's "TTL" field carries the
// extended rcode and EDNS flags, and aging it would corrupt them.
//
// If any record cannot be walked it returns no offsets at all, so a malformed
// message is cached for the floor and served unmodified rather than having
// bytes rewritten at offsets that may not be TTLs.
//
// This does not follow compression pointers. The question's name is walked
// with the same pointer-refusing rules as packet.ParseDNSQuestion, and record
// names are skipped by recognising a pointer's two-byte form rather than
// resolving it — which is all that is needed to reach the TTL field.
func ttlOffsets(msg []byte) ([]int, int) {
	const headerLen = 12
	if len(msg) < headerLen {
		return nil, 0
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))

	off := headerLen
	for i := 0; i < qdCount; i++ {
		n, ok := skipName(msg, off)
		if !ok || n+4 > len(msg) { // qtype + qclass
			return nil, 0
		}
		off = n + 4
	}

	// Each record is at least 11 bytes, which bounds the allocation by the
	// message size rather than by the attacker-chosen counts.
	offsets := make([]int, 0, min(anCount+nsCount, len(msg)/11))
	for i := 0; i < anCount+nsCount; i++ {
		n, ok := skipName(msg, off)
		if !ok || n+10 > len(msg) { // type, class, TTL, rdlength
			return nil, 0
		}
		offsets = append(offsets, n+4)
		rdLen := int(binary.BigEndian.Uint16(msg[n+8 : n+10]))
		off = n + 10 + rdLen
		if off > len(msg) {
			return nil, 0
		}
	}
	return offsets, anCount
}

// skipName advances past a DNS name at off and returns the following offset.
//
// A compression pointer terminates the name in two bytes, so it is skipped
// rather than followed. The label walk is bounded so a crafted run of labels
// cannot spin.
func skipName(msg []byte, off int) (int, bool) {
	const maxLabels = 128
	for labels := 0; ; labels++ {
		if labels > maxLabels {
			return 0, false
		}
		if off >= len(msg) {
			return 0, false
		}
		n := int(msg[off])
		switch {
		case n == 0:
			return off + 1, true
		case n&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, false
			}
			return off + 2, true
		case n&0xc0 != 0:
			return 0, false // reserved label type
		}
		off += 1 + n
		if off > len(msg) {
			return 0, false
		}
	}
}
