# Due-diligence findings and known gaps

## Fixed during hardening

| Severity | Area | Finding | Fix |
|---|---|---|---|
| Critical | Android | Engine sockets were not excluded from the VPN route → routing loop, tunnel never comes up | `transport/protect`: `VpnService.protect(fd)` on every WireGuard/Shadowsocks socket, fail-closed |
| High | Engine | Dead Shadowsocks server left state "connected" forever | Stream health tracking fails the session → failover |
| High | WireGuard | Silent peer left state "connected" forever | Dead-peer monitor (data sent, nothing received in 20s → close) |
| High | DNS | Upstream replies not matched to query → cache poisoning | ID/QR/question validation; mismatched replies discarded |
| High | netstack | TCP capped at 512 *established* flows; 513th hung | Complete forwarder request after handshake; explicit flow cap with RST |
| High | netstack | Idle UDP flows and goroutines leaked | Bidirectional idle timer, per-flow teardown, UDP flow cap |
| High | mobile | Calling `Stop()` from a state callback deadlocked | Callbacks delivered on a dedicated serial goroutine |
| Medium | Keys | `Key.String()` logged 32 bits of private keys | SHA-256 fingerprint |
| Medium | Keys | Hex keys unparseable; errors quoted secret characters | Length-dispatched parsing, sentinel errors only |
| Medium | Privacy | Shadowsocks endpoints could be hostnames → cleartext DNS outside tunnel | Literal addresses required (as WireGuard) |
| Medium | Censorship | Fixed-length first Shadowsocks segment is a known DPI fingerprint | Address header coalesced with first payload |
| Medium | DNS | SERVFAIL/truncated replies cached; no failover; label-dot cache collision | Cache only definitive answers; failover; RFC 4343 escaping |
| Medium | Engine | Flapping transport retried every 500ms forever; stale network-change killed new session | Stable-session backoff reset; network change cuts backoff short |
| Medium | Metrics | `Snapshot` reset packet counters shown in the app | Delta folding |
| Low | WireGuard | wireguard-go reports `listen_port=0` on IPv6-less hosts (upstream bug) | Bind wrapper |

### Robustness pass (soak, fuzz, race under load)

Every fix below has a regression test; the soak tests that found most of them
are described in the README's *Robustness testing* section.

| Severity | Area | Finding | Fix |
|---|---|---|---|
| Critical | netstack | Flow goroutines called `wg.Add` from gVisor's packet path while `Stack.Close` was in `wg.Wait`. A reconnect with traffic in flight raced, and the runtime could panic with "WaitGroup is reused before previous Wait has returned", killing the VPN process. Found by `go test -race -count=15 -p 4` (`TestStreamPathCarriesTraffic`, `TestDeadStreamTransportFailsOver`) | `enter()`/`closing` gate makes Add and Wait mutually exclusive; the TCP handler runs on gVisor's goroutine instead of spawning another (`TestStackCloseRacesInboundDelivery`) |
| High | netstack | With gVisor's default RACK-TLP loss detection, a sender that lost segments near its FIN could stop retransmitting: FIN-WAIT-1, data outstanding, no timer armed. This stack is the sender towards every app, so on a lossy radio, downloads hung a few hundred bytes from the end. 5 of 200 downloads stuck at 10% loss. The same stall, on the test peer's side, froze flows for over 8 minutes in the 2,000-flow soak whenever the box was CPU-starved | RACK disabled, so recovery uses SACK (RFC 6675) plus RTO (`TestStackDisablesRACK`; `TestSoakNetstackLossyDownload`, where `STACKRACK=1` reproduces the bug). The contended 2,000-flow soak now finishes in about 10 s |
| High | Shadowsocks | `CloseWrite` took the write lock only while a header was still pending. Read clears that flag when it takes the header, before writing it, so a half-close racing a server-speaks-first read shut the socket down under the header write. Result: EPIPE, and the exit node saw EOF before it learned the destination. Found by the Shadowsocks soak | `CloseWrite` always takes `writeMu` (`TestCloseWriteWaitsForInFlightHeaderWrite`) |
| High | netstack | A reset or write error on one direction of a spliced flow was passed on as a half-close. A killed app, or a server that ignores EOF, then pinned two goroutines, 64 KiB of buffers and a flow slot indefinitely | An error closes both directions, as a kernel does with RST; a clean EOF still half-closes (`TestStackRemoteResetTearsDownFlow`) |
| High | netstack | Intercepted UDP/53 flows had no cap and each lived for the 60 s UDP idle timeout. Stub resolvers use a fresh source port per query, so a browser held hundreds of goroutines and endpoints, and a port-53 flood grew them without bound | 512-flow DNS cap (drop beyond it) and a 10 s idle (`TestStackDNSFlowsAreCappedAndReclaimed`) |
| High | DNS | The cache was bounded only by entry count. TCP answers can be 64 KiB, and any web page can trigger lookups of attacker-controlled names, so 2048 entries could pin about 128 MiB. That is several times an iOS network extension's memory limit | 2 MiB byte bound with exact accounting; a single answer over 256 KiB is served but not cached (`TestCacheIsBoundedInBytes`) |
| Medium | Shadowsocks | Each UDP session allocated 2 × 64 KiB up front. That was about 130 KiB of garbage per DNS lookup (dnsproxy opens a session per query) and up to about 130 MiB resident at 1024 flows. An oversized datagram also failed the read, which ended the whole flow | Pooled send buffer and a lazily allocated 16 KiB receive buffer. Oversized datagrams are dropped and counted; the flow continues (`TestUDPSessionMemory`: about 35 KiB per query+reply including the fixture, previously over 150 KiB; `TestUDPOversizeDatagramDropped`) |
| Medium | netstack / metrics | gVisor's channel link endpoint drops packets silently when its queue is full: a short count with a nil error, and no NIC counter increments. Traffic towards the apps could be shed invisibly | `countingLink` wrapper → `Stats.DroppedOutbound`, folded into the collector's inbound drops (`TestStackCountsOutboundQueueDrops`) |
| Medium | mobile | Config validation gaps. A DNS server on port 0 or the unspecified address passed validation and then made `dnsproxy.New` fail on every session build, an endless reconnect loop over a healthy transport. Other gaps: mapped or unspecified tunnel addresses (same failure at netstack build); `keepalive_seconds`, `race_*_ms` large enough to overflow `time.Duration`; trailing data after the JSON object silently ignored | Rejected in `parseConfig` (`TestParseConfigRejectsHostileValues`, new `FuzzNewTunnel`) |

## Known gaps / roadmap

- The DNS blocklist is enforced on the Shadowsocks path only; WireGuard traffic resolves via the exit node's DNS. Fix: intercept UDP/53 in the packet path.
- Shadowsocks authentication failures are classified as "refused" in metrics; this needs a `transport.ErrAuthFailed` sentinel.
- SNI-aware `tlsfrag` has no effect under Shadowsocks (it sees ciphertext). It's useful only for a future TLS-based transport.
- No Shadowsocks 2022 (SIP022) replay protection; AEAD-2017 only.
- Real-device validation (Android VpnService, iOS NE) is still to do. The fd path is tested over a `SOCK_DGRAM` socketpair.
- The userspace stack's link queues are 512 packets deep. When the tunnel writer falls behind, packets are dropped: about 1.9k in the 2,000-flow soak. The drops are now counted (`DroppedOutbound`), and TCP recovers. On a very lossy link, though, exponential RTO backoff means one flow in 200 can take minutes (the 10%-loss download soak took between 25 s and 5 min). Pacing, or backpressure from the tunnel writer into the stack, would cut both.
- A Shadowsocks UDP session blocked in `ReadFrom` still holds its 16 KiB receive buffer, so 1024 proxied UDP flows cost about 17 MiB. Shrinking that further needs `MSG_TRUNC`-style size probing per platform.
- The DNS cache does not coalesce concurrent misses for the same name (no singleflight), so a burst of identical lookups all go upstream.
- RACK-TLP is disabled to avoid a gVisor sender stall (above). Re-enable it after upgrading gVisor, but only once `TestSoakNetstackLossyDownload` passes with `STACKRACK=1`.
