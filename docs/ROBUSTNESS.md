# Robustness testing


The engine runs for days on millions of phones, through constant network
changes, hundreds of concurrent app flows and whatever bytes apps write into the
tunnel. The suites below test for that. The measured numbers come from a 2-vCPU
Linux VM (Xeon @ 2.1 GHz).

**Soak and leak tests.** These sit behind the `soak` build tag, so `make test`
stays fast. Run them with `make soak`, or
`go test -tags soak -run Soak -count=1 -timeout 30m ./...`. Add `-race` for a
stricter, slower run (`make soak SOAKFLAGS=-race`).

| Test | What it does | Asserts | Measured |
|---|---|---|---|
| `engine` `TestSoakEngineReconnectCycles` | 520 reconnects, alternating `NetworkChanged` and transport deaths. Rotates a packet fake, a stream fake (live userspace stack) and a real wireguard-go client against a real peer | Goroutines and heap return to baseline | 208 packet / 209 stream / 103 WireGuard sessions in ~12 s; goroutines 23 → 24, heap 16.5 → 16.6 MiB |
| `netstack` `TestSoakNetstackConcurrentFlows` | 2,000 concurrent TCP flows (random 1 B–64 KiB, echo with half-close) and 1,000 UDP flows (5 exchanges each) from an app-side stack to loopback servers | Byte-exact data, zero flows and baseline goroutines after close | 124.8 MiB echoed in 7.4 s idle, 10.4 s beside two CPU-burning processes; goroutines 4 → 4; ~1.9k outbound-queue drops counted and recovered |
| `netstack` `TestSoakNetstackLossyLink` | 200 echo flows over a link dropping 2% and 10% of packets each way | Every flow completes byte-exact | 0 failures (2%: 1.4 s, 10%: ~80 s) |
| `netstack` `TestSoakNetstackLossyDownload` | 200 downloads over a 10%-loss link; the stack is the sender, FIN included | Every body arrives complete and terminated | 0 failures, 25 s to 5 min (RTO backoff); `STACKRACK=1` reproduces the gVisor RACK stall |
| `internal/ssserver` `TestSoakShadowsocksConcurrentStreams` | 200 concurrent streams per cipher (3 ciphers) against the independent server: 0 B to 256 KiB, random write and read sizes, half-closes, server-speaks-first | Byte-exact; goroutines return to baseline | 28.2 MiB per cipher, 0 failures (also clean under `-race`) |
| `dnsproxy` `TestSoakDNSProxyConcurrentQueries` | 10,000 queries from 64 clients over 5,000 names. The upstream mixes forged replies, SERVFAIL, truncation with TCP fallback, and large answers | Every reply answers its own question with the right address; cache within 2048 entries / 2 MiB; no leaked sessions or goroutines | ~20k q/s under `-race`; cache peaked at 1,836 entries / 1.4 MiB |
| `mobile` `TestSoakMobileStartStopCycles` | 200 `Start`/`Stop` cycles of the bound API over a `SOCK_DGRAM` socketpair with a real WireGuard peer, one packet verified per cycle | fd count (`/proc/self/fd`) and goroutines return to baseline | 54 ms per cycle; fds 9 → 9, goroutines 19 → 19 |

**Hostile input.** `TestHostilePacketsDoNotDisruptEngine` runs in the default
suite. It pushes 3,000 malformed, fragmented, truncated, oversized (up to
64 KiB) and IPv6-extension-chained packets through both data paths. The
session must survive, valid traffic must still flow afterwards, and nothing may
leak.

**Fuzzing.** Each target ran for at least 2 minutes with no crashers, so no
crash corpus was committed:

| Target | Package | Execs in 2 min |
|---|---|---|
| `FuzzParse` | `packet` | 3.7 M |
| `FuzzParseDNSQuestion` | `packet` | 3.9 M |
| `FuzzBuildUDPRoundTrip` | `packet` | 3.7 M |
| `FuzzFindSNI` | `transport/obfs` | 3.3 M |
| `FuzzTLSFragmentWrite` | `transport/obfs` | 3.6 M |
| `FuzzHandleQuery` | `dnsproxy` | 1.9 M |
| `FuzzResponseTTL` | `dnsproxy` | 4.8 M |
| `FuzzStackDeliverInbound` (new: arbitrary bytes into the userspace stack, DNS interception on) | `netstack` | 3.3 M |
| `FuzzNewTunnel` (new: arbitrary config JSON; an accepted config must yield transports) | `mobile` | 1.1 M |

Run one with `go test -run='^$' -fuzz='^FuzzParse$' -fuzztime=2m ./packet/`.
Only one target per invocation, and the pattern must be anchored.

**Benchmarks.** Run them with `make bench`.

| Benchmark | Result |
|---|---|
| `packet` `BenchmarkParse` | 87 ns/op, 6.2 GB/s, 0 allocs |
| `packet` `BenchmarkChecksum1400` | 537 ns/op, 2.6 GB/s, 0 allocs |
| `packet` `BenchmarkParseDNSQuestion` | 244 ns/op, 3 allocs |
| `transport/shadowsocks` `BenchmarkStreamWrite` (AES-256-GCM, 1400 B) | 662 ns/op, 2.1 GB/s, 1 alloc |
| `netstack` `BenchmarkStackTCPThroughput/upload` | 76 MB/s |
| `netstack` `BenchmarkStackTCPThroughput/download` | 78 MB/s |

The netstack figure is one bulk flow through two gVisor stacks: the app-side
test peer plus the stack under test. It is a conservative bound for the engine's
own termination and splice cost.

**Race under load.** `go test -race -count=5 ./...` passes. So does the
stress variant `go test -race -count=15 -p 4 ./...`, which runs four packages
at once on two CPUs. That variant is how the netstack shutdown race above was
found.

Engineering findings fixed during hardening, plus the remaining known gaps, are in
[docs/DUE_DILIGENCE_GAPS.md](docs/DUE_DILIGENCE_GAPS.md).
