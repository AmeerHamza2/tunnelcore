# TunnelCore

[![ci](https://github.com/ameerhamza2/tunnelcore/actions/workflows/ci.yml/badge.svg)](https://github.com/ameerhamza2/tunnelcore/actions/workflows/ci.yml)

The on-device networking engine of **Slipstream VPN**, written in Go and compiled
with `gomobile` into an Android `.aar` and an iOS `.xcframework`.

It takes the tunnel file descriptor from Android's `VpnService` or iOS's
`NEPacketTunnelProvider` and carries every packet to an exit node over
**WireGuard** or **Shadowsocks** with anti-censorship obfuscation. Along the way it
runs a userspace TCP/IP stack, an in-tunnel DNS proxy, server racing, and automatic
reconnect and failover.

The backend that issues its config lives in
[slipstream-control](https://github.com/ameerhamza2/slipstream-control).

## Architecture

```
  Android VpnService / iOS NEPacketTunnelProvider ── tun fd + JSON config
                              │  gomobile API (mobile/)
┌─────────────────────────────▼───────────────────────────────────────────┐
│ engine   supervisor · state machine · backoff · network-change handling  │
│                                                                          │
│ tun fd ─► ┬─► WireGuard (packet transport) ───────────────► exit node    │
│           └─► netstack (gVisor TCP/IP) ─► Shadowsocks ─────► exit node    │
│                 └─► dnsproxy (in-tunnel DNS, validated, cached)          │
│                                                                          │
│ racer: staggered race across servers · protect: Android socket bypass    │
│ metrics: aggregates only, no destinations or hostnames                   │
└──────────────────────────────────────────────────────────────────────────┘
```

| Package | Role |
|---|---|
| `packet` | Zero-allocation, fuzzed IPv4/IPv6/TCP/UDP/DNS parsing |
| `netstack` | gVisor stack: turns app flows into proxied connections, intercepts DNS, enforces flow limits |
| `dnsproxy` | Fail-closed in-tunnel resolver: anti-poisoning checks, byte-bounded cache, failover |
| `transport` | Transport interface (packet vs stream) and the server racer |
| `transport/wireguard` | wireguard-go on an in-memory TUN, handshake-confirmed up, dead-peer detection |
| `transport/shadowsocks` | AEAD Shadowsocks over TCP and UDP, credential probe, first-packet coalescing |
| `transport/obfs` | SNI-aware TLS fragmentation, prefix disguise |
| `transport/protect` | Fail-closed Android `VpnService.protect(fd)` |
| `engine` | Lifecycle, reconnect and backoff, failover, dead-session detection |
| `mobile` | The gomobile API: `NewTunnel`, `Start(fd)`, `Stop`, `NetworkChanged`, `StatsJSON` |
| `cmd/tun-harness` | Live demo, keygen, config validation, Linux runner |

## Key design decisions

- **The engine owns the tun fd.** It can switch between WireGuard and Shadowsocks at runtime without re-establishing the VPN.
- **"Connected" means a completed handshake**, never just an open socket.
- **Fail closed:** no DNS leaks outside the tunnel, no unprotected sockets, and UDP a transport can't carry is dropped rather than sent outside it.
- **Private keys stay on the device.** The backend only ever sees the public key.
- **A network change is not a failure.** Handovers reconnect immediately; real failures back off.

## Quick start

```bash
go run ./cmd/tun-harness demo     # ~1 s live demo, no root needed
make test                         # vet + race tests
make soak                         # leak and soak suites
make android  /  make ios         # gomobile builds
```

The demo races four servers (one blocked, one dead), sends real traffic,
simulates a Wi-Fi to cellular handover, fails over from WireGuard to
Shadowsocks, and prints per-server metrics.

## Docs

- [docs/INTEGRATION.md](docs/INTEGRATION.md): the JSON config contract, plus Kotlin and Swift integration
- [docs/DESIGN.md](docs/DESIGN.md): architecture and design decisions in depth
- [docs/ROBUSTNESS.md](docs/ROBUSTNESS.md): soak, fuzz and benchmark results
- [docs/DUE_DILIGENCE_GAPS.md](docs/DUE_DILIGENCE_GAPS.md): issues found and fixed, plus known gaps
