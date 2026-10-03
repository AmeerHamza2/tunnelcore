# Design

## Architecture

```
            ┌──────────────── mobile app (Kotlin / Swift) ────────────────┐
            │  VpnService / NEPacketTunnelProvider → fd, JSON config        │
            └───────────────────────────┬──────────────────────────────────┘
                                        │ gomobile API (package mobile)
┌───────────────────────────────────────▼──────────────────────────────────┐
│ engine   supervisor · state machine · backoff · network-change handling   │
│                                                                           │
│  tun fd ─► read ─┬─► WireGuard (packet transport) ─────────► exit node    │
│                  └─► netstack (gVisor TCP/IP) ─► Shadowsocks ─► exit node │
│                         └─► dnsproxy (in-tunnel DNS, policy, cache)       │
│                                                                           │
│ transport.Racer: happy-eyeballs race across candidates, cancels losers    │
│ protect: Android VpnService.protect(fd) on every engine socket            │
│ metrics: aggregates only — no destinations, no hostnames                  │
└───────────────────────────────────────────────────────────────────────────┘
```

| Package | Responsibility |
|---|---|
| `packet` | Zero-allocation, fuzzed IPv4/IPv6/TCP/UDP/DNS parsing and checksums |
| `netstack` | gVisor userspace stack: terminates app TCP/UDP flows, dials them over a stream transport, intercepts DNS (UDP and TCP/53), bounded flow counts |
| `dnsproxy` | In-tunnel resolver: fail-closed, reply validation (anti-poisoning), TTL-aged cache, upstream failover, blocklist policy |
| `transport` | Transport interface (packet vs stream) and the racer |
| `transport/wireguard` | wireguard-go on an in-memory TUN, handshake-confirmed `Up`, dead-peer detection |
| `transport/shadowsocks` | AEAD Shadowsocks (TCP + UDP), probe-verified credentials, first-packet coalescing |
| `transport/obfs` | SNI-aware TLS ClientHello fragmentation, prefix disguise |
| `transport/protect` | Fail-closed socket protection for Android |
| `engine` | Lifecycle, reconnect/backoff, failover, dead-session detection, stats |
| `metrics` | Privacy-preserving aggregates: success rate, latency histograms |
| `mobile` | gomobile-bindable API: `NewTunnel`, `Start(fd)`, `Stop`, `NetworkChanged`, `StatsJSON`, `GeneratePrivateKey` |
| `cmd/tun-harness` | Demo, keygen, config validation, Linux runner |

## Key design decisions

- **The engine owns the tun fd; transports never see it.** WireGuard runs on an in-memory TUN, so the racer can swap WireGuard ↔ Shadowsocks at runtime without re-establishing the VpnService.
- **"Connected" means a completed handshake**, never just "socket opened": a blackholed server must lose the race, not show a shield icon.
- **Fail closed everywhere:** DNS never leaks outside the tunnel, UDP that a transport can't carry is dropped, and an unprotectable socket fails the dial.
- **Private keys never leave the device:** `GeneratePrivateKey` runs on the phone; the backend only ever stores the public key.
- **Network change ≠ failure:** a handover reconnects immediately; real failures back off with jitter, and only sessions that stay stable reset the backoff.
