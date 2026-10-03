# Integrating TunnelCore into a mobile app

## Configuration contract

The app gets this JSON from the backend (`POST /v1/devices/{id}/config` in
slipstream-control) and passes it to `NewTunnel`. Servers are listed in
preference order, and the engine races them.

```json
{
  "servers": [
    {
      "name": "fra-01",
      "protocol": "wireguard",
      "endpoint": "203.0.113.10:51820",
      "public_key": "<server WireGuard public key, base64>",
      "preshared_key": "<optional per-peer PSK, base64>",
      "keepalive_seconds": 25
    },
    {
      "name": "fra-01-ss",
      "protocol": "shadowsocks",
      "endpoint": "203.0.113.10:8443",
      "method": "chacha20-ietf-poly1305",
      "password": "<per-user secret, base64 32 bytes>",
      "plugins": [{ "type": "prefix", "prefix": "FgMB", "label": "tls-record" }]
    }
  ],
  "tunnel_addresses": ["10.64.0.7/32"],
  "dns_servers": ["10.64.0.1"],
  "mtu": 1420,
  "blocked_domains": ["doubleclick.net"]
}
```

What the backend never sends is the device's **WireGuard private key**. The
app generates it once with `GeneratePrivateKey()`, keeps it in the Android
Keystore or iOS Keychain, registers only `PublicKeyFor(priv)`, and merges
`"private_key"` into each WireGuard server entry before calling `NewTunnel`.
Endpoints must be literal IPs: resolving a hostname would leak the server's
name in cleartext DNS before the tunnel exists.

Validation is strict. Unknown fields are rejected, so a setting the backend
thinks is enabled can't be silently ignored. A single malformed server is
skipped rather than failing the whole config.

## Mobile integration

`make android` produces `tunnelcore.aar`; `make ios` produces `Tunnelcore.xcframework`.

**Android (Kotlin, `VpnService`)**

```kotlin
class SlipstreamVpnService : VpnService() {
    private var tunnel: mobile.Tunnel? = null

    fun connect(configJson: String) {
        val t = Mobile.newTunnel(configJson)            // validates before any OS work
        t.setSocketProtector { fd -> protect(fd) }     // keep engine sockets out of the VPN
        t.setStateListener { state, reason, transport, err ->
            mainHandler.post { updateUi(state, transport, err) }  // callbacks are off the main thread
        }
        val pfd = Builder()
            .addAddress("10.64.0.7", 32)
            .addDnsServer("10.64.0.1")
            .addRoute("0.0.0.0", 0).addRoute("::", 0)
            .setMtu(1420)
            .establish() ?: return
        t.start(pfd.detachFd().toLong())               // ownership of the fd moves to the engine
        tunnel = t
    }

    // From ConnectivityManager.NetworkCallback: Wi-Fi ↔ cellular handover.
    fun onNetworkChanged() = tunnel?.networkChanged()

    override fun onDestroy() { tunnel?.stop(); super.onDestroy() }
}
```

**iOS (Swift, `NEPacketTunnelProvider`)**

```swift
class PacketTunnelProvider: NEPacketTunnelProvider {
    private var tunnel: MobileTunnel?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        var err: NSError?
        guard let t = MobileNewTunnel(configJSON, &err) else { return completionHandler(err) }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "203.0.113.10")
        settings.ipv4Settings = NEIPv4Settings(addresses: ["10.64.0.7"], subnetMasks: ["255.255.255.255"])
        settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
        settings.dnsSettings = NEDNSSettings(servers: ["10.64.0.1"])
        settings.mtu = 1420
        setTunnelNetworkSettings(settings) { error in
            if let error { return completionHandler(error) }
            // No socket protector needed: NE provider sockets bypass the tunnel.
            do { try t.start(self.tunnelFileDescriptor) } catch { return completionHandler(error) }
            self.tunnel = t
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        try? tunnel?.stop(); completionHandler()
    }
}
```

`tunnelFileDescriptor` is the usual utun-fd lookup that WireGuard's Apple
client also uses. The engine handles utun's 4-byte address-family header.

| API | Notes |
|---|---|
| `NewTunnel(json)` / `SetConfig(json)` | Validate up front, so config errors show before asking for VPN permission |
| `Start(fd)` | Returns immediately. The fd is owned by the engine even if Start fails |
| `Stop()` | Blocks until nothing touches the fd. Safe to call from a state callback |
| `NetworkChanged()` | Coalesced. Reconnects with no backoff |
| `IsUp()` | True only when traffic actually flows, never during reconnect |
| `StatsJSON()` | Aggregates only: success rate, p50/p95, bytes, reconnects |
| `GeneratePrivateKey()` / `PublicKeyFor()` | Device-side key generation |
