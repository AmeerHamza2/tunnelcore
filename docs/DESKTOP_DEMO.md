# Desktop demo: a real VPN with a web control panel

`cmd/slipstream-desktop` runs the TunnelCore engine as a real VPN on Linux,
through the same `mobile.Tunnel` API the phone apps call. A web panel shows the
connection, the public IP before and after, live throughput, and a switch that
blocks WireGuard so you can watch the engine fall back to Shadowsocks.

```
 your browser ──► panel (:8080) ──► slipstream-desktop ──► tun slip0 ──► engine
                                                                │ WireGuard UDP 51820
                                                                │ Shadowsocks TCP 8388
                                                                ▼
                                                    exit server (server-setup.sh)
                                                                ▼
                                                            internet
```

## 1. Exit server (any Ubuntu 22.04/24.04 VPS)

Open UDP 51820, UDP 51821 and TCP 8388 in the cloud firewall. Then, with the
device's public key from step 2:

```bash
ssh ubuntu@SERVER "sudo bash -s -- DEVICE_PUBLIC_KEY Singapore SG" < deploy/server-setup.sh
ssh ubuntu@SERVER "sudo cat /etc/slipstream/location.json" > singapore.json
```

The script installs WireGuard, Shadowsocks (chacha20-ietf-poly1305) and the UDP
echo health port, opens the host firewall, enables NAT, and prints the location
file. Re-running it keeps the server keys. Run it on a second server with a
different name and country for a second location.

## 2. Client (a Linux machine or VM)

```bash
./slipstream-desktop keygen                       # prints the device public key; the private key stays here
mkdir locations && cp singapore.json locations/
sudo ./slipstream-desktop serve -locations locations
```

Open the printed `http://<machine-ip>:8080` from any browser on the same network.

## How it works

- **Routing.** The client creates `slip0`, routes `0.0.0.0/1` and `128.0.0.0/1`
  into it, and adds host routes to the exit servers via the original gateway.
  Those host routes do on Linux what `VpnService.protect` does on Android: the
  engine's own sockets to the servers must not enter the tunnel.
- **DNS.** systemd-resolved sends every lookup to `slip0`. Over WireGuard the
  query travels encrypted to the resolver; over Shadowsocks the engine
  intercepts port 53 and resolves through the proxy. IPv6 is disabled for the
  session so nothing bypasses an IPv4 tunnel.
- **Block WireGuard** adds an `iptables` rule dropping UDP to the WireGuard port
  and signals a network change; the engine re-races and Shadowsocks wins. Turn
  it on before connecting and the race never picks WireGuard at all.
- Disconnect (or Ctrl-C) removes every route, rule and DNS setting it added.

Tested end to end in a three-namespace lab (client, exit server running
WireGuard and shadowsocks-libev, website): WireGuard connects in ~50 ms; with
WireGuard blocked the engine is on Shadowsocks in under 0.5 s; the website sees
the exit server's address on both transports.
