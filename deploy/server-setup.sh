#!/usr/bin/env bash
# Turns a fresh Ubuntu 22.04/24.04 server into a Slipstream exit node:
# WireGuard on UDP 51820, Shadowsocks on TCP+UDP 8388, and the UDP echo health
# port on 51821 that the app's latency probe measures.
#
# Usage (from your computer):
#   ssh -i KEY ubuntu@SERVER_IP 'sudo bash -s -- CLIENT_PUBLIC_KEY [LOCATION_NAME] [COUNTRY_CODE]' < server-setup.sh
#
# CLIENT_PUBLIC_KEY is the device's WireGuard public key. The device keeps its
# private key; the server only ever learns the public half.
#
# It prints the location file the desktop client needs (also saved to
# /etc/slipstream/location.json). Re-running it is safe: existing keys and the
# Shadowsocks password are kept, and the client key is updated.
set -euo pipefail

CLIENT_PUB="${1:-}"
LOCATION_NAME="${2:-Singapore}"
COUNTRY="${3:-SG}"
WG_PORT=51820
ECHO_PORT=51821
SS_PORT=8388
WG_NET=10.66.0
STATE=/etc/slipstream

log() { echo ">>> $*" >&2; }

if [[ $EUID -ne 0 ]]; then echo "run with sudo" >&2; exit 1; fi
if [[ ! "$CLIENT_PUB" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]]; then
  echo "usage: server-setup.sh CLIENT_PUBLIC_KEY [LOCATION_NAME] [COUNTRY_CODE]" >&2
  echo "CLIENT_PUBLIC_KEY must be a base64 WireGuard public key (44 characters ending in =)" >&2
  exit 2
fi

mkdir -p "$STATE"
chmod 700 "$STATE"

log "installing packages (WireGuard, Shadowsocks)"
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
apt-get update -qq
apt-get install -y -qq wireguard-tools iptables curl python3 >/dev/null
if ! apt-get install -y -qq shadowsocks-libev >/dev/null 2>&1; then
  log "shadowsocks-libev not available from apt; installing shadowsocks-rust"
  arch=$(uname -m)
  ver=v1.21.2
  url="https://github.com/shadowsocks/shadowsocks-rust/releases/download/${ver}/shadowsocks-${ver}.${arch}-unknown-linux-gnu.tar.xz"
  curl -fsSL "$url" | tar -xJ -C /usr/local/bin ssserver
  SS_RUST=1
fi

IFACE=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
PUBLIC_IP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)
[[ -n "$PUBLIC_IP" ]] || { echo "could not determine the public IP" >&2; exit 1; }
log "public IP $PUBLIC_IP on interface $IFACE"

# --- keys and secrets (kept across re-runs) ---------------------------------
umask 077
[[ -s $STATE/wg.key ]] || wg genkey > "$STATE/wg.key"
SERVER_PUB=$(wg pubkey < "$STATE/wg.key")
[[ -s $STATE/ss.password ]] || head -c 24 /dev/urandom | base64 | tr -d '\n' > "$STATE/ss.password"
SS_PASSWORD=$(cat "$STATE/ss.password")
umask 022

# --- kernel ------------------------------------------------------------------
cat > /etc/sysctl.d/99-slipstream.conf <<EOF
net.ipv4.ip_forward = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
sysctl -q --system || true

# --- WireGuard ---------------------------------------------------------------
log "configuring WireGuard on UDP $WG_PORT"
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = ${WG_NET}.1/24
ListenPort = ${WG_PORT}
PrivateKey = $(cat "$STATE/wg.key")
MTU = 1420

[Peer]
# Slipstream device
PublicKey = ${CLIENT_PUB}
AllowedIPs = ${WG_NET}.2/32
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl enable -q wg-quick@wg0
systemctl restart wg-quick@wg0

# --- Shadowsocks -------------------------------------------------------------
log "configuring Shadowsocks on TCP+UDP $SS_PORT"
if [[ -z "${SS_RUST:-}" ]]; then
  cat > /etc/shadowsocks-libev/config.json <<EOF
{
  "server": ["0.0.0.0"],
  "server_port": ${SS_PORT},
  "password": "${SS_PASSWORD}",
  "method": "chacha20-ietf-poly1305",
  "mode": "tcp_and_udp",
  "timeout": 300
}
EOF
  systemctl enable -q shadowsocks-libev
  systemctl restart shadowsocks-libev
else
  cat > "$STATE/ss.json" <<EOF
{"server":"0.0.0.0","server_port":${SS_PORT},"password":"${SS_PASSWORD}","method":"chacha20-ietf-poly1305","mode":"tcp_and_udp","timeout":300}
EOF
  chmod 600 "$STATE/ss.json"
  cat > /etc/systemd/system/slipstream-ss.service <<EOF
[Unit]
Description=Slipstream Shadowsocks
After=network-online.target
[Service]
ExecStart=/usr/local/bin/ssserver -c $STATE/ss.json
Restart=always
DynamicUser=yes
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable -q --now slipstream-ss
  systemctl restart slipstream-ss
fi

# --- health echo port (what the app's latency probe measures) ---------------
log "starting the UDP echo health port on $ECHO_PORT"
cat > /usr/local/bin/slipstream-echo <<'EOF'
#!/usr/bin/env python3
# Echoes small UDP datagrams back to the sender. Replies are never larger
# than the request, so the port cannot amplify traffic toward a spoofed source.
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
while True:
    data, addr = s.recvfrom(65)
    if 0 < len(data) <= 64:
        s.sendto(data, addr)
EOF
chmod 755 /usr/local/bin/slipstream-echo
cat > /etc/systemd/system/slipstream-echo.service <<EOF
[Unit]
Description=Slipstream UDP echo health port
After=network-online.target
[Service]
ExecStart=/usr/local/bin/slipstream-echo ${ECHO_PORT}
Restart=always
DynamicUser=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q slipstream-echo
systemctl restart slipstream-echo

# --- host firewall -----------------------------------------------------------
# Oracle's Ubuntu images ship iptables rules that reject everything except SSH,
# in INPUT and FORWARD, so the cloud security rules alone are not enough.
log "opening the host firewall and enabling NAT"
add_rule() { iptables -C "$@" 2>/dev/null || iptables -I "$@"; }
add_rule INPUT -p udp --dport $WG_PORT -j ACCEPT
add_rule INPUT -p udp --dport $ECHO_PORT -j ACCEPT
add_rule INPUT -p tcp --dport $SS_PORT -j ACCEPT
add_rule INPUT -p udp --dport $SS_PORT -j ACCEPT
add_rule FORWARD -i wg0 -j ACCEPT
add_rule FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -C POSTROUTING -s ${WG_NET}.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s ${WG_NET}.0/24 -o "$IFACE" -j MASQUERADE
# Clamp TCP MSS to the tunnel MTU so large downloads don't stall.
iptables -t mangle -C FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
  || iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
if command -v netfilter-persistent >/dev/null; then
  netfilter-persistent save >/dev/null 2>&1 || true
else
  apt-get install -y -qq iptables-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
fi

# --- checks --------------------------------------------------------------------
sleep 1
ok=1
wg show wg0 >/dev/null 2>&1 || { log "WARNING: WireGuard is not running"; ok=0; }
ss -lntu | grep -q ":$SS_PORT " || { log "WARNING: Shadowsocks is not listening"; ok=0; }
ss -lnu | grep -q ":$ECHO_PORT " || { log "WARNING: echo port is not listening"; ok=0; }
[[ $ok == 1 ]] && log "all services running"

# --- the location file for the client ----------------------------------------
ID=$(echo "$LOCATION_NAME" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/-*$//')
cat > "$STATE/location.json" <<EOF
{
  "id": "${ID}",
  "name": "${LOCATION_NAME}",
  "country": "${COUNTRY}",
  "public_ip": "${PUBLIC_IP}",
  "config": {
    "servers": [
      {
        "name": "${ID}-wireguard",
        "protocol": "wireguard",
        "endpoint": "${PUBLIC_IP}:${WG_PORT}",
        "public_key": "${SERVER_PUB}",
        "keepalive_seconds": 25
      },
      {
        "name": "${ID}-shadowsocks",
        "protocol": "shadowsocks",
        "endpoint": "${PUBLIC_IP}:${SS_PORT}",
        "method": "chacha20-ietf-poly1305",
        "password": "${SS_PASSWORD}",
        "plugins": [{"type": "tlsfrag", "label": "sni-split"}]
      }
    ],
    "tunnel_addresses": ["${WG_NET}.2/32"],
    "dns_servers": ["1.1.1.1", "8.8.8.8"],
    "mtu": 1420,
    "race_stagger_ms": 400
  }
}
EOF
chmod 600 "$STATE/location.json"
log "done. Location file follows (also saved to $STATE/location.json):"
cat "$STATE/location.json"
