#!/usr/bin/env bash
# WireGuard link between the CDN edges and Main (see README.md).
#
#   wg-setup.sh key                         install wireguard-tools, create this
#                                           host's key, print its PUBLIC key
#   wg-setup.sh main <edge-th-pub> <edge-asia-pub>
#   wg-setup.sh edge <10.88.0.2|10.88.0.3> <main-pub>
#
# The private key is created on the host itself (/etc/wireguard/wg0.key, 600)
# and never leaves it; wg0.conf loads it with PostUp, so the conf holds no
# secret. Run as root. Idempotent: re-running rewrites wg0.conf and restarts.
set -euo pipefail
umask 077

MAIN_PUBLIC_IP=178.104.53.123
MAIN_TUNNEL_IP=10.88.0.1
PORT=51820
CONF=/etc/wireguard/wg0.conf
KEY=/etc/wireguard/wg0.key

# Docker bridges have MTU 1500, wg0 1420: clamp TCP MSS on forwarded traffic
# leaving through the tunnel, or large responses stall while small ones work.
CLAMP="iptables -t mangle %s FORWARD -o %%i -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"

need_key() { [ -s "$KEY" ] || { echo "run '$0 key' first" >&2; exit 1; }; }
pub_ok()   { [[ "$1" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$ ]] || { echo "bad public key: $1" >&2; exit 1; }; }

interface() {  # $1 = address/prefix, $2 = extra lines
  printf '[Interface]\nAddress = %s\n%sPostUp = wg set %%i private-key %s\nPostUp = %s\nPostDown = %s\n' \
    "$1" "$2" "$KEY" "$(printf "$CLAMP" -A)" "$(printf "$CLAMP" -D)"
}

case "${1:-}" in
  key)
    command -v wg >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools >/dev/null; }
    mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
    [ -s "$KEY" ] || wg genkey > "$KEY"
    chmod 600 "$KEY"
    wg pubkey < "$KEY"
    ;;
  main)
    need_key; pub_ok "$2"; pub_ok "$3"
    {
      interface "$MAIN_TUNNEL_IP/24" "ListenPort = $PORT"$'\n'
      printf '\n[Peer]\n# edge-th 45.154.26.91\nPublicKey = %s\nAllowedIPs = 10.88.0.2/32\n' "$2"
      printf '\n[Peer]\n# edge-asia 57.158.25.236\nPublicKey = %s\nAllowedIPs = 10.88.0.3/32\n' "$3"
    } > "$CONF"
    ;;
  edge)
    need_key; pub_ok "$3"
    [[ "$2" == 10.88.0.2 || "$2" == 10.88.0.3 ]] || { echo "edge address must be 10.88.0.2 or 10.88.0.3" >&2; exit 1; }
    {
      interface "$2/24" ""
      printf '\n[Peer]\n# Main\nPublicKey = %s\nEndpoint = %s:%s\nAllowedIPs = %s/32\nPersistentKeepalive = 25\n' \
        "$3" "$MAIN_PUBLIC_IP" "$PORT" "$MAIN_TUNNEL_IP"
    } > "$CONF"
    ;;
  *)
    sed -n '2,11p' "$0"; exit 2 ;;
esac

if [ "$1" != key ]; then
  chmod 600 "$CONF"
  systemctl enable wg-quick@wg0 >/dev/null 2>&1
  systemctl restart wg-quick@wg0
  wg show wg0 | sed -n '1,3p'
fi
