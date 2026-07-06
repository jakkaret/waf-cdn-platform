#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${GEODNS_DOMAIN:-cdn.local}"
PATH_TO_TEST="${1:-/dvwa/images/login_logo.png}"

run_probe() {
  local zone="$1"
  local client_ip="$2"
  local dns_ip="$3"
  local network="cdn_cdn-net"

  echo "[probe-${zone}] network=${network} client_ip=${client_ip} dns=${dns_ip}"
  docker run --rm \
    --network "${network}" \
    --ip "${client_ip}" \
    --dns "${dns_ip}" \
    curlimages/curl:8.8.0 \
    -sS -o /dev/null -D - "http://${DOMAIN}${PATH_TO_TEST}" \
    | tr -d '\r' | awk -F': ' '/^HTTP\/|^X-Edge-Region:/ {print $0}'
  echo
}

run_probe SG 172.28.11.10 172.28.0.53
run_probe JP 172.28.22.10 172.28.0.53
run_probe TH 172.28.33.10 172.28.0.53
