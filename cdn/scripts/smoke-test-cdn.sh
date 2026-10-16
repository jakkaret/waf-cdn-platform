#!/usr/bin/env bash
set -euo pipefail

EDGE_SG="${EDGE_SG:-http://localhost:8081}"
EDGE_JP="${EDGE_JP:-http://localhost:8082}"
EDGE_TH="${EDGE_TH:-http://localhost:8086}"
TARGET_PATH="${1:-/dvwa/images/login_logo.png}"

check_health() {
  local name="$1" url="$2"
  local out
  out=$(curl -fsS "${url}/healthz")
  echo "[health] ${name}: ${out}"
}

cache_status() {
  local url="$1"
  curl -sSI "${url}${TARGET_PATH}" | tr -d '\r' | awk -F': ' '/^X-Cache-Status:/ {print $2}'
}

run_cache_flow() {
  local name="$1" url="$2"
  local first second
  first=$(cache_status "$url")
  second=$(cache_status "$url")
  echo "[cache] ${name}: first=${first:-N/A}, second=${second:-N/A}"
}

echo "== CDN health checks =="
check_health SG "$EDGE_SG"
check_health JP "$EDGE_JP"
check_health TH "$EDGE_TH"

echo "== Cache MISS/HIT checks =="
run_cache_flow SG "$EDGE_SG"
run_cache_flow JP "$EDGE_JP"
run_cache_flow TH "$EDGE_TH"
# No purge check: the purge-api service was removed (audit H13, 2026-10-16).
