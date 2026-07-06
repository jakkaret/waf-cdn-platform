#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CDN_DIR="${ROOT_DIR}/cdn"

CONTROL_TOKEN="${CDN_CONTROL_TOKEN:***REDACTED***}"
SYNC_WAIT_SEC="${CDN_SYNC_WAIT_SEC:-8}"

EDGE_SG_HOST="${EDGE_SG_HOST:-http://localhost:8081}"
EDGE_JP_HOST="${EDGE_JP_HOST:-http://localhost:8082}"
EDGE_TH_HOST="${EDGE_TH_HOST:-http://localhost:8086}"

CONTROL_API_HOST="${CONTROL_API_HOST:-http://localhost:8070}"

log() { printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"; }

log "Start origin (dvwa)"
cd "${ROOT_DIR}"
docker compose up -d dvwa >/dev/null

log "Start CDN stack"
cd "${CDN_DIR}"
docker compose -f docker-compose-cdn.yml up -d --build >/dev/null

log "Wait edges healthy"
for name in cdn-edge-sg cdn-edge-jp cdn-edge-th; do
  for i in {1..30}; do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo "")
    if [[ "$status" == "healthy" ]]; then
      break
    fi
    sleep 1
  done
  status=$(docker inspect -f '{{.State.Health.Status}}' "$name" 2>/dev/null || echo "")
  echo "edge ${name} health=${status}"
  [[ "$status" == "healthy" ]]
done

log "Smoke test cache/purge"
./scripts/smoke-test-cdn.sh

log "GeoDNS routing test"
./scripts/test-geodns-routing.sh

log "Control API health"
curl -fsS "${CONTROL_API_HOST}/healthz" >/dev/null

log "Rule sync sanity: custom rule blocks /testattack"
code=$(curl -sS -o /dev/null -w '%{http_code}' "${EDGE_SG_HOST}/testattack")
echo "SG /testattack => ${code}"
[[ "$code" == "403" ]]

log "Global blocklist sync test"
BLOCK_IP="172.28.55.55"

curl -fsS -X POST "${CONTROL_API_HOST}/api/blocklist" \
  -H "X-Control-Token: ${CONTROL_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${BLOCK_IP}\",\"source\":\"phase5-test\"}" >/dev/null

log "Wait sync ${SYNC_WAIT_SEC}s"
sleep "${SYNC_WAIT_SEC}"

for edge_ip in 172.28.0.11 172.28.0.12 172.28.0.13; do
  code=$(docker run --rm --network cdn_cdn-net --ip "${BLOCK_IP}" curlimages/curl:8.8.0 \
    -sS -o /dev/null -w '%{http_code}' "http://${edge_ip}/healthz" || true)
  echo "blocked client -> edge ${edge_ip} => ${code}"
  [[ "$code" == "403" ]]
done

curl -fsS -X DELETE "${CONTROL_API_HOST}/api/blocklist/${BLOCK_IP}" \
  -H "X-Control-Token: ${CONTROL_TOKEN}" >/dev/null

log "Wait sync ${SYNC_WAIT_SEC}s"
sleep "${SYNC_WAIT_SEC}"

for edge_ip in 172.28.0.11 172.28.0.12 172.28.0.13; do
  code=$(docker run --rm --network cdn_cdn-net --ip "${BLOCK_IP}" curlimages/curl:8.8.0 \
    -sS -o /dev/null -w '%{http_code}' "http://${edge_ip}/healthz" || true)
  echo "unblocked client -> edge ${edge_ip} => ${code}"
  [[ "$code" == "200" ]]
done

log "Phase 5 test all PASSED"
