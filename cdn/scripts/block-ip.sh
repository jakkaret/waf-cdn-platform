#!/usr/bin/env bash
set -euo pipefail

CONTROL_API_HOST="${CONTROL_API_HOST:-http://localhost:8070}"
TOKEN="${CDN_CONTROL_TOKEN:***REDACTED***}"
IP="${1:-}"
SOURCE="${2:-manual}"

if [[ -z "$IP" ]]; then
  echo "Usage: $0 <ip-or-cidr> [source]" >&2
  exit 1
fi

curl -sS -X POST "${CONTROL_API_HOST}/api/blocklist" \
  -H "X-Control-Token: ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${IP}\",\"source\":\"${SOURCE}\"}" 

echo
