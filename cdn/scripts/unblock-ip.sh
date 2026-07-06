#!/usr/bin/env bash
set -euo pipefail

CONTROL_API_HOST="${CONTROL_API_HOST:-http://localhost:8070}"
TOKEN="${CDN_CONTROL_TOKEN:***REDACTED***}"
IP="${1:-}"

if [[ -z "$IP" ]]; then
  echo "Usage: $0 <ip-or-cidr>" >&2
  exit 1
fi

curl -sS -X DELETE "${CONTROL_API_HOST}/api/blocklist/${IP}" \
  -H "X-Control-Token: ${TOKEN}"

echo
