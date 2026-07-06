#!/usr/bin/env bash
set -euo pipefail

API_URL="${CDN_PURGE_API_URL:-http://localhost:8090/purge}"
TOKEN="${CDN_PURGE_TOKEN:***REDACTED***}"
URL_PATH="${1:-}"
REGION="${2:-ALL}"

if [[ -z "$URL_PATH" ]]; then
  echo "Usage: $0 <url-or-uri> [region]"
  echo "Example: $0 /dvwa/images/login_logo.png SG"
  exit 1
fi

curl -sS -X POST "${API_URL}?url=${URL_PATH}&region=${REGION}" \
  -H "X-Purge-Token: ${TOKEN}" \
  -H "Content-Type: application/json"
echo
