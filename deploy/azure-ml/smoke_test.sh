#!/usr/bin/env bash
# Check every ML API endpoint the VPS uses, plus round-trip latency.
# Sends test requests only; changes nothing on either host (one temp file, removed on exit).
#
#   ML_URL=http://10.77.0.2:5000 ML_TOKEN=<token> bash smoke_test.sh
#   (on the VPS: set -a; . /etc/waf-ml-client.env; set +a; ML_URL=$ML_SERVICE_URL ML_TOKEN=$ML_SERVICE_TOKEN bash smoke_test.sh)
set -uo pipefail
URL="${ML_URL:?set ML_URL, e.g. http://10.77.0.2:5000}"
TOKEN="${ML_TOKEN:?set ML_TOKEN}"
H=(-H "X-WAF-ML-Token: $TOKEN" -H "Content-Type: application/json")
fail=0
TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT

check() {  # name expected_status actual_status body
  if [ "$2" = "$3" ]; then echo "  PASS  $1 ($3)"; else echo "  FAIL  $1: expected $2, got $3 ${4:-}"; fail=1; fi
}
post() { curl -sS -o "$TMP" -w '%{http_code}' --max-time 10 "${H[@]}" -d "$2" "$URL$1"; }

echo "ML API at $URL"
check "/health without token -> 401" 401 "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$URL/health")"
code=$(curl -sS -o "$TMP" -w '%{http_code}' --max-time 10 -H "X-WAF-ML-Token: $TOKEN" "$URL/health")
check "/health" 200 "$code"; echo "        $(cat "$TMP")"
check "/predict-fast (backend shadow relay)" 200 "$(post /predict-fast '{"url":"/items?id=1%27+UNION+SELECT+password+FROM+users--"}')"
echo "        $(head -c 200 "$TMP")"
check "/predict (dashboard ML Analyst)" 200 "$(post /predict '{"url":"/search?q=<script>alert(1)</script>"}')"
check "/generate-rule" 200 "$(post /generate-rule '{"url":"/items?id=1 union select 1","attack_type":"Anomaly Pattern"}')"
check "/capture" 204 "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -H "X-WAF-ML-Token: $TOKEN" -H 'X-Original-URI: /smoke' -d 'a=1' "$URL/capture")"
code=$(post /predict-gen3 '{"url":"/a?file=../../etc/passwd"}')
[ "$code" = 200 ] && echo "  PASS  /predict-gen3 (200) $(head -c 160 "$TMP")" \
                  || echo "  INFO  /predict-gen3 -> $code (Gen 3 model not installed yet?)"

echo "Latency of /predict-fast, 20 requests (includes network round trip):"
for _ in $(seq 20); do
  curl -sS -o /dev/null -w '%{time_total}\n' --max-time 10 "${H[@]}" -d '{"url":"/products?page=2"}' "$URL/predict-fast"
done | sort -n | awk '{a[NR]=$1} END {printf "        p50 %.1f ms | max %.1f ms  (ML_FAST_TIMEOUT should be >= 3x p50)\n", a[int(NR/2)+1]*1000, a[NR]*1000}'
[ "$fail" = 0 ] && echo "ALL PASS" || { echo "SOME CHECKS FAILED"; exit 1; }
