#!/usr/bin/env bash
# End-to-end checks against the running simulation, from the client machine
# (a visitor on the public networks). Prints PASS/FAIL per check; exit code
# = number of failures.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
C=(docker compose exec -T client)
M=(docker compose exec -T main)
EDGE_TH=45.154.26.91
EDGE_ASIA=57.158.25.236
MAIN=178.104.53.123
SITE=dvwa.waf-it-kku.online
fails=0

check() {  # check <name> <expected> <actual>
  if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1 (expected '$2', got '$3')"; fails=$((fails + 1)); fi
}
status() {  # status <edge ip> <path> [curl args...]: HTTP status via that edge
  local ip=$1 path=$2; shift 2
  "${C[@]}" curl -s -o /dev/null -w '%{http_code}' --max-time 15 -H "Host: $SITE" "$@" "http://$ip$path"
}
header() {  # header <name> <edge ip> <path>
  "${C[@]}" curl -s -o /dev/null -D - --max-time 15 -H "Host: $SITE" "http://$2$3" \
    | tr -d '\r' | awk -v h="$(echo "$1" | tr 'A-Z' 'a-z')" -F': ' 'tolower($1) == h { print $2 }'
}
dig_a() {  # dig_a <server> <name> [dig args...]
  local server=$1 name=$2; shift 2
  "${C[@]}" dig +short +time=2 +tries=1 @"$server" "$name" "$@" | sort | tr '\n' ' ' | sed 's/ $//'
}

# Precondition: both edges reach Main. PowerDNS starts health-checking a LUA
# record's URLs at the first query for it and answers with the backup set
# until that first check is done, so ask each server once, then wait.
for ip in $EDGE_TH $EDGE_ASIA; do
  for _ in $(seq 1 60); do
    "${C[@]}" curl -fsS --max-time 3 -H 'Host: cdn.waf-it-kku.online' "http://$ip/healthz/deep" 2>/dev/null | grep -q OK && break
    sleep 2
  done
  "${C[@]}" dig +short +time=2 +tries=1 @"$ip" x.cdn.waf-it-kku.online >/dev/null
done
sleep 10

echo "== GeoDNS (PowerDNS on both edges)"
check "Thai visitor -> edge-th"     "$EDGE_TH"   "$(dig_a $EDGE_TH x.cdn.waf-it-kku.online +subnet=1.46.0.0/24)"
check "US visitor -> edge-asia"     "$EDGE_ASIA" "$(dig_a $EDGE_ASIA x.cdn.waf-it-kku.online +subnet=8.8.8.0/24)"
check "both edges give one answer"  "$(dig_a $EDGE_TH x.cdn.waf-it-kku.online +subnet=8.8.8.0/24)" \
                                    "$(dig_a $EDGE_ASIA x.cdn.waf-it-kku.online +subnet=8.8.8.0/24)"
check "no recursion (google.com)"   "status: REFUSED" \
  "$("${C[@]}" dig +time=2 +tries=1 @$EDGE_TH google.com | grep -o 'status: REFUSED')"

echo "== Site through each edge -> Main WAF -> FRP -> lab DVWA"
check "edge-th serves the site"     200 "$(status $EDGE_TH /login.php)"
check "edge-asia serves the site"   200 "$(status $EDGE_ASIA /login.php)"
check "edge region header (th)"     edge-th "$(header X-Edge-Region $EDGE_TH /login.php)"

echo "== WAF blocking"
check "SQLi blocked at the edge"    403 "$(status $EDGE_TH "/login.php?id=1%27%20OR%201=1--")"
check "XSS blocked at the edge"     403 "$(status $EDGE_ASIA "/?q=%3Cscript%3Ealert(1)%3C/script%3E")"

echo "== Edge cache and purge"
asset="/dvwa/css/main.css"
status $EDGE_TH "$asset" >/dev/null
check "static file cached (2nd = HIT)" HIT "$(header X-Cache-Status $EDGE_TH "$asset")"
# Queue a purge the way POST /api/cdn/purge does (services/cdn_purge.py),
# then wait for edge-th's rulesync loop to apply it.
"${M[@]}" docker exec -w /root/waf_project/dashboard/backend waf-dashboard python -c "
from dotenv import load_dotenv, find_dotenv; load_dotenv(find_dotenv(usecwd=True))
from services import cdn_purge
print(cdn_purge.enqueue('$SITE', '$asset'))" >/dev/null 2>&1 \
  || echo "      (could not queue the purge through services.cdn_purge)"
sleep 12
check "after purge (= MISS)"        MISS "$(header X-Cache-Status $EDGE_TH "$asset")"

echo "== Rule sync (control-api -> edges, signed bundle)"
for e in edge-th edge-asia; do
  v=$(docker compose exec -T "$e" docker exec cdn-edge-node cat /var/lib/rulesync/version 2>/dev/null | tr -d '\r')
  check "$e runs a signed bundle"   yes "$([ -n "$v" ] && [ "$v" -gt 0 ] 2>/dev/null && echo yes || echo "no (version '$v')")"
done

echo "== Main"
check "dashboard /api/health"       200 "$("${C[@]}" curl -s -o /dev/null -w '%{http_code}' -H "Host: $MAIN" http://$MAIN/api/health)"
check "unknown Host on Main refused" 403 "$("${C[@]}" curl -s -o /dev/null -w '%{http_code}' -H "Host: $SITE" http://$MAIN/)"
last=$("${M[@]}" sh -c "grep '\"host\":\"$SITE\"' /root/waf_project/logs/nginx/access.json | tail -n 1")
check "Main sees the visitor, not the edge" yes \
  "$(echo "$last" | grep -q '"remote_addr":"45.154.26.10"\|"remote_addr":"57.158.25.10"' && echo yes || echo "no: $(echo "$last" | jq -r .remote_addr 2>/dev/null)")"

echo "== GeoDNS failover"
docker compose exec -T edge-asia docker stop cdn-edge-node >/dev/null
sleep 8
check "edge-asia down -> US visitor gets edge-th" "$EDGE_TH" "$(dig_a $EDGE_TH x.cdn.waf-it-kku.online +subnet=8.8.8.0/24)"
docker compose exec -T edge-asia docker start cdn-edge-node >/dev/null
sleep 20
check "edge-asia back -> US visitor gets edge-asia" "$EDGE_ASIA" "$(dig_a $EDGE_TH x.cdn.waf-it-kku.online +subnet=8.8.8.0/24)"

echo
[ "$fails" -eq 0 ] && echo "all checks passed" || echo "$fails check(s) failed"
exit "$fails"
