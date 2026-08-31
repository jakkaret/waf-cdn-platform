#!/usr/bin/env bash
# End-to-end test suite for the CloudWAF private tunnel.
#
# Covers the full chain (public HTTPS -> Caddy -> ModSecurity -> tunnel server
# -> agent -> private origin) plus the credential, transport and resilience
# properties the tunnel is supposed to provide.
#
# Requires SSH access to the WAF node; agent-side checks additionally need
# LAB_SSH to point at a helper that runs a command on the private origin host.
#
# Usage: tunnel/test_tunnel.sh
# Exit:  0 if every test passes.

set -uo pipefail

MAIN="${MAIN_IP:-178.104.53.123}"
MAIN_SSH="${MAIN_SSH:-ssh -o BatchMode=yes -o ConnectTimeout=15 root@$MAIN}"
LAB_SSH="${LAB_SSH:-}"                       # optional helper for the origin host
TUNNEL_HOST="${TUNNEL_HOST:-vampi.waf-it-kku.online}"
FRP_HOST="${FRP_HOST:-juice.waf-it-kku.online}"
CURL="$(command -v curl)"

pass=0; fail=0; skip=0
c_ok=$'\033[32m'; c_bad=$'\033[31m'; c_skip=$'\033[33m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[ -t 1 ] || { c_ok=""; c_bad=""; c_skip=""; c_dim=""; c_off=""; }

ok()   { printf "  ${c_ok}PASS${c_off}  %-56s %s\n" "$1" "${2:-}"; pass=$((pass+1)); }
bad()  { printf "  ${c_bad}FAIL${c_off}  %-56s %s\n" "$1" "${2:-}"; fail=$((fail+1)); }
skipt(){ printf "  ${c_skip}SKIP${c_off}  %-56s %s\n" "$1" "${2:-}"; skip=$((skip+1)); }
head() { printf "\n${c_dim}%s${c_off}\n" "$1"; }

code()  { "$CURL" -sk -m "${2:-20}" -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }
body()  { "$CURL" -sk -m "${2:-20}" "$1" 2>/dev/null; }
expect(){ [ "$3" = "$2" ] && ok "$1" "$2" || bad "$1" "got=$2 want=$3"; }
refute(){ [ "$3" != "$2" ] && ok "$1" "$2" || bad "$1" "got=$2 (must not be $3)"; }

echo "=============================================================="
echo " CloudWAF private tunnel — test suite"
echo " $(date '+%Y-%m-%d %H:%M:%S %Z')   tunnel host: $TUNNEL_HOST"
echo "=============================================================="

# --------------------------------------------------------------- reachability
head "1. The private origin is reachable through the tunnel"

expect "public HTTPS reaches the private origin" "$(code "https://$TUNNEL_HOST/")" 200
if body "https://$TUNNEL_HOST/" | grep -q "VAmPI"; then
  ok "response body comes from the origin app" "VAmPI"
else
  bad "response body comes from the origin app" "marker not found"
fi
expect "an origin API path is proxied" "$(code "https://$TUNNEL_HOST/users/v1")" 200
expect "unknown origin path returns the origin's own 404" "$(code "https://$TUNNEL_HOST/definitely-not-here")" 404

head "2. Requests really traverse the WAF before the tunnel"
expect "SQLi is blocked before reaching the tunnel"  "$(code "https://$TUNNEL_HOST/?id=1%27%20UNION%20SELECT%201,2,3--")" 403
expect "XSS is blocked"                              "$(code "https://$TUNNEL_HOST/?q=%3Cscript%3Ealert(1)%3C/script%3E")" 403
expect "path traversal is blocked"                   "$(code "https://$TUNNEL_HOST/?f=../../../../etc/passwd")" 403
expect "command injection is blocked"                "$(code "https://$TUNNEL_HOST/?cmd=;cat%20/etc/passwd")" 403
expect "custom rule still applies on this host"      "$(code "https://$TUNNEL_HOST/testattack")" 403

head "3. The origin is not reachable except through the WAF"
# Probe from the WAF node, which sits on the public internet. Probing from a
# workstation that is already on the origin's private network would prove
# nothing: the point is that the wider internet has no route to it.
direct="$($MAIN_SSH "curl -s -m 8 -o /dev/null -w '%{http_code}' http://10.198.200.75:5000/" 2>/dev/null)"
if [ "$direct" = "000" ]; then
  ok "origin port unreachable from the public internet" "no route"
else
  bad "origin port unreachable from the public internet" "got=$direct — origin is exposed"
fi

# ---------------------------------------------------------------- credentials
head "4. Agent credentials"

verify() {
  "$CURL" -s -m 12 -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -d "$1" \
    "http://$MAIN:8000/api/tunnel/verify-agent" 2>/dev/null
}
expect "empty token is rejected"            "$(verify '{"token":"","domains":["x.example.com"]}')" 401
expect "malformed token is rejected"        "$(verify '{"token":"not-a-token","domains":["x.example.com"]}')" 401
expect "unknown origin id is rejected"      "$(verify '{"token":"cwt_00000000-0000-0000-0000-000000000000_deadbeef","domains":["x.example.com"]}')" 401
expect "right origin, wrong secret rejected" "$(verify '{"token":"cwt_dc2cb510-4f78-41be-8846-21b49ba42563_wrongsecret","domains":["'"$TUNNEL_HOST"'"]}')" 401
expect "issuing a token needs authentication" \
  "$("$CURL" -s -m 12 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
     -d '{"origin_id":"x","domains":["y"]}' "http://$MAIN:8000/api/tunnel/issue-token")" 401

if [ -n "${TUNNEL_TOKEN:-}" ]; then
  good_body="$(printf '{"token":"%s","domains":["%s"]}' "$TUNNEL_TOKEN" "$TUNNEL_HOST")"
  wrong_body="$(printf '{"token":"%s","domains":["attacker-controlled.example.com"]}' "$TUNNEL_TOKEN")"
  got="$(verify "$good_body")"
  expect "valid token is accepted" "$got" 200
  got="$(verify "$wrong_body")"
  expect "valid token, undelegated domain rejected" "$got" 401
else
  skipt "valid token accepted" "set TUNNEL_TOKEN to run"
  skipt "valid token, undelegated domain rejected" "set TUNNEL_TOKEN to run"
fi

# ------------------------------------------------------------------ transport
head "5. Transport security"

if echo | openssl s_client -connect "$MAIN:8050" -servername "$MAIN" 2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
  ok "agent listener speaks TLS" "certificate presented"
else
  bad "agent listener speaks TLS" "no certificate"
fi
proto="$(echo | openssl s_client -connect "$MAIN:8050" 2>/dev/null | grep -m1 'Protocol' | awk '{print $3}')"
case "$proto" in
  TLSv1.2|TLSv1.3) ok "negotiated protocol is modern" "$proto" ;;
  *)               bad "negotiated protocol is modern" "${proto:-unknown}" ;;
esac
# A plaintext client must not get a usable HTTP session out of the TLS listener.
# (`nc -w` rather than `timeout`, which is absent on macOS.)
plain="$(printf 'GET / HTTP/1.0\r\n\r\n' | nc -w 6 "$MAIN" 8050 2>/dev/null | head -c 64)"
if printf '%s' "$plain" | grep -q "HTTP/"; then
  bad "plaintext client gets no HTTP session from the TLS port" "server spoke HTTP"
else
  ok "plaintext client gets no HTTP session from the TLS port" "${plain:+TLS alert only}${plain:-connection dropped}"
fi

head "6. The vhost listener is not exposed to the internet"
vhost="$("$CURL" -s -m 8 -o /dev/null -w '%{http_code}' "http://$MAIN:8060/" 2>/dev/null)"
expect "tunnel vhost port is closed from outside" "$vhost" 000

# --------------------------------------------------------------------- status
head "7. Status reporting reflects reality"

state="$($MAIN_SSH 'cat /var/lib/cloudwaf-tunnel/state.json' 2>/dev/null)"
if [ -n "$state" ]; then
  agents="$(printf '%s' "$state" | python3 -c 'import sys,json;print(json.load(sys.stdin)["agent_count"])' 2>/dev/null)"
  [ "${agents:-0}" -ge 1 ] && ok "server reports a connected agent" "count=$agents" \
                           || bad "server reports a connected agent" "count=${agents:-none}"
  dom="$(printf '%s' "$state" | python3 -c 'import sys,json;print(",".join(json.load(sys.stdin)["agents"][0]["domains"]))' 2>/dev/null)"
  # The agent may legitimately serve more than one hostname (it now also
  # carries dvwa/juice/bwapp alongside vampi -- see Docs/15-Progress-Log.md,
  # 2026-08-31). The invariant this test protects is narrower: TUNNEL_HOST
  # must be *among* the registered domains, not the only one.
  case ",$dom," in
    *",$TUNNEL_HOST,"*) ok "registered domain matches" "$dom" ;;
    *) bad "registered domain matches" "got=${dom:-none}" ;;
  esac
  reqs="$(printf '%s' "$state" | python3 -c 'import sys,json;print(json.load(sys.stdin)["agents"][0]["requests"])' 2>/dev/null)"
  [ "${reqs:-0}" -ge 1 ] && ok "request counter advanced" "requests=$reqs" \
                         || bad "request counter advanced" "requests=${reqs:-0}"
else
  bad "state file is readable" "not found"
fi
expect "status endpoint requires authentication" \
  "$("$CURL" -s -m 12 -o /dev/null -w '%{http_code}' "http://$MAIN:8000/api/tunnel/status")" 401

# ----------------------------------------------------------------- resilience
head "8. Resilience"

if [ -n "$LAB_SSH" ]; then
  $LAB_SSH "systemctl restart cloudwaf-agent" >/dev/null 2>&1
  sleep 8
  expect "origin recovers after an agent restart" "$(code "https://$TUNNEL_HOST/")" 200
else
  skipt "origin recovers after an agent restart" "set LAB_SSH to run"
fi

$MAIN_SSH 'systemctl restart cloudwaf-tunnel' >/dev/null 2>&1
sleep 12
after="$(code "https://$TUNNEL_HOST/" 30)"
if [ "$after" = "200" ]; then
  ok "agent reconnects after a server restart" "200"
else
  sleep 10
  after="$(code "https://$TUNNEL_HOST/" 30)"
  expect "agent reconnects after a server restart" "$after" 200
fi

head "9. Behaviour when no agent serves a hostname"
unknown="$($MAIN_SSH "curl -s -m 8 -o /dev/null -w '%{http_code}' -H 'Host: nobody.waf-it-kku.online' http://172.18.0.1:8060/" 2>/dev/null)"
expect "unregistered hostname returns 502, not a hang" "$unknown" 502

# ------------------------------------------------------- no collateral damage
head "10. The FRP-backed hosts are unaffected"
expect "FRP host still serves"        "$(code "https://$FRP_HOST/")" 200
expect "FRP host still filtered"      "$(code "https://$FRP_HOST/?id=1%27%20UNION%20SELECT%201,2,3--")" 403
expect "dashboard still serves"       "$(code "https://waf-it-kku.online/")" 200

echo
echo "=============================================================="
printf " %s%d passed%s, %s%d failed%s, %d skipped\n" \
  "$c_ok" "$pass" "$c_off" \
  "$([ "$fail" -gt 0 ] && echo "$c_bad" || echo "$c_ok")" "$fail" "$c_off" "$skip"
echo "=============================================================="
[ "$fail" -eq 0 ] || exit 1
