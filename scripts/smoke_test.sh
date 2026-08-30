#!/usr/bin/env bash
# Smoke test for the WAF + CDN platform.
#
# Run before and after any change that touches routing, rules, auth, or the
# control plane. Checks are split into two groups:
#
#   INVARIANTS    - must pass at all times. A failure here is a regression.
#   SECURITY GATES - target state from the Week 0 stabilisation work. These
#                    are expected to fail until the corresponding task lands.
#
# Usage:  scripts/smoke_test.sh [--quiet]
# Exit:   0 if all INVARIANTS pass, 1 otherwise. Gate failures are reported
#         but do not affect the exit code, so this stays usable as a
#         regression gate while the security work is still in progress.

set -uo pipefail

EDGE_IP="${EDGE_IP:-45.154.26.91}"
MAIN_IP="${MAIN_IP:-178.104.53.123}"
DASH_HOST="${DASH_HOST:-waf-it-kku.online}"
SITE_HOST="${SITE_HOST:-dvwa.waf-it-kku.online}"
TIMEOUT="${TIMEOUT:-15}"

CURL="$(command -v curl)"
inv_pass=0; inv_fail=0
gate_pass=0; gate_fail=0

c_ok=$'\033[32m'; c_bad=$'\033[31m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[ -t 1 ] || { c_ok=""; c_bad=""; c_dim=""; c_off=""; }

code() { "$CURL" -sk -m "$TIMEOUT" -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }

# check <group> <description> <expected> <actual>
check() {
  local group="$1" desc="$2" want="$3" got="$4"
  if [ "$got" = "$want" ]; then
    printf "  ${c_ok}PASS${c_off}  %-52s %s\n" "$desc" "$got"
    [ "$group" = inv ] && inv_pass=$((inv_pass+1)) || gate_pass=$((gate_pass+1))
  else
    printf "  ${c_bad}FAIL${c_off}  %-52s got=%s want=%s\n" "$desc" "$got" "$want"
    [ "$group" = inv ] && inv_fail=$((inv_fail+1)) || gate_fail=$((gate_fail+1))
  fi
}

# check_not <group> <description> <forbidden> <actual>
check_not() {
  local group="$1" desc="$2" forbid="$3" got="$4"
  if [ "$got" != "$forbid" ]; then
    printf "  ${c_ok}PASS${c_off}  %-52s %s\n" "$desc" "$got"
    [ "$group" = inv ] && inv_pass=$((inv_pass+1)) || gate_pass=$((gate_pass+1))
  else
    printf "  ${c_bad}FAIL${c_off}  %-52s got=%s (must not be %s)\n" "$desc" "$got" "$forbid"
    [ "$group" = inv ] && inv_fail=$((inv_fail+1)) || gate_fail=$((gate_fail+1))
  fi
}

echo "=============================================================="
echo " WAF + CDN smoke test — $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo " edge=$EDGE_IP  main=$MAIN_IP"
echo "=============================================================="

# ---------------------------------------------------------------- INVARIANTS
echo
echo "INVARIANTS (a failure here is a regression)"
echo "${c_dim}-- WAF blocking ------------------------------------------${c_off}"

check inv "SQLi  (UNION SELECT) blocked"      403 "$(code "https://$SITE_HOST/?id=1%27%20UNION%20SELECT%201,2,3--")"
check inv "XSS   (script tag) blocked"        403 "$(code "https://$SITE_HOST/?q=%3Cscript%3Ealert(1)%3C/script%3E")"
check inv "Path traversal blocked"            403 "$(code "https://$SITE_HOST/?f=../../../../etc/passwd")"
check inv "Command injection blocked"         403 "$(code "https://$SITE_HOST/?cmd=;cat%20/etc/passwd")"
check inv "Custom rule 1000001 (testattack)"  403 "$(code "https://$SITE_HOST/testattack")"
check inv "Custom rule 990001 (sync probe)"   403 "$(code "https://$SITE_HOST/test-waf-sync-rule")"
check inv "Custom rule 123 (testpj)"          403 "$(code "https://$SITE_HOST/testpj")"

echo "${c_dim}-- No over-broad rule (regression guard for rule 123) -----${c_off}"
check_not inv "/latest not blocked"        403 "$(code "https://$SITE_HOST/latest")"
check_not inv "/contest not blocked"       403 "$(code "https://$SITE_HOST/contest")"
check_not inv "/testimonials not blocked"  403 "$(code "https://$SITE_HOST/testimonials")"

echo "${c_dim}-- Dashboard reachability --------------------------------${c_off}"
check inv "Dashboard root over HTTPS"       200 "$(code "https://$DASH_HOST/")"
check inv "Dashboard over direct IP"        200 "$(code "http://$MAIN_IP/")"
check inv "Backend API docs reachable"      200 "$(code "http://$MAIN_IP:8000/docs")"
check inv "Backend health endpoint"         200 "$(code "http://$MAIN_IP:8000/api/health")"

echo "${c_dim}-- Auth is enforced --------------------------------------${c_off}"
check inv "GET /api/origins without token"  401 "$(code "http://$MAIN_IP:8000/api/origins")"
check inv "GET /api/rules/ without token"   401 "$(code "http://$MAIN_IP:8000/api/rules/")"

echo "${c_dim}-- Edge behaviour ----------------------------------------${c_off}"
check inv "Edge healthz"                    200 "$(code "https://$SITE_HOST/healthz")"

# /healthz is a `return 200` block, so it does not inherit the add_header
# directives from `location /`. The region is in its JSON body instead.
health_region="$("$CURL" -sk -m "$TIMEOUT" "https://$SITE_HOST/healthz" 2>/dev/null \
  | sed -n 's/.*"region"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
check inv "Edge healthz reports its region" TH "${health_region:-missing}"

# Normal paths do go through `location /`, which sets the edge headers.
edge_hdrs="$("$CURL" -sk -m "$TIMEOUT" -D - -o /dev/null "https://$SITE_HOST/latest" 2>/dev/null)"
region="$(printf '%s' "$edge_hdrs" | grep -i '^x-edge-region:' | tr -d '\r' | awk '{print $2}')"
check inv "Edge sets X-Edge-Region header"  TH "${region:-missing}"
cache_hdr="$(printf '%s' "$edge_hdrs" | grep -ic '^x-cache-status:' || true)"
check inv "Edge sets X-Cache-Status header" 1 "$cache_hdr"

echo "${c_dim}-- TLS ---------------------------------------------------${c_off}"
check inv "Dashboard passes strict TLS"     200 "$("$CURL" -s -m "$TIMEOUT" -o /dev/null -w '%{http_code}' "https://$DASH_HOST/" 2>/dev/null)"
dash_issuer="$(echo | openssl s_client -connect "$DASH_HOST:443" -servername "$DASH_HOST" 2>/dev/null \
  | openssl x509 -noout -issuer 2>/dev/null)"
case "$dash_issuer" in
  *"Let's Encrypt"*|*ZeroSSL*) check inv "Dashboard cert from a public CA" ok ok ;;
  *)                           check inv "Dashboard cert from a public CA" ok "${dash_issuer:-none}" ;;
esac

# ------------------------------------------------------------ SECURITY GATES
echo
echo "SECURITY GATES (target state — may fail until the fix lands)"
echo "${c_dim}-- Control plane must not be reachable from the internet --${c_off}"
check_not gate "T4: /api/sync/bundle not public"  200 "$(code "http://$MAIN_IP:8070/api/sync/bundle")"
check_not gate "T4: /api/blocklist not public"    200 "$(code "http://$MAIN_IP:8070/api/blocklist")"
check_not gate "T4: control-api /docs not public" 200 "$(code "http://$MAIN_IP:8070/docs")"

echo "${c_dim}-- No secrets in the public JS bundle ---------------------${c_off}"
bundle_path="$("$CURL" -sk -m "$TIMEOUT" "http://$MAIN_IP:8000/" 2>/dev/null \
  | grep -oE '/assets/[A-Za-z0-9._-]+\.js' | head -1)"
if [ -n "$bundle_path" ]; then
  bundle="$("$CURL" -sk -m 30 "http://$MAIN_IP:8000$bundle_path" 2>/dev/null)"
  for secret in WAF_SECURE_TUNNEL_2026_TOKEN cdn-secret-token; do
    hits="$(printf '%s' "$bundle" | grep -c "$secret" || true)"
    check gate "T5: '$secret' absent from bundle" 0 "$hits"
  done
else
  printf "  ${c_bad}FAIL${c_off}  %-52s %s\n" "T5: could not locate JS bundle" "no asset link found"
  gate_fail=$((gate_fail+1))
fi

echo "${c_dim}-- Injection guard ---------------------------------------${c_off}"
# A quote in the time range must not produce a 500. Note this check is weak on
# its own: unauthenticated it returns 401 and never reaches the query layer, so
# it passes for the wrong reason. The authenticated version of this test lives
# in the pytest suite, which can mint a token. Keep this here as a crash guard.
sqli_code="$("$CURL" -sk -m "$TIMEOUT" -o /dev/null -w '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -d '{"start_time":"2026-01-01 00:00:00'"'"'","end_time":"2026-01-02 00:00:00"}' \
  "http://$MAIN_IP:8000/api/ai/summarize-range" 2>/dev/null)"
check_not gate "T6: quote in time range does not 500" 500 "$sqli_code"

# --------------------------------------------------------------------- TOTAL
echo
echo "=============================================================="
printf " INVARIANTS      %s%d passed%s, %s%d failed%s\n" "$c_ok" "$inv_pass" "$c_off" \
  "$([ "$inv_fail" -gt 0 ] && echo "$c_bad" || echo "$c_ok")" "$inv_fail" "$c_off"
printf " SECURITY GATES  %s%d passed%s, %d failed\n" "$c_ok" "$gate_pass" "$c_off" "$gate_fail"
echo "=============================================================="

if [ "$inv_fail" -gt 0 ]; then
  echo "REGRESSION: an invariant broke. Investigate before continuing."
  exit 1
fi
echo "All invariants hold."
exit 0
