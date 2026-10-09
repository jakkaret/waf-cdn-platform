#!/usr/bin/env bash
# Measure the Gen 3 model's detection with 3 standard WAF-testing tools, on a
# LOCAL harness only. Defensive evaluation of your own model — never point this
# at the production VPS or any host you do not own.
#
#   TOOLS=~/.cache/wafprobe/tools bash ml/security_test/run_tests.sh
#
# Expects the harness already running on $TARGET (see waf_test_harness.py) and
# the tools present: $TOOLS/gotestwaf (+ its source checkout in $GTW_SRC for
# config.yaml and testcases/), $TOOLS/nuclei, $TOOLS/sqlmap/sqlmap.py.
# Before each tool, the harness log's line count is appended to reports/marks.txt
# so summarize.py can attribute every decision to the tool that sent it.
set -uo pipefail
TARGET="${TARGET:-http://127.0.0.1:8088}"
TOOLS="${TOOLS:-$HOME/.cache/wafprobe/tools}"
GTW_SRC="${GTW_SRC:-$TOOLS/gotestwaf-src}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="${WAF_TEST_LOG:-$HERE/decisions.jsonl}"
OUT="$HERE/reports"; mkdir -p "$OUT/gotestwaf"
RL="${RL:-25}"   # requests/sec cap — keep the local box responsive
mark() { echo "$1 $( [ -f "$LOG" ] && wc -l < "$LOG" || echo 0 )" >> "$OUT/marks.txt"; }
: > "$OUT/marks.txt"

echo "== target $TARGET"; curl -s "$TARGET/healthz"; echo

# 1) GoTestWAF — purpose-built WAF efficacy benchmark (its own malicious + benign corpus).
if [ -x "$TOOLS/gotestwaf" ] && [ -f "$GTW_SRC/config.yaml" ]; then
  echo "== [1/3] GoTestWAF"; mark gotestwaf
  "$TOOLS/gotestwaf" --url "$TARGET" --configPath "$GTW_SRC/config.yaml" --testCasesPath "$GTW_SRC/testcases" \
    --blockStatusCodes 403 --passStatusCodes 200 --nonBlockedAsPassed --workers 8 \
    --reportPath "$OUT/gotestwaf" --reportName gtw --reportFormat json \
    --noEmailReport --skipWAFIdentification 2>&1 | grep -E "Score|Blocked|Bypassed|True-" | tail -12
fi

# 2) Nuclei — scanner templates (CVE, exposed panels, config files). Shows the
#    no-payload probe gap (e.g. /wp-admin) the model is known to miss.
if [ -x "$TOOLS/nuclei" ]; then
  echo "== [2/3] Nuclei"; mark nuclei
  "$TOOLS/nuclei" -u "$TARGET" -tags panel,exposure,misconfig -rl "$RL" -jsonl \
    -o "$OUT/nuclei.jsonl" -silent 2>&1 | tail -3
fi

# 3) sqlmap — one endpoint, tamper scripts, to see if the model still catches
#    obfuscated SQLi. --batch = no prompts; scoped to the local harness.
if [ -f "$TOOLS/sqlmap/sqlmap.py" ]; then
  echo "== [3/3] sqlmap"; mark sqlmap
  python3 "$TOOLS/sqlmap/sqlmap.py" -u "$TARGET/item?id=1" --batch --level 3 --risk 2 \
    --tamper=space2comment,between,charencode --technique=BEU \
    --output-dir="$OUT/sqlmap" 2>&1 | tail -6
fi
mark end
echo "== done — reports in $OUT"
