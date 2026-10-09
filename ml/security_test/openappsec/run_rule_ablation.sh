#!/usr/bin/env bash
# ML rule-proposal ablation on the open-appsec benchmark (plan: ml/security_test/BENCHMARK_PLAN_OPENAPPSEC.md,
# section "ML rule proposal"). Local Docker only; nothing here touches the production VPS.
#
#   bash ml/security_test/openappsec/run_rule_ablation.sh [--view url|url+body] [--workers 16] [--full]
#
# Needs <RESULTS>/offline/requests.duckdb from score_offline.py (the request set of a --fast run).
# Steps:
#   1. propose_rules.py   RF-rules and Gen3-rules from the gen half
#   2. backtest_rules.py  "-backtest" policy: keep rules that match no gen-half legitimate request
#   3. run_benchmark.sh   base CRS + the four rule sets, one tool run (same sample for all five)
#   4. summarize_db.py    eval half only, change vs the base CRS with 95% bootstrap CI
# BASE_CRS_IMAGE / BASE_CRS_NAME as in run_benchmark.sh (default CRS 4.25.1, what production runs after its upgrade).
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
VIEW=url; WORKERS=16; FAST=--fast
while [ $# -gt 0 ]; do
  case "$1" in
    --view) VIEW="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --full) FAST=""; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
RESULTS="${RESULTS:-$HOME/waf-bench/results}"
BASE="${BASE_CRS_NAME:-CRS-4.25.1}"
PY="$REPO/.venv/bin/python"
RULES_DIR="$RESULTS/rules/${VIEW/+/_}"
REQUESTS_DB="$RESULTS/offline/requests.duckdb"
[ -f "$REQUESTS_DB" ] || { echo "missing $REQUESTS_DB: run score_offline.py first" >&2; exit 1; }
# --full stays leakage-free: the split is by website / payload group, so the eval half of the full
# dataset never shares a group with the gen-half requests the rules came from.

cd "$REPO"
echo "== 1. propose rules (view=$VIEW)"
PYTHONPATH=. "$PY" ml/security_test/openappsec/propose_rules.py --requests-db "$REQUESTS_DB" --out "$RESULTS/rules" --view "$VIEW"
echo "== 2. backtest on the gen half's legitimate traffic"
PYTHONPATH=. "$PY" ml/security_test/openappsec/backtest_rules.py --requests-db "$REQUESTS_DB" --rules-dir "$RULES_DIR"
echo "== 3. benchmark"
RULES_DIR="$RULES_DIR" RESULTS="$RESULTS" bash ml/security_test/openappsec/run_benchmark.sh $FAST --workers "$WORKERS" \
  --systems "$BASE,$BASE+RF-rules-all,$BASE+RF-rules-backtest,$BASE+Gen3-rules-all,$BASE+Gen3-rules-backtest"
echo "== 4. eval half vs $BASE"
PYTHONPATH=. "$PY" ml/security_test/openappsec/summarize_db.py "$RESULTS/db/waf_comparison.duckdb" \
  --half eval --baseline "$BASE" --json "$RULES_DIR/ablation_eval.json" | tee "$RULES_DIR/ablation_eval.txt"
