#!/usr/bin/env bash
# open-appsec WAF Comparison against our systems, all on local Docker containers.
# Plan and rules: ml/security_test/BENCHMARK_PLAN_OPENAPPSEC.md
#
#   bash ml/security_test/openappsec/run_benchmark.sh --systems "CRS-4.25.1,Gen3@card" --fast --workers 16
#   bash ml/security_test/openappsec/run_benchmark.sh --systems "CRS-4.25.1,CRS-4.25.1+RF-rules-all,CRS-4.25.1+Gen3-rules-backtest" --fast
#   bash ml/security_test/openappsec/run_benchmark.sh --systems "CRS-4.25.1,CRS-4.25.1+Gen3@card" --origin httpbin --fast
#
# --origin stub (default, traefik/whoami: 200 for every request) | httpbin (kennethreitz/httpbin, a real
# web app behind the WAF; system names get "@httpbin"). The origin is on the private Docker network only.
#
# Systems (the name is also the --waf-name on the tool's PDF and DuckDB; <BASE> = $BASE_CRS_NAME):
#   CRS-4.20.0-default     CRS 4.20.0 image defaults (calibration against the published "OWASP CRS 4.20.0" row)
#   <BASE>                 base CRS with production settings: PL1, inbound anomaly 5, outbound 4
#   Gen3@<thr>             ML harness alone (no CRS); <thr> = a number, or "card" for the model card's threshold
#   <BASE>+Gen3@<thr>      base CRS in front of the ML harness
#   <BASE>-tuned[+Gen3@<thr>]  same with $CRS_TUNING loaded after CRS (rule exclusions, crs_fp_attribution.py)
#   <BASE>+<gen>-<policy>  base CRS + rules proposed by the ML (ml/security_test/openappsec/propose_rules.py)
#                          <gen> = RF-rules | Gen3-rules, <policy> = all | backtest (backtest_rules.py)
#   Old letters still work: K, A, B, C, D = CRS-4.20.0-default, <BASE>, <BASE>+Gen3@0.99, <BASE>+Gen3@card, Gen3@card
#
# Environment:
#   BASE_CRS_IMAGE  image of the base CRS (default CRS 4.25.1 LTS, what production runs after its upgrade).
#                   Always a pinned tag: the floating "nginx" tag is CRS 4.29.0 since 30/09/2026, not 3.3.8.
#                   CRS 3.3.8 as production ran it: owasp/modsecurity-crs:3.3.8-nginx-202603150103
#   BASE_CRS_NAME   its name in system names and reports (default CRS-4.25.1)
#   MODEL           ONNX model for the Gen3 systems, relative to the repo (default ml/models/gen3/gen3_f_noopenappsec.onnx)
#                   must be the model trained WITHOUT OpenAppSec (plan section 3)
#   RULES_DIR       proposed rules for the "-rules-" systems (default ~/waf-bench/results/rules/url):
#                   rf-rules-all.conf, rf-rules-backtest.conf, gen3-rules-all.conf, gen3-rules-backtest.conf
#   HARNESS_WORKERS uvicorn workers of the ML harness (default 1)
#   WAF_ORT_THREADS onnxruntime threads per harness worker (default: onnxruntime's, one per host CPU)
#   RESULTS         tool results dir with results/datasets (default ~/waf-bench/results); the tool
#                   downloads the datasets (~1.2 GB zip, ~7 GB extracted) there on first run
#
# Only local containers are targeted; nothing here touches the production VPS.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SYSTEMS="CRS-4.20.0-default,CRS-4.25.1"; FAST=""; WORKERS=16; ORIGIN=stub
while [ $# -gt 0 ]; do
  case "$1" in
    --systems) SYSTEMS="$2"; shift 2 ;;
    --fast) FAST="--fast"; shift ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --origin) ORIGIN="$2"; shift 2 ;;  # stub (traefik/whoami, 200 for everything) | httpbin (kennethreitz/httpbin)
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$ORIGIN" in
  stub) ORIGIN_IMG=traefik/whoami; SUFFIX="" ;;
  httpbin) ORIGIN_IMG=kennethreitz/httpbin; SUFFIX="@httpbin" ;;  # names say which origin was behind the WAF
  *) echo "unknown origin: $ORIGIN" >&2; exit 2 ;;
esac
ORIGIN_URL=http://oa-origin:80
# ML harness serving: uvicorn workers, and onnxruntime threads per worker (empty = onnxruntime's default)
HARNESS_WORKERS="${HARNESS_WORKERS:-1}"
WAF_ORT_THREADS="${WAF_ORT_THREADS:-}"
MODEL="${MODEL:-ml/models/gen3/gen3_f_noopenappsec.onnx}"
RESULTS="${RESULTS:-$HOME/waf-bench/results}"
RULES_DIR="${RULES_DIR:-$HOME/waf-bench/results/rules/url}"
CRS_TUNING="${CRS_TUNING:-$REPO/ml/security_test/openappsec/crs-tuning.conf}"  # for <BASE>-tuned systems
BASE_CRS_IMAGE="${BASE_CRS_IMAGE:-owasp/modsecurity-crs:4.25.1-nginx-202609301109-lts}"
BASE="${BASE_CRS_NAME:-CRS-4.25.1}"
NET=oa-net
CRS4=owasp/modsecurity-crs:4.20.0-nginx-202511100111
TOOL=ghcr.io/openappsec/waf-comparison-project:latest
HARNESS_IMG=waf-gen3-harness:local
mkdir -p "$RESULTS" "$RESULTS/harness-logs"

# old letters -> names
NAMES=()
IFS=, read -ra LIST <<< "$SYSTEMS"
for s in "${LIST[@]}"; do
  case "$s" in
    K) s="CRS-4.20.0-default" ;;  A) s="$BASE" ;;  B) s="$BASE+Gen3@0.99" ;;
    C) s="$BASE+Gen3@card" ;;     D) s="Gen3@card" ;;
  esac
  NAMES+=("$s")
done

container() { echo "oa-$1" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9.-]/-/g'; }  # docker names allow no + or @

case ",${NAMES[*]}," in *Gen3@*)
  [ -f "$REPO/$MODEL" ] || { echo "model not found: $REPO/$MODEL (see plan, step 3)" >&2; exit 1; }
  if ! docker image inspect $HARNESS_IMG >/dev/null 2>&1; then
    echo "== building ML harness image"
    docker build -q -t $HARNESS_IMG -f "$REPO/ml/security_test/openappsec/Dockerfile.harness" "$REPO" >/dev/null
  else
    echo "== ML harness image $HARNESS_IMG already exists, reusing"
  fi ;;
esac

echo "== cleaning old containers"
docker ps -aq --filter "name=^oa-" | xargs -r docker rm -f >/dev/null
docker network rm $NET >/dev/null 2>&1 || true
docker network create $NET >/dev/null
docker run -d --name oa-origin --network $NET "$ORIGIN_IMG" >/dev/null
echo "== origin: $ORIGIN ($ORIGIN_IMG) at $ORIGIN_URL, private network only"

ml_harness() {  # container threshold ("card" = the model card's); allowed requests go on to the origin
  local name=$1 thr=$2 upstream=()
  [ "$thr" = card ] && thr=""
  [ "$ORIGIN" != stub ] && upstream=(-e WAF_TEST_UPSTREAM="$ORIGIN_URL")
  docker run -d --name "$name" --network $NET -v "$REPO:/app" -v "$RESULTS/harness-logs:/logs" \
    -e WAF_GEN3_ONNX_PATH="/app/$MODEL" ${thr:+-e WAF_TEST_THRESHOLD=$thr} ${WAF_ORT_THREADS:+-e WAF_ORT_THREADS=$WAF_ORT_THREADS} \
    "${upstream[@]}" -e WAF_TEST_LOG="/logs/$name.jsonl" $HARNESS_IMG \
    uvicorn ml.security_test.waf_test_harness:app --host 0.0.0.0 --port 8088 --no-access-log --workers "$HARNESS_WORKERS" >/dev/null
}
base_crs() {  # container backend [rules file loaded before CRS] [tuning file loaded after CRS]
  local mount=()
  [ -n "${3:-}" ] && mount+=(-v "$3:/opt/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf:ro")
  [ -n "${4:-}" ] && mount+=(-v "$4:/opt/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf:ro")
  # PARANOIA is the CRS 3 image's variable, BLOCKING_PARANOIA the CRS 4 one: set both so BASE_CRS_IMAGE can be either
  docker run -d --name "$1" --network $NET -e BACKEND="$2" "${mount[@]}" \
    -e PARANOIA=1 -e BLOCKING_PARANOIA=1 -e ANOMALY_INBOUND=5 -e ANOMALY_OUTBOUND=4 "$BASE_CRS_IMAGE" >/dev/null
}

need_tuning() {
  [ -f "$CRS_TUNING" ] || { echo "CRS tuning file not found: $CRS_TUNING" >&2; exit 1; }
  echo "   tuning: $CRS_TUNING ($(grep -c -E '^Sec' "$CRS_TUNING") directives)"
}

ARGS=()
for s in "${NAMES[@]}"; do
  c=$(container "$s")
  case "$s" in
    CRS-4.20.0-default)
      docker run -d --name "$c" --network $NET -e BACKEND=$ORIGIN_URL $CRS4 >/dev/null; url="http://$c:8080" ;;
    "$BASE")
      base_crs "$c" $ORIGIN_URL; url="http://$c:8080" ;;
    "$BASE-tuned")
      need_tuning; base_crs "$c" $ORIGIN_URL "" "$CRS_TUNING"; url="http://$c:8080" ;;
    "$BASE-tuned+Gen3@"*)
      need_tuning; ml_harness "$c-ml" "${s#"$BASE-tuned+Gen3@"}"
      base_crs "$c" "http://$c-ml:8088" "" "$CRS_TUNING"; url="http://$c:8080" ;;
    Gen3@*)
      ml_harness "$c" "${s#Gen3@}"; url="http://$c:8088" ;;
    "$BASE+Gen3@"*)
      ml_harness "$c-ml" "${s#"$BASE+Gen3@"}"; base_crs "$c" "http://$c-ml:8088"; url="http://$c:8080" ;;
    "$BASE+RF-rules-"*|"$BASE+Gen3-rules-"*)
      rest="${s#"$BASE+"}"                                   # RF-rules-all
      file="$RULES_DIR/$(echo "$rest" | tr 'A-Z' 'a-z').conf"  # rf-rules-all.conf
      [ -f "$file" ] || { echo "rules not found: $file (run propose_rules.py / backtest_rules.py)" >&2; exit 1; }
      echo "   $s: $(grep -c '^SecRule' "$file") rules from $file"
      base_crs "$c" $ORIGIN_URL "$file"; url="http://$c:8080" ;;
    *) echo "unknown system: $s (base CRS is \"$BASE\")" >&2; exit 2 ;;
  esac
  ARGS+=(--waf-name="$s$SUFFIX" --waf-url="$url")
done

echo "== waiting for targets (benign must be 200, XSS must be 403)"
probe() { docker run --rm --network $NET curlimages/curl:latest -s -o /dev/null -w "%{http_code}" "$1" 2>/dev/null || echo 000; }
for ((i=1; i<${#ARGS[@]}; i+=2)); do
  url="${ARGS[$i]#--waf-url=}"
  for _ in $(seq 1 90); do [ "$(probe "$url/")" = 200 ] && break; sleep 2; done
  b=$(probe "$url/"); x=$(probe "$url/?a=%3Cscript%3Ealert(1)%3C/script%3E")
  echo "   ${ARGS[$((i-1))]#--waf-name=} $url benign=$b xss=$x"
  [ "$b" = 200 ] && [ "$x" = 403 ] || { echo "target not ready: $url (docker logs $(echo "$url" | sed 's#http://##; s#:.*##'))" >&2; exit 1; }
done

echo "== running the open-appsec tool (${NAMES[*]}, workers=$WORKERS ${FAST:-full})"
start=$(date +%s)
docker run --rm --name oa-tool --network $NET -v "$RESULTS:/app/results" $TOOL \
  --fresh-run $FAST --max-workers "$WORKERS" "${ARGS[@]}"
echo "ELAPSED_SEC $(( $(date +%s) - start ))"

echo "== rates (status 0 = timeout, dropped from the rates by the tool; report the count)"
stamp=$(date +%Y%m%d-%H%M%S)
# the next --fresh-run wipes the tool's DB; db/ belongs to the tool container's root, so keep a copy in runs/
RUN_DIR="$RESULTS/runs/$stamp"; mkdir -p "$RUN_DIR"
cp "$RESULTS/db/waf_comparison.duckdb" "$RUN_DIR/waf_comparison.duckdb"
cp "$(ls -t "$RESULTS"/waf-comparison-report_*.pdf | head -1)" "$RUN_DIR/" 2>/dev/null || true
printf '%s\n' "systems: ${NAMES[*]}" "origin: $ORIGIN" "fast: ${FAST:-no}" "workers: $WORKERS" \
  "base image: $BASE_CRS_IMAGE" "harness workers: $HARNESS_WORKERS, ort threads: ${WAF_ORT_THREADS:-default}" \
  "elapsed_sec: $(( $(date +%s) - start ))" > "$RUN_DIR/run.txt"
if command -v python3 >/dev/null 2>&1 && python3 -c "import duckdb" >/dev/null 2>&1; then
  python3 "$REPO/ml/security_test/openappsec/summarize_db.py" "$RESULTS/db/waf_comparison.duckdb" \
    | tee "$RESULTS/summary-$stamp.txt"
else
  docker run --rm -v "$RESULTS:/r" -v "$REPO/ml/security_test/openappsec:/s:ro" python:3.12-slim \
    sh -c "pip install -q duckdb >/dev/null 2>&1 && python /s/summarize_db.py /r/db/waf_comparison.duckdb" \
    | tee "$RESULTS/summary-$stamp.txt"
fi
cp "$RESULTS/summary-$stamp.txt" "$RUN_DIR/summary.txt"
echo "== kept in $RUN_DIR: DB, PDF report, summary, run settings"
