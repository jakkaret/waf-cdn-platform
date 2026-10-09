#!/usr/bin/env bash
# Install / update the WAF ML API (ml/ml_api.py, ONNX runtime) on a fresh
# Ubuntu 24.04 VM that serves ONLY the ML model for the main WAF VPS.
#
#   sudo bash install.sh            (BRANCH=<name> to deploy another branch)
#
# Idempotent: re-running pulls the branch, updates packages and restarts the
# service; an existing /etc/waf-ml/waf-ml.env (token, bind address) is kept.
# See deploy/azure-ml/README.md for the whole setup (VM, WireGuard, VPS side).
set -euo pipefail

# Public repository: the VM clones it without credentials.
REPO_URL="${REPO_URL:-https://github.com/jakkaret/waf-cdn-platform.git}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/waf_project}"
ENV_DIR="${ENV_DIR:-/etc/waf-ml}"
ENV_FILE="$ENV_DIR/waf-ml.env"
SERVICE=waf-ml
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo bash install.sh)" >&2; exit 1; }

echo "[1/7] system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-dev build-essential git curl openssl wireguard ufw >/dev/null
python3 -c 'import sys; assert sys.version_info[:2] >= (3, 10), sys.version' \
  || { echo "Python >= 3.10 required (Ubuntu 24.04 ships 3.12)" >&2; exit 1; }

echo "[2/7] service user"
id wafml >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin wafml

echo "[3/7] code: $REPO_URL ($BRANCH) -> $APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch -q origin "$BRANCH"
  git -C "$APP_DIR" checkout -q -B "$BRANCH" "origin/$BRANCH"
else
  git clone -q --branch "$BRANCH" --single-branch "$REPO_URL" "$APP_DIR"
fi
git -C "$APP_DIR" log -1 --format='      commit %h %s'

echo "[4/7] Python venv (ml/requirements-serve.txt; libinjection builds from source, ~1-2 min)"
[ -x "$APP_DIR/.venv/bin/python" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/ml/requirements-serve.txt"

echo "[5/7] RandomForest ONNX for /predict-fast (engine 'rf'), built from the tracked joblib"
if [ ! -f "$APP_DIR/ml/models/random_forest_waf.onnx" ]; then
  "$APP_DIR/.venv/bin/pip" install -q skl2onnx==1.20.0
  (cd "$APP_DIR" && PYTHONPATH="$APP_DIR" "$APP_DIR/.venv/bin/python" -W ignore -m ml.onnx_export >/dev/null)
  "$APP_DIR/.venv/bin/pip" uninstall -q -y skl2onnx
fi
mkdir -p "$APP_DIR/ml/models/gen3" "$APP_DIR/ml/telemetry"
chown -R root:root "$APP_DIR"
chown wafml:wafml "$APP_DIR/ml/telemetry"          # the only directory the service may write

echo "[6/7] configuration $ENV_FILE"
mkdir -p "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
  sed "s/^WAF_ML_API_TOKEN=.*/WAF_ML_API_TOKEN=$(openssl rand -hex 32)/" "$KIT_DIR/waf-ml.env.example" > "$ENV_FILE"
  echo "      created with a new random token"
fi
chown root:wafml "$ENV_FILE"
chmod 640 "$ENV_FILE"

echo "[7/7] systemd unit $SERVICE.service"
install -m 644 "$KIT_DIR/waf-ml.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable -q "$SERVICE"
systemctl restart "$SERVICE"

# shellcheck disable=SC1090
. "$ENV_FILE"
for _ in $(seq 1 30); do
  curl -fsS -o /dev/null -H "X-WAF-ML-Token: $WAF_ML_API_TOKEN" "http://$WAF_ML_BIND:$WAF_ML_PORT/health" && break
  sleep 1
done
echo
echo "health: $(curl -sS -H "X-WAF-ML-Token: $WAF_ML_API_TOKEN" "http://$WAF_ML_BIND:$WAF_ML_PORT/health" || echo 'NOT RESPONDING - journalctl -u waf-ml -n 50')"
echo
echo "Next:"
echo "  - Gen 3 model: ml/models/gen3/gen3_f_noopenappsec.onnx comes with the repo; to use a newer one:"
echo "      scp gen3_f_model.onnx <vm>:/tmp/ && sudo install -m 644 /tmp/gen3_f_model.onnx $APP_DIR/ml/models/gen3/gen3_f_noopenappsec.onnx && sudo systemctl restart $SERVICE"
echo "  - token for the VPS (ML_SERVICE_TOKEN): sudo grep WAF_ML_API_TOKEN $ENV_FILE"
echo "  - bind address is $WAF_ML_BIND; set WAF_ML_BIND to the WireGuard address once wg0 is up (README step 5)"
