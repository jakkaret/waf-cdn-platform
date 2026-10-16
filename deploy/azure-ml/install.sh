#!/usr/bin/env bash
# Install / update the WAF ML API (ml/ml_api.py, ONNX runtime) on a fresh
# Ubuntu 24.04 VM that serves ONLY the ML model for the main WAF VPS.
#
#   sudo REF=<commit sha or tag> bash install.sh
#
# REF is required (audit H03): the VM runs exactly the reviewed commit, never
# whatever a branch points at when the script happens to run. The model files
# are then checked against ml/models/SHA256SUMS from that same commit.
#
# Idempotent: re-running checks out REF, updates packages and restarts the
# service; an existing /etc/waf-ml/waf-ml.env (token, bind address) is kept.
# See deploy/azure-ml/README.md for the whole setup (VM, WireGuard, VPS side).
set -euo pipefail

# Public repository: the VM clones it without credentials.
REPO_URL="${REPO_URL:-https://github.com/jakkaret/waf-cdn-platform.git}"
REF="${REF:-}"
APP_DIR="${APP_DIR:-/opt/waf_project}"
ENV_DIR="${ENV_DIR:-/etc/waf-ml}"
ENV_FILE="$ENV_DIR/waf-ml.env"
SERVICE=waf-ml
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo REF=<sha|tag> bash install.sh)" >&2; exit 1; }
[ -n "$REF" ] || { echo "set REF to the commit sha or tag to deploy, e.g. sudo REF=v1.2.0 bash install.sh" >&2; exit 1; }

echo "[1/7] system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q python3 python3-venv python3-dev build-essential git curl openssl wireguard ufw >/dev/null
python3 -c 'import sys; assert sys.version_info[:2] >= (3, 10), sys.version' \
  || { echo "Python >= 3.10 required (Ubuntu 24.04 ships 3.12)" >&2; exit 1; }

echo "[2/7] service user"
id wafml >/dev/null 2>&1 || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin wafml

echo "[3/7] code: $REPO_URL @ $REF -> $APP_DIR"
[ -d "$APP_DIR/.git" ] || git clone -q --no-checkout "$REPO_URL" "$APP_DIR"
git -C "$APP_DIR" fetch -q --tags origin
git -C "$APP_DIR" checkout -q --detach "$REF^{commit}"
case "$REF" in
  # A full sha must be exactly what is checked out (no prefix tricks).
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*)
    [ "${#REF}" -ne 40 ] || [ "$(git -C "$APP_DIR" rev-parse HEAD)" = "$REF" ] \
      || { echo "checked out $(git -C "$APP_DIR" rev-parse HEAD), expected $REF" >&2; exit 1; } ;;
esac
git -C "$APP_DIR" log -1 --format='      commit %H %s'

echo "[4/7] Python venv (ml/requirements-serve.txt; libinjection builds from source, ~1-2 min)"
[ -x "$APP_DIR/.venv/bin/python" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/ml/requirements-serve.txt"

echo "[5/7] model files: sha256 against ml/models/SHA256SUMS of this commit"
# Every served model is committed (ONNX and pickle-free .npz); nothing is
# built or unpickled here (H52). A mismatch stops the install.
(cd "$APP_DIR/ml/models" && grep -v '^#' SHA256SUMS | sha256sum --strict -c --quiet -) \
  || { echo "model files do not match ml/models/SHA256SUMS" >&2; exit 1; }
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
echo "  - models: commit a new model together with its line in ml/models/SHA256SUMS, then re-run"
echo "      sudo REF=<new sha|tag> bash install.sh   (no scp of model files: they would skip the hash check)"
echo "  - token for the VPS (ML_SERVICE_TOKEN): sudo grep WAF_ML_API_TOKEN $ENV_FILE"
echo "  - bind address is $WAF_ML_BIND; set WAF_ML_BIND to the WireGuard address once wg0 is up (README step 5)"
