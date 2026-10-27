#!/usr/bin/env bash
# Main node: the repo's docker-compose.yml (waf-nginx, Caddy, Redis, Caddy
# storage, ClickHouse, control-api, Postgres) plus what runs under systemd on
# the real machine (dashboard backend :8000, frps, the CloudWAF tunnel
# server), each as a host-network container so ports and 127.0.0.1 behave
# as they do there.
set -euo pipefail
. /sim/lib.sh
REPO=/root/waf_project
SIM_MAIN=/sim/main

log "copying the repo to $REPO"
deploy_copy . "$REPO"
cd "$REPO"

# --- .env (fake secrets) ----------------------------------------------------
umask 077
cat > .env <<EOF
# Simulated Main node -- fake secrets from sim/.state/secrets.env
ML_RELAY_SECRET=$ML_RELAY_SECRET
DECEPTION_INTERNAL_KEY=$DECEPTION_INTERNAL_KEY
REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
CADDY_STORAGE_PASSWORD=$CADDY_STORAGE_PASSWORD
CLICKHOUSE_PASSWORD=$CLICKHOUSE_PASSWORD
CLICKHOUSE_HOST=127.0.0.1
CONTROL_TOKEN=$CONTROL_TOKEN
CAPTCHA_HMAC_SECRET=$CAPTCHA_HMAC_SECRET
OTP_HMAC_SECRET=$OTP_HMAC_SECRET
BUNDLE_SIGNING_KEY=$BUNDLE_SIGNING_KEY
JWT_SECRET_KEY=$JWT_SECRET_KEY
FRP_AUTH_TOKEN=$FRP_AUTH_TOKEN
FRP_HOOK_SECRET=$FRP_HOOK_SECRET
FRP_ADMIN_USER=$FRP_ADMIN_USER
FRP_ADMIN_PASS=$FRP_ADMIN_PASS
TUNNEL_STATE_FILE=/var/lib/cloudwaf-tunnel/state.json
# Public DNS of the real domains is not reachable from here.
WAF_DNS_AUTHORITATIVE=0
# Plain http inside the simulation.
SESSION_COOKIE_SECURE=false
PUBLIC_APP_URL=http://178.104.53.123
EOF
umask 022

# Key files that are not in git (the WAF template mounts server.key).
if [ ! -s nginx/templates/conf/server.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=waf-sim-main" \
    -keyout nginx/templates/conf/server.key -out nginx/templates/conf/server.crt 2>/dev/null
fi

# --- control-api image (trusts the extra CA when there is one) -------------
cat > docker-compose.sim.yml <<EOF
services:
  control-api:
    build:
      context: ./cdn/control-api
      dockerfile: $(with_extra_ca cdn/control-api Dockerfile)
EOF
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.sim.yml)

# waf-net must be 172.18.0.0/16 (the template reaches frps and the tunnel
# server at 172.18.0.1, and qa-echo sits at 172.18.0.250). On the real host
# compose happened to create it first; here it is created explicitly.
docker network inspect waf_project_waf-net >/dev/null 2>&1 || \
  docker network create --subnet 172.18.0.0/16 --gateway 172.18.0.1 \
    --label com.docker.compose.project=waf_project --label com.docker.compose.network=waf-net \
    waf_project_waf-net

# --- Postgres: the repo's own bootstrap (migrations, login roles) ----------
log "postgres bootstrap"
PYTHON=/usr/bin/python3 bash deploy/postgres/bootstrap.sh

# --- the rest of docker-compose.yml ------------------------------------------
log "docker compose up (first run pulls/builds images)"
"${COMPOSE[@]}" up -d --build
bash scripts/qa/infra.sh

# --- dashboard backend image (stands in for waf-dashboard.service) ---------
log "building the dashboard backend image"
ctx=/tmp/dashboard-image
rm -rf "$ctx"; mkdir -p "$ctx"
cp dashboard/backend/requirements.txt "$ctx/"
cp "$SIM_MAIN/dashboard.Dockerfile" "$ctx/Dockerfile"
cp /usr/local/bin/docker "$ctx/docker"
docker build -q -t wafsim-dashboard -f "$ctx/$(with_extra_ca "$ctx" Dockerfile)" "$ctx" >/dev/null

if [ "${SIM_BUILD_FRONTEND:-1}" = 1 ] && [ ! -f dashboard/frontend/dist/index.html ]; then
  log "building the frontend (npm ci + vite build)"
  extra=()
  has_extra_ca && extra=(-v /sim-ca/extra.crt:/extra-ca.crt:ro -e NODE_EXTRA_CA_CERTS=/extra-ca.crt)
  docker run --rm "${extra[@]}" -v "$REPO/dashboard/frontend:/app" -w /app node:20-alpine \
    sh -c 'npm ci --no-audit --no-fund --loglevel=error && npm run build' \
    || log "frontend build failed; the API still runs (the dashboard page says it is not built)"
fi

run_host() {  # run_host <name> <docker run options> <image> <command>: a "systemd service" on this host
  local name=$1; shift
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --restart unless-stopped --network host "$@" >/dev/null
}

log "starting waf-dashboard (:8000)"
mkdir -p /var/lib/cloudwaf-tunnel
run_host waf-dashboard \
  -v "$REPO:$REPO" -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/lib/cloudwaf-tunnel:/var/lib/cloudwaf-tunnel \
  -w "$REPO/dashboard/backend" \
  wafsim-dashboard python -m uvicorn main:app --host 0.0.0.0 --port 8000
wait_for 180 "dashboard /api/health" curl -fsS http://127.0.0.1:8000/api/health

# --- frps (FRP tunnel server, gatekeeper hook on the dashboard) ------------
log "starting frps (:7000, vhost :8085)"
mkdir -p /etc/frp
sed -e "s/@FRP_AUTH_TOKEN@/$FRP_AUTH_TOKEN/" -e "s/@FRP_HOOK_SECRET@/$FRP_HOOK_SECRET/" \
    -e "s/@FRP_ADMIN_USER@/$FRP_ADMIN_USER/" -e "s/@FRP_ADMIN_PASS@/$FRP_ADMIN_PASS/" \
    "$SIM_MAIN/frps.toml" > /etc/frp/frps.toml
run_host frps -v /etc/frp/frps.toml:/etc/frp/frps.toml:ro snowdreamtech/frps:0.61.1

# --- CloudWAF tunnel server (:8050 agents, :8060 for nginx) -----------------
log "starting cloudwaf-tunnel (:8050 / :8060)"
mkdir -p /etc/cloudwaf-tunnel
if [ ! -s /etc/cloudwaf-tunnel/server.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=main.waf-it-kku.online" \
    -keyout /etc/cloudwaf-tunnel/server.key -out /etc/cloudwaf-tunnel/server.crt 2>/dev/null
fi
run_host cloudwaf-tunnel \
  -v "$REPO/tunnel:/opt/cloudwaf-tunnel:ro" -v /etc/cloudwaf-tunnel:/etc/cloudwaf-tunnel:ro \
  -v /var/lib/cloudwaf-tunnel:/var/lib/cloudwaf-tunnel \
  -e TUNNEL_VHOST_HOST=0.0.0.0 -w /opt/cloudwaf-tunnel wafsim-dashboard python server.py

# --- first admin (operator-seeded, as on the real server) -------------------
log "seeding the admin account"
printf '%s' "$SIM_ADMIN_PASSWORD" > /root/sim_admin_password
docker run --rm --network host -v "$REPO:$REPO" -v /root/sim_admin_password:/run/pw:ro \
  -w "$REPO/dashboard/backend" wafsim-dashboard \
  python scripts/seed_admin.py --email "$SIM_ADMIN_EMAIL" --username simadmin --role admin --password-file /run/pw
# No SMTP here, so the verification code cannot be mailed: mark it verified.
docker exec -i waf-postgres psql -q -U waf_owner -d waf \
  -c "UPDATE waf.users SET email_verified_at = now() WHERE email = '$SIM_ADMIN_EMAIL' AND email_verified_at IS NULL"

wait_for 60 "caddy :80" curl -fsS -o /dev/null -H 'Host: 178.104.53.123' http://127.0.0.1/api/health
log "ready"
