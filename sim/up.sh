#!/usr/bin/env bash
# Start the simulated platform (see sim/README.md).
#
#   bash sim/up.sh          build the node image, start every machine, wait
#   bash sim/test.sh        run the end-to-end checks from the client
#   bash sim/down.sh        stop (add -v to also drop the machines' disks)
#
# Settings (environment):
#   SIM_EXTRA_CA          a CA bundle to trust inside every machine (only
#                         behind a TLS-inspecting proxy)
#   SIM_REGISTRY_MIRROR   registry mirror for the machines' own Docker daemons
#                         (default https://mirror.gcr.io; empty = Docker Hub)
set -euo pipefail
SIM=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
STATE=$SIM/.state
mkdir -p "$STATE"
chmod 700 "$STATE"

# Fake secrets, once, shared by every machine (never the real ones).
if [ ! -s "$STATE/secrets.env" ]; then
  umask 077
  {
    for k in CONTROL_TOKEN ML_RELAY_SECRET DECEPTION_INTERNAL_KEY REDIS_PASSWORD \
             CADDY_STORAGE_PASSWORD CLICKHOUSE_PASSWORD CAPTCHA_HMAC_SECRET \
             OTP_HMAC_SECRET BUNDLE_SIGNING_KEY JWT_SECRET_KEY FRP_AUTH_TOKEN \
             FRP_HOOK_SECRET FRP_ADMIN_PASS SIM_ADMIN_PASSWORD; do
      printf '%s=%s\n' "$k" "$(openssl rand -hex 24)"
    done
    echo "FRP_ADMIN_USER=frpadmin"
    echo "SIM_ADMIN_EMAIL=admin@sim.waf-it-kku.online"
  } > "$STATE/secrets.env"
  echo "fake secrets written to sim/.state/secrets.env"
fi

# The machines (and their image builds) trust this extra CA; empty = none.
if [ -n "${SIM_EXTRA_CA:-}" ]; then cp "$SIM_EXTRA_CA" "$STATE/extra-ca.crt"; else : > "$STATE/extra-ca.crt"; fi

cd "$SIM"
docker compose build
docker compose up -d

echo "waiting for the machines to finish their setup (first run pulls images, ~10-20 min)"
unhealthy=0
for node in main edge-th edge-asia lab; do
  printf '  %-10s' "$node"
  for _ in $(seq 1 360); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "wafsim-$node-1" 2>/dev/null || echo missing)
    [ "$status" = healthy ] && break
    if [ "$(docker inspect -f '{{.State.Running}}' "wafsim-$node-1" 2>/dev/null)" != true ]; then
      status=stopped; break
    fi
    sleep 5
  done
  echo "$status"
  if [ "$status" != healthy ]; then
    unhealthy=$((unhealthy + 1))
    echo "  last log lines of $node:"
    docker logs --tail 20 "wafsim-$node-1" 2>&1 | sed 's/^/    /'
  fi
done

if [ "$unhealthy" -gt 0 ]; then
  echo "$unhealthy machine(s) did not finish their setup; see the logs above" >&2
  exit 1
fi

cat <<EOF

Dashboard:  http://localhost:8880
Admin:      \$(grep SIM_ADMIN_EMAIL sim/.state/secrets.env), password SIM_ADMIN_PASSWORD in the same file
Tests:      bash sim/test.sh
EOF
