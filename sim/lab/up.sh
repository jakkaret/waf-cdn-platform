#!/usr/bin/env bash
# Lab node: DVWA, published to the WAF only through an FRP agent set up the
# way a customer does it -- log in to the dashboard, take the docker command
# from the config generator, run it.
set -euo pipefail
. /sim/lib.sh
MAIN=178.104.53.123
DOMAIN=dvwa.waf-it-kku.online

grep -q main.waf-it-kku.online /etc/hosts || echo "$MAIN main.waf-it-kku.online" >> /etc/hosts

log "starting DVWA on 127.0.0.1:8081"
# Recreated on every boot: the image's Apache does not start again in a
# restarted container (stale pid file), and DVWA keeps no data worth keeping.
docker rm -f waf-dvwa-app >/dev/null 2>&1 || true
docker run -d --name waf-dvwa-app -p 127.0.0.1:8081:80 vulnerables/web-dvwa >/dev/null
wait_for 120 "DVWA" curl -fsS -o /dev/null http://127.0.0.1:8081/login.php

log "waiting for the dashboard on Main"
wait_for 3600 "the dashboard" curl -fsS -H "Host: $MAIN" "http://$MAIN/api/health"

# The admin account appears once Main's setup has seeded it.
login() {
  curl -fsS -H "Host: $MAIN" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$SIM_ADMIN_EMAIL\",\"password\":\"$SIM_ADMIN_PASSWORD\"}" \
    "http://$MAIN/api/auth/login" | jq -er .access_token
}
token=""
for _ in $(seq 1 60); do
  token=$(login 2>/dev/null) && break
  sleep 15   # login is rate limited (5/minute)
done
[ -n "$token" ] || { log "could not log in as $SIM_ADMIN_EMAIL"; exit 1; }

log "asking the config generator for an agent for $DOMAIN"
cfg=$(curl -fsS -H "Host: $MAIN" -H "Authorization: Bearer $token" \
  "http://$MAIN/api/tunnels/config-generator?domain=$DOMAIN&port=8081&local_ip=127.0.0.1")
cmd=$(echo "$cfg" | jq -r .docker_command)
docker rm -f "waf-agent-${DOMAIN//./-}" >/dev/null 2>&1 || true
# The generated command is for a host with sudo; this one runs as root.
bash -c "${cmd//sudo /}" >/dev/null

wait_for 120 "the FRP agent to register $DOMAIN" \
  sh -c "docker logs waf-agent-${DOMAIN//./-} 2>&1 | grep -q 'start proxy success'"
log "ready"
