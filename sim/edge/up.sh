#!/usr/bin/env bash
# An edge node: Caddy + the CRS edge nginx (rulesync, purge) talking to Main
# over the WireGuard network, and PowerDNS GeoDNS on the edge's own address
# (cdn/geodns-pdns, run exactly as its README says).
set -euo pipefail
. /sim/lib.sh
: "${EDGE_REGION:?}" "${EDGE_PUBLIC_IP:?}" "${EDGE_DEPLOY_DIR:?}"
D=$EDGE_DEPLOY_DIR

log "deploying the edge to $D"
deploy_copy cdn/edge "$D/edge"
# The repo has this file as 100644; the nginx image skips entrypoint scripts
# that are not executable, and then no rules sync and nginx does not start
# (the placeholder rule file it creates is missing). The real edges'
# untracked copies are executable.
chmod +x "$D/edge/entrypoint.d/99-rulesync.sh"
cp /sim/edge/compose.yml /sim/edge/Caddyfile "$D/"
umask 077
printf 'EDGE_REGION=%s\nBUNDLE_SIGNING_KEY=%s\n' "$EDGE_REGION" "$BUNDLE_SIGNING_KEY" > "$D/.env"
umask 022
mkdir -p "$D/logs" "$D/ssl"

# TLS files of the edge nginx's :443 server (the key is not in git).
if [ ! -s "$D/ssl/edge.key" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=cdn.waf-it-kku.online" \
    -keyout "$D/ssl/edge.key" -out "$D/ssl/edge.crt" 2>/dev/null
  openssl dhparam -dsaparam -out "$D/ssl/dhparam-2048.pem" 2048 2>/dev/null
fi

log "starting cdn-caddy-ssl + cdn-edge-node"
(cd "$D" && docker compose up -d)

log "starting GeoDNS (PowerDNS on $EDGE_PUBLIC_IP:53)"
deploy_copy cdn/geodns-pdns /opt/geodns-pdns
mkdir -p /opt/geodns-pdns/geo
python3 /sim/edge/make_geo_mmdb.py /opt/geodns-pdns/geo/dbip-country-lite.mmdb
(cd /opt/geodns-pdns && PDNS_LOCAL_ADDRESS="$EDGE_PUBLIC_IP" docker compose up -d)

wait_for 60 "PowerDNS" dig +time=1 +tries=1 @"$EDGE_PUBLIC_IP" cdn.waf-it-kku.online SOA +short
# Main takes longer on a first run (image builds); the edge is ready without it.
wait_for 1800 "the edge's path to Main (/healthz/deep)" \
  sh -c "curl -fsS -H 'Host: cdn.waf-it-kku.online' http://127.0.0.1/healthz/deep | grep -q OK" \
  || log "Main not reachable yet; /healthz/deep fails and GeoDNS drops this edge until it is"
log "ready"
