#!/usr/bin/env bash
# Run on an edge as root.  edge-switch.sh check|switch|rollback <compose dir>
# check: from inside each edge container, reach Main over the tunnel.
# switch: point the edge at 10.88.0.1 (backup first). rollback: restore backup.
set -uo pipefail
MODE=${1:?mode}; D=${2:?dir}; cd "$D" || exit 1
WG=10.88.0.1; P=0; F=0
ok(){ echo "PASS $1"; P=$((P+1)); }; bad(){ echo "FAIL $1"; F=$((F+1)); }
chk(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
code(){ docker exec cdn-edge-node curl -s -m 10 -o /dev/null -w "%{http_code}" "$@"; }

check() {
  chk "host ping $WG" 'ping -c2 -W2 $WG >/dev/null'
  chk "edge-node -> 8080 /healthz 200" '[ "$(code http://$WG:8080/healthz)" = 200 ]'
  chk "edge-node -> 8080 attack 403" '[ "$(code -H "Host: dvwa.waf-it-kku.online" "http://$WG:8080/?id=1%27%20OR%201=1--")" = 403 ]'
  local sz; sz=$(docker exec cdn-edge-node curl -s -m 10 -o /dev/null -w "%{http_code}:%{size_download}" http://$WG:8070/api/sync/bundle)
  chk "edge-node -> 8070 bundle 200, multi-segment ($sz)" '[ "${sz%%:*}" = 200 ] && [ "${sz#*:}" -gt 2800 ]'
  chk "log-forwarder -> 8000 health" 'docker exec cdn-log-forwarder python -c "import urllib.request as u;assert u.urlopen(\"http://$WG:8000/api/health\",timeout=10).status==200"'
  # The backend answers 200 for a domain it would issue a cert for, 400 otherwise;
  # the tunnel must give the same answer as the public path.
  local a b; a=$(docker exec cdn-caddy-ssl curl -s -m 10 -o /dev/null -w "%{http_code}" "http://$WG:8000/api/domains/check-ssl-allowed?domain=x.invalid")
  b=$(docker exec cdn-caddy-ssl curl -s -m 10 -o /dev/null -w "%{http_code}" "http://$WG:8000/api/domains/check-ssl-allowed?domain=")
  chk "caddy -> 8000 check-ssl-allowed answers (unknown=$a, empty=$b)" '[ "$a" = 400 ] && [ "$b" = 400 ]'
}

case "$MODE" in
  check) check ;;
  switch)
    BK=/root/backups/edge-wg-$(date +%Y%m%d-%H%M%S); mkdir -p "$BK"; chmod 700 "$BK"
    cp -p .env edge/Caddyfile docker-compose.yml "$BK/"; echo "BACKUP=$BK"
    check; [ "$F" = 0 ] || { echo "precheck failed, not switching"; exit 1; }
    sed -i -e "s#^MAIN_SERVER_IP=.*#MAIN_SERVER_IP=$WG#" -e "s#^CONTROL_API_URL=.*#CONTROL_API_URL=http://$WG:8070#" .env
    NEW=$(mktemp)   # not a fixed /tmp name: root writes it, and a planted symlink there would be followed
    sed "s#ask http://178.104.53.123:8000/#ask http://$WG:8000/#" edge/Caddyfile > "$NEW"
    grep -q "ask http://$WG:8000/" "$NEW" || { rm -f "$NEW"; echo "Caddyfile edit failed"; exit 1; }
    cat "$NEW" > edge/Caddyfile; rm -f "$NEW"   # same inode: bind-mounted
    docker exec cdn-caddy-ssl caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
    docker exec cdn-caddy-ssl caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
    docker compose up -d 2>&1 | grep -v "^ *Container .* Running" | tail -4
    for _ in $(seq 1 30); do [ "$(docker inspect -f '{{.State.Health.Status}}' cdn-edge-node)" = healthy ] && break; sleep 2; done
    echo "edge-node: $(docker inspect -f '{{.State.Health.Status}}' cdn-edge-node)"
    docker exec cdn-edge-node sh -c 'grep -h "server .*:8080" /etc/nginx/conf.d/default.conf'
    ;;
  rollback)
    BK=${3:?backup dir}; cp -p "$BK/.env" .env; cat "$BK/Caddyfile" > edge/Caddyfile
    docker exec cdn-caddy-ssl caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
    docker compose up -d 2>&1 | tail -2 ;;
esac
echo "SUMMARY $P passed, $F failed"
