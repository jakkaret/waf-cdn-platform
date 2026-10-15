#!/usr/bin/env bash
# Run on Main after probes tagged $TAG went through the edge.
# verify_edge.sh <edge public ip> <tunnel ip> <tag>
set -uo pipefail
E=$1; T=$2; TAG=$3; cd /root/waf_project
P=0; F=0; ok(){ echo "PASS $1"; P=$((P+1)); }; bad(){ echo "FAIL $1"; F=$((F+1)); }
chk(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
CH=$(sed -n 's/^CLICKHOUSE_PASSWORD=//p' .env)
q(){ curl -s -u "default:$CH" "http://127.0.0.1:8123/" --data-binary "$1"; }
LOG=$(docker inspect waf-nginx -f '{{range .Mounts}}{{if eq .Destination "/var/log/nginx"}}{{.Source}}{{end}}{{end}}')/access.json
# the attack probe is blocked by the edge's own ModSecurity, so only the benign one reaches Main
chk "Main access.json: benign probe arrived from $T" '[ "$(grep "$TAG" "$LOG" | grep -c "\"remote_addr\":\"$T\"")" -ge 1 ]'
chk "Main access.json: none from public $E" '! grep "$TAG" "$LOG" | grep -q "\"remote_addr\":\"$E\""'
n=0; for _ in $(seq 1 15); do n=$(q "SELECT count() FROM access_logs WHERE timestamp > now() - 900 AND position(url, '$TAG') > 0"); [ "${n:-0}" -ge 2 ] && break; sleep 2; done
chk "ClickHouse got both probes from the edge forwarder ($n)" '[ "${n:-0}" -ge 2 ]'
sleep 5; n=$(q "SELECT count() FROM access_logs WHERE timestamp > now() - 900 AND position(url, '$TAG') > 0")
chk "ClickHouse: not double-counted ($n)" '[ "${n:-0}" -eq 2 ]'
echo "rows: $(q "SELECT edge_node, client_ip, status_code FROM access_logs WHERE timestamp > now() - 900 AND position(url, '$TAG') > 0 FORMAT TSV" | tr '\t\n' ' ;')"
chk "control-api saw $T fetch the bundle" '[ "$(docker logs --since 2m waf-control-api 2>&1 | grep -c "$T:.*sync/bundle.* 200")" -gt 0 ]'
chk "nginx -t" 'docker exec waf-nginx nginx -t >/dev/null 2>&1'
echo "SUMMARY $P passed, $F failed"
