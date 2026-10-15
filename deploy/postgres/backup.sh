#!/usr/bin/env bash
# pg_dump of the waf database, kept 7 days. Scheduled by /etc/cron.d/waf-pg-backup:
#   0 */6 * * * root /root/waf_project/deploy/postgres/backup.sh >> /var/log/waf-pg-backup.log 2>&1
# Writes $WAF_BACKUP_DIR/waf-YYYY-MM-DD-HH.dump (custom format; the directory
# is mounted at /backups in the postgres container, see docker-compose.yml)
# and checks it with pg_restore --list before pruning old dumps.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
env_value() { [ -n "${!1:-}" ] && printf '%s' "${!1}" || sed -n "s/^$1=//p" "$REPO/.env" 2>/dev/null | tail -1; }
DIR=$(env_value WAF_BACKUP_DIR); DIR=${DIR:-backups/pg}
case "$DIR" in /*) ;; *) DIR="$REPO/${DIR#./}" ;; esac
CONTAINER=$(env_value WAF_PG_CONTAINER); CONTAINER=${CONTAINER:-waf-postgres}
NAME="waf-$(date +%F-%H).dump"
mkdir -p "$DIR"
chmod 700 "$DIR"

docker exec "$CONTAINER" pg_dump -U waf_owner -d waf -Fc -f "/backups/$NAME"
docker exec "$CONTAINER" pg_restore --list "/backups/$NAME" >/dev/null
chmod 600 "$DIR/$NAME"
find "$DIR" -name 'waf-*.dump' -mtime +7 -delete
echo "$(date -Is) backup ok: $DIR/$NAME ($(stat -c %s "$DIR/$NAME") bytes)"
