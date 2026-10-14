#!/usr/bin/env bash
# pg_dump of the waf database, kept 7 days. Scheduled by /etc/cron.d/waf-pg-backup:
#   0 */6 * * * root /root/waf_project/deploy/postgres/backup.sh >> /var/log/waf-pg-backup.log 2>&1
# Writes /root/backups/pg/waf-YYYY-MM-DD-HH.dump (custom format) and checks
# the file is readable with pg_restore --list before pruning old dumps.
set -euo pipefail

DIR=/root/backups/pg
NAME="waf-$(date +%F-%H).dump"
mkdir -p "$DIR"
chmod 700 "$DIR"

docker exec waf-postgres pg_dump -U waf_owner -d waf -Fc -f "/backups/$NAME"
docker exec waf-postgres pg_restore --list "/backups/$NAME" >/dev/null
chmod 600 "$DIR/$NAME"
find "$DIR" -name 'waf-*.dump' -mtime +7 -delete
echo "$(date -Is) backup ok: $DIR/$NAME ($(stat -c %s "$DIR/$NAME") bytes)"
