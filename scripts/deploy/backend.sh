#!/usr/bin/env bash
# Deploy changed dashboard backend files to Main: stage, compile, back up,
# copy, import check, restart, health check. Rolls back on any failed check.
#   scripts/deploy/backend.sh "<files to copy>" ["<files to remove>"]
# Paths are relative to dashboard/backend. Backups stay next to each file as
# <file>.bak-<TS>.
set -euo pipefail
HOST=${WAF_MAIN_HOST:-root@178.104.53.123}
LOCAL="$(cd "$(dirname "$0")/../.." && pwd)/dashboard/backend"
REMOTE=/root/waf_project/dashboard/backend
COPY="$1"; REMOVE="${2:-}"
TS=$(date +%Y%m%d-%H%M%S)
STAGE=/tmp/waf-deploy-$TS

ssh $HOST "mkdir -p $STAGE"
# COPYFILE_DISABLE / --no-xattrs: Mac tar otherwise adds ._* files.
(cd "$LOCAL" && COPYFILE_DISABLE=1 tar --no-xattrs -cf - $COPY) | ssh $HOST "tar -xf - -C $STAGE"

ssh $HOST "bash -s" <<EOF
set -euo pipefail
cd $REMOTE
rollback() {
  echo "ROLLBACK: restoring .bak-$TS files"
  for f in $COPY $REMOVE; do
    if [ -e "\$f.bak-$TS" ]; then cp -p "\$f.bak-$TS" "\$f"; else rm -f "\$f"; fi
  done
  systemctl restart waf-dashboard; sleep 4
  curl -fsS -o /dev/null -w "health after rollback %{http_code}\n" http://127.0.0.1:8000/api/health || true
  exit 1
}
# compile the staged copies before touching anything live
for f in $COPY; do case "\$f" in *.py) .venv/bin/python -m py_compile "$STAGE/\$f";; esac; done
for f in $COPY $REMOVE; do [ -e "\$f" ] && cp -p "\$f" "\$f.bak-$TS" || true; done
for f in $COPY; do mkdir -p "\$(dirname "\$f")"; cp "$STAGE/\$f" "\$f"; done
for f in $REMOVE; do rm -f "\$f"; done
.venv/bin/python -c 'import main' >/tmp/waf-import-$TS.log 2>&1 || { tail -20 /tmp/waf-import-$TS.log; rollback; }
systemctl restart waf-dashboard
for i in \$(seq 1 20); do
  curl -fsS -o /dev/null http://127.0.0.1:8000/api/health 2>/dev/null && break; sleep 2
done
curl -fsS -o /dev/null -w "health %{http_code}\n" http://127.0.0.1:8000/api/health || rollback
systemctl is-active waf-dashboard
echo "deployed TS=$TS"
EOF
