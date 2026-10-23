#!/usr/bin/env bash
# Build the dashboard frontend on Main from the local tree and swap it in:
# stage in /tmp/fe-stage-<TS> (node_modules linked from the live tree),
# tsc -b, vitest, vite build, then move dist aside as dist.bak-<TS> and copy
# the listed source files into the live src so it matches what was built.
#   scripts/deploy/frontend.sh "<changed files>"
# Paths are relative to dashboard/frontend. Nothing live changes if a check fails.
# Roll back: cd /root/waf_project/dashboard/frontend && rm -rf dist && mv dist.bak-<TS> dist
set -euo pipefail
HOST=${WAF_MAIN_HOST:-root@178.104.53.123}
LOCAL="$(cd "$(dirname "$0")/../.." && pwd)/dashboard/frontend"
REMOTE=/root/waf_project/dashboard/frontend
CHANGED="${1:?list the changed files, relative to dashboard/frontend}"
TS=$(date +%Y%m%d-%H%M%S)
STAGE=/tmp/fe-stage-$TS

ssh $HOST "mkdir -p $STAGE"
# COPYFILE_DISABLE / --no-xattrs: Mac tar otherwise adds ._* files, which vitest picks up.
(cd "$LOCAL" && COPYFILE_DISABLE=1 tar --no-xattrs --exclude=node_modules --exclude=dist -cf - .) \
  | ssh $HOST "tar -xf - -C $STAGE"

ssh $HOST "bash -s" <<EOF
set -euo pipefail
cd $STAGE
ln -s $REMOTE/node_modules node_modules
npx tsc -b
npx vitest run
npx vite build
cd $REMOTE
for f in $CHANGED; do [ -e "\$f" ] && cp -p "\$f" "\$f.bak-$TS" || true; mkdir -p "\$(dirname "\$f")"; cp "$STAGE/\$f" "\$f"; done
mv dist dist.bak-$TS
cp -r $STAGE/dist dist
echo "live src files that still differ from the build: \$(diff -rq $STAGE/src src | grep -v '\.bak-' | wc -l)"
echo "deployed TS=$TS (stage $STAGE)"
EOF
