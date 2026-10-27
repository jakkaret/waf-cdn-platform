# Helpers for the per-machine setup scripts (sourced, not run).

log() { echo "[${SIM_NODE:-sim}] $*"; }

# shellcheck disable=SC1091
set -a; . /sim-state/secrets.env; set +a

# Copy part of the repo the way a deploy would: the machine gets its own
# working tree, so nothing it writes (.env, logs, generated config) reaches
# the checkout it was copied from.
deploy_copy() {  # deploy_copy <repo-relative src> <dest>
  mkdir -p "$2"
  rsync -a --delete \
    --exclude .git --exclude node_modules --exclude .venv --exclude __pycache__ \
    --exclude '/sim/.state' --exclude '/logs' --exclude '/.env' --exclude '/secrets' \
    --exclude '/backups' --exclude '/dashboard/frontend/dist' \
    "/src/$1/" "$2/"
}

has_extra_ca() { [ -s /sim-ca/extra.crt ]; }

# A copy of a Dockerfile that also trusts the extra CA (TLS-inspecting proxy
# only). Without one, the original Dockerfile is used as it is.
#   with_extra_ca <context dir> <dockerfile name> -> prints the name to build with
with_extra_ca() {
  local ctx=$1 name=$2
  if ! has_extra_ca; then echo "$name"; return; fi
  cp /sim-ca/extra.crt "$ctx/sim-extra-ca.crt"
  awk '
    { print }
    /^FROM / {
      print "COPY sim-extra-ca.crt /usr/local/share/ca-certificates/sim-extra-ca.crt"
      print "RUN cat /usr/local/share/ca-certificates/sim-extra-ca.crt >> /etc/ssl/certs/ca-certificates.crt"
      print "ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/sim-extra-ca.crt"
    }' "$ctx/$name" > "$ctx/$name.sim"
  echo "$name.sim"
}

wait_for() {  # wait_for <seconds> <description> <command...>
  local secs=$1 what=$2; shift 2
  for _ in $(seq 1 "$secs"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  log "timed out waiting for $what"
  return 1
}
