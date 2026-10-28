#!/usr/bin/env bash
# Starts this machine's Docker daemon, then its role script
# (/sim/<SIM_ROLE>/up.sh), then stays up with the daemon.
set -euo pipefail
rm -f /run/sim-ready   # left over from the previous boot of this container

# Behind a TLS-inspecting proxy the daemon (image pulls) and the role scripts
# need its CA. Empty file = nothing to add.
if [ -s /sim-ca/extra.crt ] && [ ! -f /etc/ssl/certs/.sim-extra-ca ]; then
  cat /sim-ca/extra.crt >> /etc/ssl/certs/ca-certificates.crt
  touch /etc/ssl/certs/.sim-extra-ca
fi

mirror_args=()
[ -n "${SIM_REGISTRY_MIRROR:-}" ] && mirror_args=(--registry-mirror="${SIM_REGISTRY_MIRROR}")
dockerd-entrypoint.sh dockerd "${mirror_args[@]}" >/var/log/dockerd.log 2>&1 &
dockerd_pid=$!

for _ in $(seq 1 60); do
  docker info >/dev/null 2>&1 && break
  sleep 1
done
docker info >/dev/null 2>&1 || { echo "[sim-node] dockerd did not start"; tail -n 30 /var/log/dockerd.log; exit 1; }

echo "[sim-node] ${SIM_NODE:-?} (${SIM_ROLE}) docker ready, running /sim/${SIM_ROLE}/up.sh"
if bash "/sim/${SIM_ROLE}/up.sh"; then
  echo "[sim-node] ${SIM_NODE:-?} up"
  touch /run/sim-ready
else
  echo "[sim-node] ${SIM_NODE:-?}: up.sh failed (the daemon stays up for debugging)"
fi

wait "${dockerd_pid}"
