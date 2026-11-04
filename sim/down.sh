#!/usr/bin/env bash
# Stop the simulated platform. `bash sim/down.sh -v` also deletes each
# machine's Docker data (images, databases, caches); secrets stay in .state.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
docker compose down "$@"
