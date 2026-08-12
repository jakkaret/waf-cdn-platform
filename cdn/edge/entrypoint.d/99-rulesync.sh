#!/usr/bin/env sh
set -eu

CONTROL_API_URL="${CONTROL_API_URL:-http://cdn-control-api:8070}"
SYNC_INTERVAL_SEC="${SYNC_INTERVAL_SEC:-5}"
RULES_DIR="${CUSTOM_RULES_DIR:-/opt/custom-rules}"

NGINX_BIN="${NGINX_BIN:-/usr/sbin/nginx}"

bundle_tmp="/tmp/rules-bundle.tgz"
hash_tmp="/tmp/rules-bundle.sha"

(
  echo "[rulesync] starting: api=${CONTROL_API_URL} interval=${SYNC_INTERVAL_SEC}s rules_dir=${RULES_DIR}" >&2

  mkdir -p "${RULES_DIR}"
  # Ensure at least one .conf exists so ModSecurity glob include does not fail.
  if [ ! -f "${RULES_DIR}/00-placeholder.conf" ]; then
    cat >"${RULES_DIR}/00-placeholder.conf" <<'EOF'
# Placeholder custom rules (keeps Include /opt/custom-rules/*.conf from failing)
EOF
  fi

  while true; do
    if ! curl -fsS "${CONTROL_API_URL}/api/sync/bundle" -o "${bundle_tmp}.new"; then
      sleep "${SYNC_INTERVAL_SEC}"
      continue
    fi

    new_hash=$(sha256sum "${bundle_tmp}.new" | awk '{print $1}')
    old_hash=""
    if [ -f "${hash_tmp}" ]; then
      old_hash=$(cat "${hash_tmp}" 2>/dev/null || true)
    fi

    if [ "${new_hash}" != "${old_hash}" ]; then
      rm -f "${bundle_tmp}" || true
      mv "${bundle_tmp}.new" "${bundle_tmp}"

      tmp_dir="/tmp/custom-rules.$$"
      rm -rf "${tmp_dir}" || true
      mkdir -p "${tmp_dir}"

      if tar -xzf "${bundle_tmp}" -C "${tmp_dir}"; then
        # Replace rules atomically-ish
        rm -f "${RULES_DIR}"/*.conf "${RULES_DIR}"/*.txt 2>/dev/null || true
        cp -f "${tmp_dir}"/* "${RULES_DIR}/" 2>/dev/null || true

        if "${NGINX_BIN}" -t >/dev/null 2>&1; then
          "${NGINX_BIN}" -s reload >/dev/null 2>&1 || true
          echo "${new_hash}" >"${hash_tmp}"
          echo "[rulesync] updated + reloaded" >&2
        else
          echo "[rulesync] nginx -t failed; not reloading" >&2
        fi
      else
        echo "[rulesync] failed to extract bundle" >&2
      fi

      rm -rf "${tmp_dir}" || true
    else
      rm -f "${bundle_tmp}.new" || true
    fi

    sleep "${SYNC_INTERVAL_SEC}"
  done
) &

exit 0
