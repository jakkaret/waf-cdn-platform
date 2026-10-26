#!/usr/bin/env sh
set -eu

# Pulls the custom-rule bundle from Main's control-api and applies it.
#
# P4.1 (H05/H21/N13 of security audit run 1):
#   * a bundle is applied only when its HMAC signature (BUNDLE_SIGNING_KEY,
#     shared with control-api) checks and its version is newer than the one
#     this edge runs -- a tampered or replayed older bundle is refused;
#   * it is unpacked into a staging directory first and checked (file names,
#     no paths), then swapped in; if nginx -t fails, the previous files are
#     put back before anything is reloaded, so nginx keeps serving the last
#     good rules and the log says why.

CONTROL_API_URL="${CONTROL_API_URL:-http://cdn-control-api:8070}"
SYNC_INTERVAL_SEC="${SYNC_INTERVAL_SEC:-5}"
RULES_DIR="${CUSTOM_RULES_DIR:-/opt/custom-rules}"
BUNDLE_SIGNING_KEY="${BUNDLE_SIGNING_KEY:-}"
STATE_DIR="${RULESYNC_STATE_DIR:-/var/lib/rulesync}"

NGINX_BIN="${NGINX_BIN:-/usr/sbin/nginx}"
CACHE_DIR="${EDGE_CACHE_DIR:-/var/cache/nginx/edge}"

work="/tmp/rulesync"
version_file="${STATE_DIR}/version"
purge_file="${STATE_DIR}/purge_id"

log() { echo "[rulesync] $*" >&2; }

header() {
  # header <name> <file>: value of an HTTP response header, no CR
  grep -i "^$1:" "$2" | tail -n 1 | cut -d: -f2- | tr -d ' \r\n'
}

apply_bundle() {
  bundle="$1" version="$2"
  staging="${work}/staging" backup="${work}/backup"
  rm -rf "${staging}" "${backup}"
  mkdir -p "${staging}" "${backup}"

  # Only plain rule files at the top level: no directories, no "..".
  if ! names=$(tar -tzf "${bundle}" 2>/dev/null); then
    log "v${version}: not a valid archive; keeping the current rules"
    return 1
  fi
  for n in ${names}; do
    case "${n}" in
      */*|..*|.*) log "v${version}: refused entry '${n}'; keeping the current rules"; return 1 ;;
      *.conf|*.txt|*.data) ;;
      *) log "v${version}: refused entry '${n}'; keeping the current rules"; return 1 ;;
    esac
  done
  if ! tar -xzf "${bundle}" -C "${staging}"; then
    log "v${version}: failed to extract; keeping the current rules"
    return 1
  fi

  # Swap: keep the current files aside, put the new ones in place.
  cp -p "${RULES_DIR}"/*.conf "${RULES_DIR}"/*.txt "${RULES_DIR}"/*.data "${backup}/" 2>/dev/null || true
  find "${RULES_DIR}" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.txt' -o -name '*.data' \) \
    ! -name '00-placeholder.conf' -delete
  cp -p "${staging}"/* "${RULES_DIR}/" 2>/dev/null || true

  if test_out=$("${NGINX_BIN}" -t 2>&1); then
    "${NGINX_BIN}" -s reload >/dev/null 2>&1 || true
    echo "${version}" > "${version_file}"
    log "v${version}: updated + reloaded"
    return 0
  fi

  # nginx refused the new rules: restore the previous set, reload nothing.
  find "${RULES_DIR}" -maxdepth 1 -type f \( -name '*.conf' -o -name '*.txt' -o -name '*.data' \) \
    ! -name '00-placeholder.conf' -delete
  cp -p "${backup}"/* "${RULES_DIR}/" 2>/dev/null || true
  log "v${version}: nginx -t failed, previous rules restored: $(echo "${test_out}" | grep -E 'emerg|error' | head -n 2 | tr '\n' ' ')"
  return 1
}

# Cache purge (dashboard -> control-api /api/sync/purges -> here). nginx keeps
# a cached response in ${CACHE_DIR}/<last char>/<2 chars before>/<md5 of key>
# (levels=1:2), and the key is "http|<host>|<method>|<uri>" (Caddy talks to
# this nginx over plain http). Deleting the file is enough: nginx treats a
# missing file as a miss and fetches the page again.
purge_job() {
  host="$1" path="$2"
  case "${host}" in ''|*[!a-z0-9.-]*) return 1 ;; esac
  case "${path}" in /*) ;; *) return 1 ;; esac
  n=0
  case "${path}" in
    *\*)
      # Prefix: every cached file whose KEY line starts with it.
      prefix="${path%\*}"
      grep -rlaF -e "KEY: http|${host}|GET|${prefix}" -e "KEY: http|${host}|HEAD|${prefix}" \
        -e "KEY: https|${host}|GET|${prefix}" -e "KEY: https|${host}|HEAD|${prefix}" \
        "${CACHE_DIR}" 2>/dev/null > "${work}/purge-files" || true
      n=$(wc -l < "${work}/purge-files" | tr -d ' ')
      xargs -r rm -f < "${work}/purge-files"
      ;;
    *)
      for key in "http|${host}|GET|${path}" "http|${host}|HEAD|${path}" \
                 "https|${host}|GET|${path}" "https|${host}|HEAD|${path}"; do
        h=$(printf '%s' "${key}" | md5sum | cut -c1-32)
        f="${CACHE_DIR}/$(echo "${h}" | cut -c32)/$(echo "${h}" | cut -c30-31)/${h}"
        if [ -f "${f}" ]; then rm -f "${f}"; n=$((n + 1)); fi
      done
      ;;
  esac
  echo "${n}"
}

purge_once() {
  [ -n "${BUNDLE_SIGNING_KEY}" ] || return 0
  after=$(cat "${purge_file}" 2>/dev/null || echo 0)
  case "${after}" in ''|*[!0-9]*) after=0 ;; esac
  curl -fsS -D "${work}/purge-headers" "${CONTROL_API_URL}/api/sync/purges?after=${after}" \
    -o "${work}/purges" 2>/dev/null || return 0
  signature=$(header X-Purge-Signature "${work}/purge-headers")
  body_sha=$(sha256sum "${work}/purges" | awk '{print $1}')
  expected=$(printf 'purge:%s' "${body_sha}" \
    | openssl dgst -sha256 -hmac "${BUNDLE_SIGNING_KEY}" | awk '{print $NF}')
  if [ -z "${signature}" ] || [ "${expected}" != "${signature}" ]; then
    log "purge list signature does not match; ignored"
    return 0
  fi
  latest=$(awk -F '\t' '$1 == "latest" { print $2 }' "${work}/purges")
  case "${latest}" in ''|*[!0-9]*) return 0 ;; esac
  tab=$(printf '\t')
  awk -F '\t' 'NF == 3 && $1 ~ /^[0-9]+$/' "${work}/purges" \
    | while IFS="${tab}" read -r id host path; do
        if n=$(purge_job "${host}" "${path}"); then
          log "purge #${id} ${host}${path}: ${n} cached file(s) removed"
        else
          log "purge #${id}: refused (${host} ${path})"
        fi
      done
  # A lower "latest" than ours means Main's queue was reset: follow it.
  echo "${latest}" > "${purge_file}"
}

(
  log "starting: api=${CONTROL_API_URL} interval=${SYNC_INTERVAL_SEC}s rules_dir=${RULES_DIR}"

  mkdir -p "${RULES_DIR}" "${STATE_DIR}" "${work}"
  # Ensure at least one .conf exists so ModSecurity glob include does not fail.
  if [ ! -f "${RULES_DIR}/00-placeholder.conf" ]; then
    cat >"${RULES_DIR}/00-placeholder.conf" <<'EOF'
# Placeholder custom rules (keeps Include /opt/custom-rules/*.conf from failing)
EOF
  fi
  if [ -z "${BUNDLE_SIGNING_KEY}" ]; then
    log "BUNDLE_SIGNING_KEY is not set: no bundle will be applied"
  fi

  last_refused=""
  sync_once() {
    curl -fsS -D "${work}/headers" "${CONTROL_API_URL}/api/sync/bundle" -o "${work}/bundle.tgz" || return 0
    version=$(header X-Bundle-Version "${work}/headers")
    signature=$(header X-Bundle-Signature "${work}/headers")
    current=$(cat "${version_file}" 2>/dev/null || echo 0)

    case "${version}" in ''|*[!0-9]*) version="" ;; esac
    if [ -z "${BUNDLE_SIGNING_KEY}" ] || [ -z "${version}" ] || [ -z "${signature}" ]; then
      [ "${last_refused}" = "unsigned" ] || log "bundle without a valid version/signature refused"
      last_refused="unsigned"
      return 0
    fi

    body_sha=$(sha256sum "${work}/bundle.tgz" | awk '{print $1}')
    expected=$(printf '%s:%s' "${version}" "${body_sha}" \
      | openssl dgst -sha256 -hmac "${BUNDLE_SIGNING_KEY}" | awk '{print $NF}')
    if [ "${expected}" != "${signature}" ]; then
      [ "${last_refused}" = "sig:${version}" ] || log "v${version}: signature does not match; refused"
      last_refused="sig:${version}"
    elif [ "${version}" -lt "${current}" ]; then
      [ "${last_refused}" = "old:${version}" ] || log "v${version}: older than the running v${current}; refused"
      last_refused="old:${version}"
    elif [ "${version}" -gt "${current}" ] && [ "$(cat "${version_file}.failed" 2>/dev/null)" != "${version}" ]; then
      if apply_bundle "${work}/bundle.tgz" "${version}"; then
        last_refused=""
      else
        # Do not retry the same broken version every few seconds; a newer
        # one is tried as soon as Main publishes it.
        echo "${version}" > "${version_file}.failed"
      fi
    fi
    return 0
  }

  while true; do
    sync_once
    purge_once
    [ "${RULESYNC_ONCE:-0}" = "1" ] && break  # tests run one pass in the foreground
    sleep "${SYNC_INTERVAL_SEC}"
  done
) &

[ "${RULESYNC_ONCE:-0}" = "1" ] && wait
exit 0
