#!/usr/bin/env bash
# QA infrastructure on Main for tests/integration (idempotent).
#   qa-echo     origin that answers with the request it received (headers incl.
#               X-Real-IP), fixed IP on waf-net so an origin record can point at it
#   qa-mailpit  captures OTP mail for QA_MAIL_DOMAINS (docker-compose control-api);
#               API only on 127.0.0.1:8025
set -euo pipefail
NET=waf_project_waf-net
docker inspect qa-echo >/dev/null 2>&1 || docker run -d --name qa-echo --network $NET --ip 172.18.0.250 \
  --restart unless-stopped -e HTTP_PORT=8080 -e LOG_WITHOUT_NEWLINE=true mendhak/http-https-echo:latest
docker inspect qa-mailpit >/dev/null 2>&1 || docker run -d --name qa-mailpit --network $NET --network-alias mailpit \
  --restart unless-stopped -p 127.0.0.1:8025:8025 -e MP_SMTP_AUTH_ACCEPT_ANY=1 -e MP_SMTP_AUTH_ALLOW_INSECURE=1 \
  axllent/mailpit:latest
docker ps --filter name=qa- --format "{{.Names}} {{.Status}}"
