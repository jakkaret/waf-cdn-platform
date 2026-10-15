#!/usr/bin/env bash
# One-time (idempotent) PostgreSQL setup for the WAF dashboard backend, on
# Main or on a freshly cloned machine:
#
#   bash deploy/postgres/bootstrap.sh
#
# What it does:
#   1. creates $WAF_SECRETS_DIR (700) with random passwords (600), once;
#   2. starts the `postgres` service of the main docker-compose.yml (only that
#      service: --no-deps, other containers are not touched);
#   3. applies dashboard/backend/db/migrations as waf_owner (db/migrate.py);
#   4. creates LOGIN roles waf_app_login (IN ROLE waf_app) and
#      waf_maint_login (IN ROLE waf_maintenance) with role-level timeouts;
#   5. sets random JWT_SECRET_KEY, CLICKHOUSE_PASSWORD, CONTROL_TOKEN and
#      ML_RELAY_SECRET (before any compose call), then WAF_SECRETS_DIR,
#      WAF_BACKUP_DIR, DATABASE_URL and DATABASE_URL_MAINT in the repo's .env
#      when missing or empty (existing values are never replaced).
# The owner DSN goes ONLY to $WAF_SECRETS_DIR/pg_owner.env, never to .env:
# the app must not be able to run DDL or disable the audit_logs triggers.
# Passwords are never printed.
#
# Settings (env, or already in .env): WAF_SECRETS_DIR (default <repo>/secrets),
# WAF_BACKUP_DIR (default <repo>/backups/pg), WAF_PG_PORT (5432),
# WAF_PG_CONTAINER (waf-postgres), PYTHON (default the backend's .venv python;
# needs dashboard/backend/requirements.txt installed), COMPOSE_PROJECT_NAME.
set -euo pipefail

REPO=${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
ENV_FILE=$REPO/.env
BACKEND=$REPO/dashboard/backend
# .env holds secrets (JWT key, database passwords): owner-only from the start.
umask 077
touch "$ENV_FILE"
chmod 600 "$ENV_FILE"

env_value() {  # value of KEY from the environment, else from .env
  local key=$1
  if [ -n "${!key:-}" ]; then printf '%s' "${!key}"; return; fi
  sed -n "s/^$key=//p" "$ENV_FILE" | tail -1
}
add_env() {  # set KEY=VALUE in .env only if KEY is absent, empty, or an unexpanded $(...)
  local current
  current=$(sed -n "s/^$1=//p" "$ENV_FILE" | tail -1 | tr -d '"' | tr -d "'")
  # .env is not run through a shell: "KEY=$(openssl rand -hex 32)" is that
  # literal (public) text, so it counts as unset and gets a real value.
  case "$current" in *'$('*|*'`'*) current="" ;; esac
  [ -n "$current" ] && return
  sed -i.bak "/^$1=/d" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  # a file without a final newline would glue the new line onto its last one
  if [ -s "$ENV_FILE" ] && [ -n "$(tail -c1 "$ENV_FILE")" ]; then echo >> "$ENV_FILE"; fi
  printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
}

abs_path() {  # relative paths are relative to the repo, as docker compose reads them
  case "$1" in /*) printf '%s' "$1" ;; *) printf '%s' "$REPO/${1#./}" ;; esac
}
SECRETS=$(env_value WAF_SECRETS_DIR); SECRETS=$(abs_path "${SECRETS:-secrets}")
BACKUPS=$(env_value WAF_BACKUP_DIR); BACKUPS=$(abs_path "${BACKUPS:-backups/pg}")
PORT=$(env_value WAF_PG_PORT); PORT=${PORT:-5432}
CONTAINER=$(env_value WAF_PG_CONTAINER); CONTAINER=${CONTAINER:-waf-postgres}
PYTHON=${PYTHON:-$BACKEND/.venv/bin/python}
export WAF_SECRETS_DIR=$SECRETS WAF_BACKUP_DIR=$BACKUPS WAF_PG_PORT=$PORT WAF_PG_CONTAINER=$CONTAINER
COMPOSE=(docker compose -f "$REPO/docker-compose.yml")

[ -x "$PYTHON" ] || { echo "Python with the backend requirements not found at $PYTHON (set PYTHON=...)" >&2; exit 1; }
"$PYTHON" -c 'import psycopg, psycopg_pool' # fail early if the driver is missing

mkdir -p "$SECRETS" "$BACKUPS"
chmod 700 "$SECRETS" "$BACKUPS"

gen() { [ -s "$SECRETS/$1" ] || openssl rand -hex 24 > "$SECRETS/$1"; chmod 600 "$SECRETS/$1"; }
gen pg_owner_password
gen pg_app_password
gen pg_maint_password

OWNER_PW=$(cat "$SECRETS/pg_owner_password")
APP_PW=$(cat "$SECRETS/pg_app_password")
MAINT_PW=$(cat "$SECRETS/pg_maint_password")

printf 'DATABASE_URL_OWNER=postgresql://waf_owner:%s@127.0.0.1:%s/waf\n' "$OWNER_PW" "$PORT" \
  > "$SECRETS/pg_owner.env"
chmod 600 "$SECRETS/pg_owner.env"

# Secrets docker-compose.yml interpolates (${VAR:?}): compose refuses to run
# any service while one is missing, so they are generated before the first
# compose call. Existing values are kept.
add_env JWT_SECRET_KEY "$(openssl rand -hex 32)"
add_env CLICKHOUSE_PASSWORD "$(openssl rand -hex 24)"
add_env CLICKHOUSE_HOST 127.0.0.1
add_env CONTROL_TOKEN "$(openssl rand -hex 32)"
add_env ML_RELAY_SECRET "$(openssl rand -hex 32)"
add_env DECEPTION_INTERNAL_KEY "$(openssl rand -hex 32)"
add_env REDIS_PASSWORD "$(openssl rand -hex 32)"

"${COMPOSE[@]}" up -d --no-deps postgres
for _ in $(seq 1 30); do
  if docker exec "$CONTAINER" pg_isready -U waf_owner -d waf >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker exec "$CONTAINER" pg_isready -U waf_owner -d waf

(cd "$BACKEND" && WAF_PG_OWNER_ENV="$SECRETS/pg_owner.env" "$PYTHON" db/migrate.py)

# Login roles. Passwords go in over stdin (never on a command line, so they
# do not show up in `ps`); they are hex from openssl, so no quoting issues.
docker exec -i "$CONTAINER" psql -q -v ON_ERROR_STOP=1 -U waf_owner -d waf <<SQL
SELECT 'CREATE ROLE waf_app_login LOGIN IN ROLE waf_app'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'waf_app_login') \gexec
SELECT 'CREATE ROLE waf_maint_login LOGIN IN ROLE waf_maintenance'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'waf_maint_login') \gexec
ALTER ROLE waf_app_login PASSWORD '$APP_PW';
ALTER ROLE waf_maint_login PASSWORD '$MAINT_PW';
ALTER ROLE waf_app_login SET statement_timeout = '5s';
ALTER ROLE waf_app_login SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE waf_app_login SET search_path = waf, public;
ALTER ROLE waf_maint_login SET statement_timeout = '60s';
ALTER ROLE waf_maint_login SET search_path = waf, public;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE waf FROM PUBLIC;
GRANT CONNECT ON DATABASE waf TO waf_app, waf_maintenance;
SQL

add_env WAF_SECRETS_DIR "$SECRETS"
add_env WAF_BACKUP_DIR "$BACKUPS"
add_env DATABASE_URL "postgresql://waf_app_login:$APP_PW@127.0.0.1:$PORT/waf"
add_env DATABASE_URL_MAINT "postgresql://waf_maint_login:$MAINT_PW@127.0.0.1:$PORT/waf"
chmod 600 "$ENV_FILE"   # sed -i may have recreated it

echo "bootstrap done: $CONTAINER up on 127.0.0.1:$PORT, migrations applied, login roles ready"
echo "first admin: $PYTHON $BACKEND/scripts/seed_admin.py --email <you> --role admin --generate-password $SECRETS/admin_login_password"
