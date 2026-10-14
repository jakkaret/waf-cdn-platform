#!/usr/bin/env bash
# One-time (idempotent) setup of PostgreSQL on Main for the WAF backend.
#
#   sudo bash deploy/postgres/bootstrap.sh
#
# What it does:
#   1. creates /root/.waf-secrets (700) with random passwords (600), once;
#   2. starts the waf-postgres compose project;
#   3. applies db/migrations as waf_owner (dashboard/backend/db/migrate.py);
#   4. creates LOGIN roles waf_app_login (IN ROLE waf_app) and
#      waf_maint_login (IN ROLE waf_maintenance) with role-level timeouts;
#   5. adds DATABASE_URL / DATABASE_URL_MAINT to the service .env if missing.
# The owner DSN goes ONLY to /root/.waf-secrets/pg_owner.env, never to .env:
# the app must not be able to run DDL or disable the audit_logs triggers.
# Passwords are never printed.
set -euo pipefail

REPO=${REPO:-/root/waf_project}
SECRETS=/root/.waf-secrets
BACKEND=$REPO/dashboard/backend
VENV_PY=$BACKEND/.venv/bin/python
ENV_FILE=$REPO/.env
COMPOSE=(docker compose -f "$REPO/deploy/postgres/compose.yml" -p waf-postgres)

umask 077
mkdir -p "$SECRETS" /root/backups/pg
chmod 700 "$SECRETS"

gen() { [ -s "$SECRETS/$1" ] || openssl rand -hex 24 > "$SECRETS/$1"; chmod 600 "$SECRETS/$1"; }
gen pg_owner_password
gen pg_app_password
gen pg_maint_password

OWNER_PW=$(cat "$SECRETS/pg_owner_password")
APP_PW=$(cat "$SECRETS/pg_app_password")
MAINT_PW=$(cat "$SECRETS/pg_maint_password")

printf 'DATABASE_URL_OWNER=postgresql://waf_owner:%s@127.0.0.1:5432/waf\n' "$OWNER_PW" \
  > "$SECRETS/pg_owner.env"
chmod 600 "$SECRETS/pg_owner.env"

"$VENV_PY" -c 'import psycopg, psycopg_pool' # fail early if the venv lacks the driver

"${COMPOSE[@]}" up -d
for _ in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T postgres pg_isready -U waf_owner -d waf >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
"${COMPOSE[@]}" exec -T postgres pg_isready -U waf_owner -d waf

(cd "$BACKEND" && WAF_PG_OWNER_ENV="$SECRETS/pg_owner.env" "$VENV_PY" db/migrate.py)

# Login roles. Passwords go in over stdin (never on a command line, so they
# do not show up in `ps`); they are hex from openssl, so no quoting issues.
"${COMPOSE[@]}" exec -T postgres psql -q -v ON_ERROR_STOP=1 -U waf_owner -d waf <<SQL
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

add_env() {  # add KEY=VALUE to .env only if KEY is absent
  grep -q "^$1=" "$ENV_FILE" || printf '%s=%s\n' "$1" "$2" >> "$ENV_FILE"
}
add_env DATABASE_URL "postgresql://waf_app_login:$APP_PW@127.0.0.1:5432/waf"
add_env DATABASE_URL_MAINT "postgresql://waf_maint_login:$MAINT_PW@127.0.0.1:5432/waf"

echo "bootstrap done: waf-postgres up, migrations applied, login roles ready"
