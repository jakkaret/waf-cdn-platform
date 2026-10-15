"""Hourly retention for the PostgreSQL store (replaces DynamoDB TTL).

1. As the maintenance role (DATABASE_URL_MAINT), SELECT waf.run_retention():
   audit_logs > 180 days, threat_patterns > 72 h, status_history_days > 400
   days, alerts > 90 days. The app role cannot delete audit rows at all.
2. Expired temporary IP bans: removed by IPRuleService, which also re-renders
   the ModSecurity block/allow files and reloads nginx -- the database cannot
   do that part, so it is not in run_retention().
Started by main.py only when DATA_BACKEND=postgres.
"""
import asyncio
import logging
import os

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = int(os.getenv("RETENTION_INTERVAL_SECONDS", "3600"))


def run_database_retention() -> list:
    """[(table_name, deleted)] from waf.run_retention(), on its own connection."""
    import psycopg
    dsn = os.getenv("DATABASE_URL_MAINT", "").strip()
    if not dsn:
        raise RuntimeError("DATABASE_URL_MAINT is not set")
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5) as conn:
        return [tuple(r) for r in conn.execute("SELECT table_name, deleted FROM waf.run_retention()")]


def expire_ip_bans(service=None) -> int:
    """Drop expired temporary bans and re-render the block/allow files from
    the database on every run -- not only when a row expired -- so the files
    can never drift from the table (a failed earlier render, a restart, an
    expired allow rule left in the whitelist would otherwise stay in force).
    nginx is reloaded only when a file actually changed."""
    from services.pg_store import PgIPRuleRepository
    if service is None:
        from api.ip_rules import service
    removed = PgIPRuleRepository().delete_expired()
    if service._sync_files_from_db():
        service._reload_nginx()
    return removed


async def retention_worker():
    while True:
        try:
            results = await asyncio.to_thread(run_database_retention)
            removed = await asyncio.to_thread(expire_ip_bans)
            deleted = {t: n for t, n in results if n} | ({"ip_rules": removed} if removed else {})
            if deleted:
                logger.info("retention: deleted %s", deleted)
        except Exception as exc:
            logger.error("retention run failed: %s", exc)
        await asyncio.sleep(INTERVAL_SECONDS)
