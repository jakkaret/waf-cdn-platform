"""The control-plane store under its historical name.

DynamoDB was replaced by PostgreSQL (2026-10-15, docs: the migration plan).
The class every module imports as DynamoDBService is services.pg_store.PgStore;
the name is kept so the 26+ importers did not have to change.
"""
from services.pg_store import DomainAlreadyClaimed, DuplicateDomain, PgStore  # noqa: F401

DynamoDBService = PgStore


def invalidate_alerts_cache() -> None:
    """Alerts are read from PostgreSQL on every call; nothing is cached any
    more. Kept for the callers that still signal a change."""
