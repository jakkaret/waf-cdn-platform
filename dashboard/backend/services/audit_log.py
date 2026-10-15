"""Audit log for Team Workspace + AI Incident Postmortem (2026-09-22,
overnight session).

Write points are chosen by what a postmortem would actually need to
explain an incident -- settings changes, rule approve/reject, origin
updates, viewer/editor grants -- not by what's easiest to instrument. Read
endpoints are never logged.

Fail-closed: the event is written in the same transaction as the change
(callers wrap both in services.txn.atomic), so a change that cannot be
audited does not happen. Retention (180 days) is waf.run_retention().
"""
import datetime as dt
import secrets
from typing import Optional, List, Dict, Any

from services.dynamodb_service import DynamoDBService

db = DynamoDBService()

RETENTION_DAYS = 180


def _now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def write_audit_event(
    scope_id: str,
    actor_user_id: str,
    actor_username: str,
    action: str,
    summary: str,
    details: Optional[Dict[str, Any]] = None,
    db=None,
    now: Optional[dt.datetime] = None,
) -> None:
    """scope_id is an origin_id for origin-scoped events (origin update,
    domain changes, viewer/editor grants) or the literal string "global"
    for system-wide events (settings.py's paranoia_level, ml-rules
    approve/reject -- neither is tied to one origin)."""
    _db = db if db is not None else globals()["db"]
    now = now or _now_utc()
    event_id = f"{int(now.timestamp() * 1000):020d}#{secrets.token_hex(4)}"

    # Fail-closed: the INSERT runs on the caller's open transaction
    # (db.pool.transaction / services.txn.atomic) when there is one, so the
    # event and the change it records commit or roll back together, and an
    # error propagates instead of being swallowed.
    _db.put_audit_event({
        "scope_id": scope_id,
        "event_id": event_id,
        "timestamp": now.isoformat(),
        "actor_user_id": actor_user_id,
        "actor_username": actor_username,
        "action": action,
        "summary": summary,
        "details": details or {},
    })


def get_audit_log(
    scope_id: str,
    db=None,
    start: Optional[dt.datetime] = None,
    end: Optional[dt.datetime] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """Newest first. event_id's zero-padded-epoch-ms prefix makes
    lexicographic order the same as chronological order, so a plain
    query + reverse is enough -- no separate sort needed."""
    _db = db if db is not None else globals()["db"]
    try:
        items = _db.query_audit_events(scope_id)
    except Exception as e:
        print(f"[audit_log] query failed for scope={scope_id}: {e}")
        return []

    if start or end:
        filtered = []
        for item in items:
            try:
                ts = dt.datetime.fromisoformat(item["timestamp"])
            except (KeyError, ValueError):
                continue
            if start and ts < start:
                continue
            if end and ts > end:
                continue
            filtered.append(item)
        items = filtered

    items.sort(key=lambda i: i.get("event_id", ""), reverse=True)
    return items[:limit]
