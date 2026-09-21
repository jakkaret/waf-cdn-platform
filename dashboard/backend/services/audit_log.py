"""Audit log for Team Workspace + AI Incident Postmortem (2026-09-22,
overnight session).

Write points are chosen by what a postmortem would actually need to
explain an incident -- settings changes, rule approve/reject, origin
updates, viewer/editor grants -- not by what's easiest to instrument. Read
endpoints are never logged.

Never allowed to break the mutation it's recording: write_audit_event()
swallows its own failures. An audit-log outage must not turn a real
settings update, origin edit, or rule approval into a 500.
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
    expires_at = int((now + dt.timedelta(days=RETENTION_DAYS)).timestamp())

    try:
        _db.audit_log_table.put_item(Item={
            "scope_id": scope_id,
            "event_id": event_id,
            "timestamp": now.isoformat(),
            "actor_user_id": actor_user_id,
            "actor_username": actor_username,
            "action": action,
            "summary": summary,
            "details": details or {},
            "expires_at": expires_at,
        })
    except Exception as e:
        print(f"[audit_log] failed to write event for scope={scope_id} action={action}: {e}")


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
    from boto3.dynamodb.conditions import Key

    _db = db if db is not None else globals()["db"]
    try:
        items = _db.audit_log_table.query(
            KeyConditionExpression=Key("scope_id").eq(scope_id)
        ).get("Items", [])
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
