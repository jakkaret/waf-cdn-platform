"""Value conversions between PostgreSQL rows and the dict shapes the code
used with DynamoDB/SQLite. Each table keeps the timestamp format it had:

    iso_z_us     isoformat()+'Z' with microseconds  users, alerts, origins, domains
    iso_z_s      '%Y-%m-%dT%H:%M:%SZ'                pending_rules, threshold_proposals
    iso_offset   isoformat() '+00:00'               audit_logs, ssl_certificates,
                                                    postmortems.created_at
    naive_utc    '%Y-%m-%d %H:%M:%S'                postmortems.start_time/end_time
    date_text    'YYYY-MM-DD'                       status_history_days.date_bucket
    epoch int                                       tunnel_token_issued_at, ip_rules
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any, Optional


def as_uuid(value: Any) -> Optional[str]:
    """Canonical uuid string, or None for anything that is not a uuid (path
    params, token parts, legacy ids): callers return "not found" before a
    query instead of aborting the transaction with a cast error."""
    if isinstance(value, uuid.UUID):
        return str(value)
    if value is None:
        return None
    try:
        return str(uuid.UUID(str(value).strip()))
    except (ValueError, AttributeError, TypeError):
        return None


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def iso_z_us(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return _utc_naive(value).isoformat() + "Z"


def iso_z_s(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return _utc_naive(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_offset(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def naive_utc(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return _utc_naive(value).strftime("%Y-%m-%d %H:%M:%S")


def date_text(value: Optional[date]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def epoch_int(value: Optional[datetime]) -> Optional[int]:
    return int(value.timestamp()) if value is not None else None


def epoch_str(value: Optional[datetime]) -> Optional[str]:
    return str(int(value.timestamp())) if value is not None else None


def from_epoch(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    return datetime.fromtimestamp(int(float(value)), tz=timezone.utc)


def parse_ts(value: Any) -> Optional[datetime]:
    """Parse any of the stored string formats (incl. trailing 'Z') to an
    aware UTC datetime; datetimes pass through."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
