"""Shield (OTP / CAPTCHA) events, queued in Redis for the dashboard.

control-api has Redis but no ClickHouse client, so every event is pushed onto
one capped Redis list and the dashboard backend's shield_events worker moves
them into ClickHouse (table shield_events), where an origin's Admins and
Viewers can read their own origin's rows.

The visitor's email never leaves this process in full: only a masked form
(for a human to recognise) and a short hash (to group repeat requests) are
queued.
"""
import hashlib
import json
import logging
import time

logger = logging.getLogger(__name__)

EVENTS_KEY = "waf:shield:events"
# Newest at the head (LPUSH); the backend pops from the tail. If the backend is
# down, LTRIM drops the oldest events beyond this instead of growing Redis.
MAX_QUEUED = 20000


def mask_email(email: str) -> str:
    local, _, domain = (email or "").strip().lower().partition("@")
    if not domain:
        return ""
    shown = local[:2] if len(local) > 2 else local[:1]
    return f"{shown}***@{domain}"


def email_hash(email: str) -> str:
    value = (email or "").strip().lower()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else ""


def record(client, *, kind: str, event: str, host: str, origin_id: str = "",
           client_ip: str = "", email: str = "", path: str = "") -> None:
    """Queue one event. Never raises: losing an event must not fail the
    visitor's request."""
    if client is None:
        return
    item = {
        "ts": int(time.time()),
        "kind": kind,
        "event": event,
        "host": host,
        "origin_id": origin_id or "",
        "client_ip": client_ip or "",
        "email_masked": mask_email(email),
        "email_hash": email_hash(email),
        "path": (path or "")[:512],
    }
    try:
        pipe = client.pipeline()
        pipe.lpush(EVENTS_KEY, json.dumps(item, separators=(",", ":")))
        pipe.ltrim(EVENTS_KEY, 0, MAX_QUEUED - 1)
        pipe.execute()
    except Exception as exc:
        logger.warning("shield event not queued (%s/%s): %s", kind, event, exc)
