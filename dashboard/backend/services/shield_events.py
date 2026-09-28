"""OTP / CAPTCHA shield events: Redis queue -> ClickHouse, and per-origin reads.

control-api (cdn/control-api/shield_events.py) LPUSHes one JSON object per
event onto EVENTS_KEY. The worker below pops the oldest ones in batches and
inserts them into ClickHouse table shield_events (created in
clickhouse_service.init_db). Readers always filter by origin_id, which is
what keeps one origin's visitors out of another origin's dashboard.
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

import redis

logger = logging.getLogger(__name__)

EVENTS_KEY = "waf:shield:events"
BATCH = 500
COLUMNS = ["timestamp", "origin_id", "host", "kind", "event", "client_ip", "email_masked", "email_hash", "path"]

EVENT_LABELS = {
    "challenge_shown": "Challenge shown",
    "blocked_no_clearance": "Blocked (no clearance, non-GET)",
    "otp_requested": "Code sent",
    "otp_send_failed": "Email send failed",
    "otp_rate_limited": "Too many code requests",
    "otp_verified": "Verified",
    "otp_wrong_code": "Wrong code",
    "otp_too_many_attempts": "Too many wrong codes",
    "otp_expired": "Expired / unknown code",
    "otp_context_mismatch": "Different device/network",
    "otp_not_allowed": "Email not on the allowlist",
    "would_challenge": "Would challenge (log only)",
    "would_block": "Would block non-GET (log only)",
}

# User-Agents that are not a browser a person can solve a challenge in:
# scripts, HTTP libraries and native mobile apps (iOS CFNetwork, Android okhttp).
NON_BROWSER_UA_RE = (
    "(?i)(curl|wget|python|okhttp|go-http|java/|axios|node-fetch|undici|postman|insomnia|httpie|"
    "libwww|scrapy|aiohttp|dart|cfnetwork|guzzle|ruby|php/|powershell)"
)


def _like(pattern: str) -> str:
    """fnmatch pattern (what control-api matches paths with) -> SQL LIKE."""
    out = pattern.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return out.replace("*", "%").replace("?", "_")


def preview_for_paths(ch, hosts: List[str], login_paths: List[str], exclude_paths: List[str], hours: int = 168) -> dict:
    """What the last `hours` of real traffic to these hosts would have met on
    these paths: how many requests are GET/HEAD (-> challenge page), how many
    use another method (-> blocked with 403) and how many come from something
    that isn't a browser (can't solve any challenge)."""
    if not hosts or not login_paths:
        return {"hours": hours, "total": 0, "get_head": 0, "other_methods": 0, "non_browser": 0, "top_non_browser": []}
    params = {"hosts": list(hosts), "hours": int(hours), "ua_re": NON_BROWSER_UA_RE}
    path = "splitByChar('?', url)[1]"
    match = []
    for i, pattern in enumerate(login_paths[:20]):
        params[f"p{i}"] = _like(pattern)
        match.append(f"{path} LIKE {{p{i}:String}}")
    exclude = []
    for i, pattern in enumerate((exclude_paths or [])[:20]):
        params[f"x{i}"] = _like(pattern)
        exclude.append(f"{path} LIKE {{x{i}:String}}")
    where = (
        "host IN {hosts:Array(String)} AND timestamp > now() - INTERVAL {hours:UInt32} HOUR "
        f"AND ({' OR '.join(match)})"
        + (f" AND NOT ({' OR '.join(exclude)})" if exclude else "")
    )
    non_browser = "(user_agent = '' OR match(user_agent, {ua_re:String}))"
    total, get_head, other, nb = ch.client.query(
        f"SELECT count(), countIf(method IN ('GET','HEAD')), countIf(method NOT IN ('GET','HEAD','OPTIONS')), "
        f"countIf({non_browser}) FROM access_logs WHERE {where}",
        parameters=params,
    ).result_rows[0]
    top = ch.client.query(
        f"SELECT user_agent, count() c FROM access_logs WHERE {where} AND {non_browser} "
        "GROUP BY user_agent ORDER BY c DESC LIMIT 5",
        parameters=params,
    ).result_rows
    return {
        "hours": int(hours), "total": int(total), "get_head": int(get_head),
        "other_methods": int(other), "non_browser": int(nb),
        "top_non_browser": [{"user_agent": ua or "(empty)", "count": int(c)} for ua, c in top],
    }


def _redis_client():
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=int(os.getenv("REDIS_DB", "0")),
        decode_responses=True,
        socket_connect_timeout=1,
        socket_timeout=2,
    )


def _row(item: dict) -> list:
    ts = datetime.fromtimestamp(int(item.get("ts") or 0), tz=timezone.utc).replace(tzinfo=None)
    return [ts] + [str(item.get(c) or "")[:512] for c in COLUMNS[1:]]


def drain_once(client, ch) -> int:
    """Move up to BATCH queued events into ClickHouse. Returns how many were
    popped. On an insert failure the batch goes back on the tail (oldest end)
    so it is retried next tick instead of lost."""
    raw: Optional[List[str]] = client.rpop(EVENTS_KEY, BATCH)
    if not raw:
        return 0
    rows = []
    for value in raw:
        try:
            rows.append(_row(json.loads(value)))
        except (ValueError, TypeError):
            logger.warning("dropping malformed shield event: %.120s", value)
    try:
        if rows:
            ch.client.insert("shield_events", rows, column_names=COLUMNS)
    except Exception:
        client.rpush(EVENTS_KEY, *reversed(raw))
        raise
    return len(raw)


async def shield_events_worker(ch, interval: float = 2.0):
    client = _redis_client()
    logger.info("shield events worker starting")
    while True:
        moved = 0
        try:
            if ch.connected:
                # redis + clickhouse calls are blocking; keep them off the loop
                moved = await asyncio.to_thread(drain_once, client, ch)
        except Exception:
            logger.exception("shield events drain failed")
        await asyncio.sleep(0 if moved >= BATCH else interval)


def summary_for_origin(ch, origin_id: str, hours: int = 24, limit: int = 100) -> dict:
    params = {"origin_id": origin_id, "hours": int(hours), "limit": int(limit)}
    counts = ch.client.query(
        "SELECT kind, event, count() FROM shield_events "
        "WHERE origin_id = {origin_id:String} AND timestamp > now() - INTERVAL {hours:UInt32} HOUR "
        "GROUP BY kind, event",
        parameters=params,
    ).result_rows
    recent = ch.client.query(
        "SELECT timestamp, host, kind, event, client_ip, email_masked, path FROM shield_events "
        "WHERE origin_id = {origin_id:String} AND timestamp > now() - INTERVAL {hours:UInt32} HOUR "
        "ORDER BY timestamp DESC LIMIT {limit:UInt32}",
        parameters=params,
    ).result_rows
    return {
        "hours": int(hours),
        "counts": [{"kind": k, "event": e, "label": EVENT_LABELS.get(e, e), "count": int(n)} for k, e, n in counts],
        "recent": [
            {
                "timestamp": ts.isoformat() + "Z", "host": host, "kind": kind, "event": event,
                "label": EVENT_LABELS.get(event, event), "client_ip": ip, "email": email, "path": path,
            }
            for ts, host, kind, event, ip, email, path in recent
        ],
    }
