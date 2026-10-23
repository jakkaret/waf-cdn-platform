import asyncio
import html
import logging
import os
import secrets
import time
import httpx
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv
from services.dynamodb_service import DynamoDBService, invalidate_alerts_cache
from services import threat_intel

load_dotenv()

logger = logging.getLogger(__name__)

db = DynamoDBService()
_api_id_raw = os.getenv("TELEGRAM_API_ID")
API_ID = int(_api_id_raw) if _api_id_raw and _api_id_raw.isdigit() else None
API_HASH = os.getenv("TELEGRAM_API_HASH")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_BOTTOKEN")

_user_cache: list = []
_user_cache_ts: float = 0.0
_user_cache_fp: str = ""
USER_CACHE_TTL = 60


def _recipients_fingerprint() -> str:
    try:
        from services.rbac import auth_service
        return auth_service._pg.recipients_fingerprint()
    except Exception:
        return ""


def _get_telegram_users() -> list:
    """Recipients, cached up to 60 s -- but never past a role change or a
    deleted account, even one made by another process (H25/H34)."""
    global _user_cache, _user_cache_ts, _user_cache_fp
    now = time.monotonic()
    fp = _recipients_fingerprint()
    if now - _user_cache_ts < USER_CACHE_TTL and _user_cache and fp and fp == _user_cache_fp:
        return _user_cache

    try:
        from services.rbac import auth_service
        result = auth_service.list_telegram_recipients()
        _user_cache = result
        _user_cache_ts = now
        _user_cache_fp = fp
        logger.debug("Refreshed telegram user cache: %d users", len(_user_cache))
    except Exception as e:
        logger.error("Failed to refresh telegram user cache: %s", e)

    return _user_cache


ALL_ROLES = ("owner", "editor", "viewer")


def _alert_recipients(users: list, origin: dict, support_allowed: bool, roles: tuple = ALL_ROLES) -> list:
    """Users who may see this alert, i.e. who would see it in the Alert Center.

    The origin's owner, editors and viewers. Platform admins (the support
    team) only when ``support_allowed``: the alert belongs to no tenant
    (unattributed) or the origin has an active support grant -- the same
    scope as _visible_alerts_for_user in api/ai_summary.py.
    2026-09-28: every user with a chat id used to receive every alert, so
    tenant A was sent tenant B's IPs, URLs, rules and AI summary even though
    the stored alert itself is correctly partitioned by origin_id.
    2026-10-23: admins still received every tenant's alerts here after the
    web views were narrowed to support grants (docs/tickets/support-access.md).
    """
    allowed = set()
    if origin:
        if origin.get("admin_user_id") and "owner" in roles:
            allowed.add(origin["admin_user_id"])
        if "editor" in roles:
            allowed |= set(origin.get("editor_user_ids") or [])
        if "viewer" in roles:
            allowed |= set(origin.get("viewer_user_ids") or [])
    return [u for u in users if u.get("user_id") in allowed or (support_allowed and u.get("role") == "admin")]


def _support_may_receive(origin_id: str) -> bool:
    """Unattributed alerts, or an origin under an active support grant.
    A failed grant lookup counts as no grant (active_grant fails closed)."""
    if origin_id == db.ALERTS_UNATTRIBUTED:
        return True
    from services import support_service
    return bool(support_service.active_grant(origin_id))


def _esc(value) -> str:
    """Telegram parse_mode=HTML. Every value is escaped: URLs and paths are
    attacker-controlled, and an unescaped `<script>` (a routine XSS probe)
    made Telegram reject the message, or a crafted `<a href>` could put a link
    into someone's alert (F-039)."""
    return html.escape(str(value), quote=False)


def invalidate_user_cache():
    global _user_cache_ts
    _user_cache_ts = 0.0


async def record_alert(data: dict):
    """Store one blocked request as an alert and count its pattern for threat
    intel. Nothing is pushed from here (2026-10-24): a blocked request is the
    WAF working, and pushing each one (F-039, then a 5-minute cooldown per
    IP+rule) still sent dozens of messages per scanner run. Telegram now goes
    out per attack incident (services/alert_incidents.py). No Gemini call per
    request either; ai_summary stays empty and the UI shows the attack type."""
    try:
        ip = str(data.get("ip") or data.get("remote_addr") or data.get("client_ip") or "unknown").strip()
        url = str(data.get("url") or data.get("request_uri") or data.get("uri") or "unknown").strip()
        status_code = str(data.get("status") or data.get("status_code") or "403")
        attack_type = str(data.get("attack_type") or "WAF Security Block")
        rule_id = str(data.get("rule_id") or "WAF-CRS")
        severity = str(data.get("severity") or "CRITICAL")
        edge_node = str(data.get("edge_node") or data.get("region") or "Edge-TH")

        timestamp_int = int(data.get("timestamp") or time.time())
        rand_suffix = secrets.token_hex(8).upper()  # 2 bytes collided within a second
        raw_alert_id = data.get("alert_id")
        if raw_alert_id:
            # Strip IP suffix if existing caller passed timestamp-ip format
            alert_id = str(raw_alert_id)
        else:
            alert_id = f"ALT-{timestamp_int}-{rand_suffix}"
        # 2026-09-22: real cross-tenant leak fixed -- user_id here has
        # always been the hardcoded placeholder below, never a real owner,
        # so GET /api/ai/notifications/feed had no way to scope alerts per
        # tenant and showed every user every alert (confirmed live: a
        # brand-new account saw the full backlog). services/log_forward.py
        # already captures the real Host header into data["host"]; it was
        # simply never carried through to the stored alert. Storing it here
        # as "domain" is what api/ai_summary.py's _alert_belongs_to_tenant
        # now matches against the requesting user's registered domains.
        domain = str(data.get("host") or "").strip().lower()
        # 2026-09-23: resolve the captured Host to the origin that owns it,
        # once, here at write time. Matching the stored domain string at
        # read time (the 2026-09-22 fix above) is loose in both directions
        # -- a tenant registered for "example.com" matched an alert whose
        # Host was "example.com.attacker.test", because the check is a
        # two-way substring test. An origin_id resolved from
        # waf_domains' domain_name-index is exact. Empty means the Host is
        # not a registered domain (direct-to-IP traffic, a probe for
        # someone else's hostname): not attributable, so it stays
        # admin-only rather than being shown to a guessed owner.
        # Partition key as of the 2026-09-23 migration to waf_alerts_v2.
        # Never empty: an unresolvable Host (direct-to-IP traffic, a probe
        # for someone else's hostname) goes to the UNATTRIBUTED partition,
        # which is admin-only on read, rather than being attributed to a
        # guessed owner.
        origin_id = await asyncio.to_thread(db.get_origin_id_for_domain, domain) or db.ALERTS_UNATTRIBUTED
        try:
            await asyncio.to_thread(
                db.put_alert,
                {
                    "origin_id": origin_id,
                    # No longer a key. Kept because every pre-migration row
                    # carries it and some UI still surfaces it.
                    "user_id": "default-user",
                    "alert_id": alert_id,
                    "ip": ip,
                    "url": url,
                    "domain": domain,
                    "status": status_code,
                    "rule_id": rule_id,
                    "attack_type": attack_type,
                    "severity": severity,
                    "edge_node": edge_node,
                    "ai_summary": None,
                    "message": f"{attack_type} (Rule: {rule_id})",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "read": False
                }
            )
            invalidate_alerts_cache()
        except Exception as err:
            logger.error("Error saving alert to DynamoDB: %s", err)

        # Cross-tenant threat intel (opt-in, pattern-only -- see
        # services/threat_intel.py's module docstring for the full design).
        # This is *this* async task, already a fire-and-forget
        # asyncio.create_task() from every caller -- adds no latency to the
        # WAF's actual block response. Never raises: a missing host or a
        # DynamoDB hiccup here must never take down the alert store.
        host = data.get("host")
        if host:
            try:
                await asyncio.to_thread(
                    threat_intel.record_pattern_hit_for_domain, host, rule_id, attack_type
                )
            except Exception as e:
                logger.warning("threat_intel pattern recording failed for %s: %s", host, e)

    except Exception as e:
        logger.error("record_alert failed: %s", e)


def recipients_for(scope: str, origin: dict, roles: tuple = ALL_ROLES) -> list:
    """Telegram recipients for a site's alert (scope = origin id) or for
    traffic that belongs to no site (scope = ALERTS_UNATTRIBUTED, origin {}).
    roles narrows the site's team, e.g. ("owner",) for team changes."""
    users = _get_telegram_users()
    if not users:
        return []
    return _alert_recipients(users, origin, _support_may_receive(scope), roles)


async def send_telegram(chat_ids: list, text: str, buttons: Optional[list] = None) -> int:
    """Send one HTML message to each chat. buttons: [(label, https url)], URL
    buttons only (no callbacks, so nothing in a message can act by itself).
    Returns how many sends Telegram accepted."""
    if not BOT_TOKEN or not chat_ids:
        return 0
    payload = {"text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
    if buttons:
        payload["reply_markup"] = {"inline_keyboard": [[{"text": t, "url": u} for t, u in buttons]]}
    sent = 0
    async with httpx.AsyncClient(timeout=6.0) as client:
        for chat_id in chat_ids:
            if not chat_id or not str(chat_id).strip():
                continue
            try:
                res = await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                                        json={**payload, "chat_id": chat_id})
                if res.status_code == 200:
                    sent += 1
                else:
                    logger.warning("Telegram send rejected: %s", res.status_code)
            except Exception as e:
                logger.warning("Telegram send failed: %s", e)
    return sent


async def alert_worker():
    """Telegram goes out per attack incident, never per blocked request."""
    from services.alert_incidents import incident_worker
    await incident_worker()
