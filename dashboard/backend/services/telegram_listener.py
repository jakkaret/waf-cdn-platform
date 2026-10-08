import asyncio
import html
import logging
import os
import secrets
import time
import httpx
from datetime import datetime
from typing import Dict, Tuple
from dotenv import load_dotenv
from services.dynamodb_service import DynamoDBService, invalidate_alerts_cache
from services.gemini_service import gemini_service
from services import threat_intel
from boto3.dynamodb.conditions import Attr

load_dotenv()

logger = logging.getLogger(__name__)

db = DynamoDBService()
_api_id_raw = os.getenv("TELEGRAM_API_ID")
API_ID = int(_api_id_raw) if _api_id_raw and _api_id_raw.isdigit() else None
API_HASH = os.getenv("TELEGRAM_API_HASH")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_BOTTOKEN")

_user_cache: list = []
_user_cache_ts: float = 0.0
USER_CACHE_TTL = 60


def _get_telegram_users() -> list:
    global _user_cache, _user_cache_ts
    now = time.monotonic()
    if now - _user_cache_ts < USER_CACHE_TTL and _user_cache:
        return _user_cache

    try:
        result = db.dynamodb.Table("waf_users").scan(
            FilterExpression=Attr("telegram_chat_id").exists()
        ).get("Items", [])
        _user_cache = result
        _user_cache_ts = now
        logger.debug("Refreshed telegram user cache: %d users", len(_user_cache))
    except Exception as e:
        logger.error("Failed to refresh telegram user cache: %s", e)

    return _user_cache


def _alert_recipients(users: list, origin: dict) -> list:
    """Users who may see this alert, i.e. who would see it in the Alert Center.

    Admins get everything (including the admin-only ``unattributed``
    partition). Otherwise only the origin's owner, editors and viewers.
    2026-09-28: every user with a chat id used to receive every alert, so
    tenant A was sent tenant B's IPs, URLs, rules and AI summary even though
    the stored alert itself is correctly partitioned by origin_id.
    """
    allowed = set()
    if origin:
        if origin.get("admin_user_id"):
            allowed.add(origin["admin_user_id"])
        allowed |= set(origin.get("editor_user_ids") or [])
        allowed |= set(origin.get("viewer_user_ids") or [])
    return [u for u in users if u.get("role") == "admin" or u.get("user_id") in allowed]


# F-039: every blocked request produced its own Telegram push to every
# recipient, so one scanner run meant hundreds of messages (and Telegram's own
# rate limit dropping them). Alerts are still all stored; only repeat pushes
# for the same (origin, client IP, rule) inside the window are suppressed.
TELEGRAM_COOLDOWN_SECONDS = 300
_last_push: Dict[Tuple[str, str, str], float] = {}


def _telegram_cooldown_ok(key: Tuple[str, str, str], now: float) -> bool:
    last = _last_push.get(key)
    if last is not None and now - last < TELEGRAM_COOLDOWN_SECONDS:
        return False
    _last_push[key] = now
    if len(_last_push) > 10000:  # bound memory: drop entries outside the window
        for k, t in list(_last_push.items()):
            if now - t >= TELEGRAM_COOLDOWN_SECONDS:
                _last_push.pop(k, None)
    return True


def _format_alert_message(status_code, edge_node, ip, url, rule_id, severity,
                          attack_type, ai_summary, time_local) -> str:
    """Telegram parse_mode=HTML message. Every value is escaped: the URL is
    attacker-controlled, and an unescaped `<script>` (a routine XSS probe)
    made Telegram reject the message, so exactly those alerts were silently
    dropped -- or a crafted `<a href>` could put a link into an admin's
    alert (F-039)."""
    e = lambda v: html.escape(str(v), quote=False)  # noqa: E731
    return (
        f"🚨 <b>WAF SECURITY ALERT ({e(status_code)})</b>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <b>Node:</b> <code>{e(edge_node)}</code>\n"
        f"📍 <b>Client IP:</b> <code>{e(ip)}</code>\n"
        f"🎯 <b>URL:</b> <code>{e(url[:500])}</code>\n"
        f"🛡️ <b>Rule ID:</b> <code>{e(rule_id)}</code> ({e(severity)})\n"
        f"⚠️ <b>Attack Type:</b> {e(attack_type)}\n\n"
        f"🤖 <b>[บทวิเคราะห์โดย AI]:</b>\n"
        f"<i>{e(ai_summary)}</i>\n"
        f"━━━━━━━━━━━━━━━━━━\n"
        f"⏰ <b>Time:</b> <code>{e(time_local)}</code>"
    )


def invalidate_user_cache():
    global _user_cache_ts
    _user_cache_ts = 0.0


async def dispatch_telegram_alert(data: dict):
    """Send real-time Telegram alert with Gemini AI Human-Readable Explanation and persist to DB"""
    try:
        ip = str(data.get("ip") or data.get("remote_addr") or data.get("client_ip") or "unknown").strip()
        url = str(data.get("url") or data.get("request_uri") or data.get("uri") or "unknown").strip()
        status_code = str(data.get("status") or data.get("status_code") or "403")
        time_local = str(data.get("datetime") or data.get("time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        attack_type = str(data.get("attack_type") or "WAF Security Block")
        rule_id = str(data.get("rule_id") or "WAF-CRS")
        severity = str(data.get("severity") or "CRITICAL")
        edge_node = str(data.get("edge_node") or data.get("region") or "Edge-TH")

        # 1. Generate human-readable AI explanation using Gemini 2.0/Flash
        ai_summary = await gemini_service.explain_attack(data)

        # 2. Save alert into AWS DynamoDB waf_alerts with AI analysis
        timestamp_int = int(data.get("timestamp") or time.time())
        rand_suffix = secrets.token_hex(2).upper()
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
                db.alerts_table.put_item,
                Item={
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
                    "ai_summary": ai_summary,
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
        # DynamoDB hiccup here must never take down the Telegram alert path.
        host = data.get("host")
        if host:
            try:
                await asyncio.to_thread(
                    threat_intel.record_pattern_hit_for_domain, host, rule_id, attack_type
                )
            except Exception as e:
                logger.warning("threat_intel pattern recording failed for %s: %s", host, e)

        if not BOT_TOKEN:
            logger.warning("Telegram BOT_TOKEN missing, alert not sent via Telegram")
            return

        # 3. Get registered users with chat_id from DynamoDB
        users = await asyncio.to_thread(_get_telegram_users)
        if not users:
            logger.warning("No users registered with telegram_chat_id")
            return

        origin = {}
        if origin_id != db.ALERTS_UNATTRIBUTED:
            origin = await asyncio.to_thread(db.get_origin_by_id, origin_id) or {}
        users = _alert_recipients(users, origin)
        if not users:
            logger.info("No Telegram recipients allowed to see alert for origin %s", origin_id)
            return

        if not _telegram_cooldown_ok((origin_id, ip, rule_id), time.time()):
            logger.info("Telegram push suppressed (cooldown) for %s %s %s", origin_id, ip, rule_id)
            return

        msg = _format_alert_message(status_code, edge_node, ip, url, rule_id, severity,
                                    attack_type, ai_summary, time_local)

        async with httpx.AsyncClient(timeout=6.0) as client:
            for user in users:
                chat_id = user.get("telegram_chat_id")
                if chat_id and str(chat_id).strip():
                    try:
                        res = await client.post(
                            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                            json={
                                "chat_id": chat_id,
                                "text": msg,
                                "parse_mode": "HTML"
                            }
                        )
                    except Exception as e:
                        print(f"❌ Failed to send Telegram alert to {chat_id}: {e}")

    except Exception as e:
        print(f"❌ Error in dispatch_telegram_alert: {e}")


async def alert_worker():
    logger.info("📡 Telegram Alert Worker active")
    while True:
        await asyncio.sleep(60)
