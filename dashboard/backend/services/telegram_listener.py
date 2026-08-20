import asyncio
import logging
import os
import time
import httpx
from datetime import datetime
from dotenv import load_dotenv
from services.dynamodb_service import DynamoDBService
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


def invalidate_user_cache():
    global _user_cache_ts
    _user_cache_ts = 0.0


async def dispatch_telegram_alert(data: dict):
    """Send real-time Telegram alert for 403 / 429 / Critical attacks and save to DynamoDB waf_alerts"""
    try:
        ip = str(data.get("ip") or data.get("remote_addr") or data.get("client_ip") or "unknown").strip()
        url = str(data.get("url") or data.get("request_uri") or data.get("uri") or "unknown").strip()
        status_code = str(data.get("status") or data.get("status_code") or "403")
        time_local = str(data.get("datetime") or data.get("time") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        attack_type = str(data.get("attack_type") or "WAF Security Block")
        rule_id = str(data.get("rule_id") or "WAF-CRS")
        severity = str(data.get("severity") or "CRITICAL")
        edge_node = str(data.get("edge_node") or data.get("region") or "Edge-TH")

        # 1. Save alert into AWS DynamoDB waf_alerts
        timestamp_int = int(data.get("timestamp") or time.time())
        try:
            db.save_alert(
                user_id="default-user",
                alert_id=f"{timestamp_int}-{ip}",
                ip=ip,
                url=url,
                status=status_code,
                message=f"{attack_type} (Rule: {rule_id})"
            )
        except Exception as err:
            logger.error("Error saving alert to DynamoDB: %s", err)

        if not BOT_TOKEN:
            logger.warning("Telegram BOT_TOKEN missing, alert not sent via Telegram")
            return

        # 2. Get registered users with chat_id from DynamoDB
        users = _get_telegram_users()
        if not users:
            logger.warning("No users registered with telegram_chat_id")
            return

        msg = (
            f"🚨 <b>WAF SECURITY ALERT ({status_code})</b>\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🌐 <b>Node:</b> <code>{edge_node}</code>\n"
            f"📍 <b>Client IP:</b> <code>{ip}</code>\n"
            f"🎯 <b>URL:</b> <code>{url}</code>\n"
            f"🛡️ <b>Rule ID:</b> <code>{rule_id}</code> ({severity})\n"
            f"⚠️ <b>Attack Type:</b> {attack_type}\n"
            f"⏰ <b>Time:</b> <code>{time_local}</code>"
        )

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
                        print(f"✅ Telegram Alert sent to chat_id: {chat_id}, status: {res.status_code}")
                    except Exception as e:
                        print(f"❌ Failed to send Telegram alert to {chat_id}: {e}")

    except Exception as e:
        print(f"❌ Error in dispatch_telegram_alert: {e}")


# Background worker placeholder (kept for lifecycle compatibility)
async def alert_worker():
    logger.info("📡 Telegram Alert Worker active")
    while True:
        await asyncio.sleep(60)
