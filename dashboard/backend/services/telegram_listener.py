from telethon import TelegramClient
from dotenv import load_dotenv
from services.dynamodb_service import DynamoDBService
from boto3.dynamodb.conditions import Attr
import asyncio
import logging
import os
import time

load_dotenv()

logger = logging.getLogger(__name__)

db = DynamoDBService()
_api_id_raw = os.getenv("TELEGRAM_API_ID")
API_ID = int(_api_id_raw) if _api_id_raw and _api_id_raw.isdigit() else None
API_HASH = os.getenv("TELEGRAM_API_HASH")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_BOTTOKEN")

# [R3 FIX] Cache user list แทนการ scan DynamoDB ทุก 5 วินาที
# cache จะถูก refresh อัตโนมัติเมื่อครบ USER_CACHE_TTL วินาที
_user_cache: list = []
_user_cache_ts: float = 0.0
USER_CACHE_TTL = 60  # วินาที — refresh ทุก 1 นาที

alerted_events = {}  # key -> timestamp
ALERT_TTL = 600  # 10 นาที


def _get_telegram_users() -> list:
    """
    [R3 FIX] ดึง users ที่มี telegram_chat_id โดยใช้ cache TTL 60 วินาที
    แทนการ scan DynamoDB ทุก 5 วินาที (loop ของ alert_worker)
    """
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
    """เรียกเมื่อมีการ connect/disconnect Telegram เพื่อ force refresh"""
    global _user_cache_ts
    _user_cache_ts = 0.0


# 🔁 background worker
async def alert_worker():
    logger.info("📡 Telegram Alert Worker started")
    if not API_ID or not API_HASH or not BOT_TOKEN:
        logger.warning(
            "⚠️ Telegram worker disabled: missing TELEGRAM_API_ID/TELEGRAM_API_HASH/TELEGRAM_BOT_TOKEN"
        )
        return

    client = TelegramClient("waf_alert_bot", API_ID, API_HASH)
    await client.start(bot_token=BOT_TOKEN)

    try:
        while True:
            logs = db.get_unalerted_403_logs()
            # [Q4 FIX] เปลี่ยนจาก print("DEBUG logs:", logs) → logging.debug
            logger.debug("Fetched unalerted 403 logs: %d entries", len(logs))

            if logs:
                logger.info("Found %d new 403 logs to alert", len(logs))

            # [R3 FIX] ใช้ cached user list แทนการ scan ทุก loop
            users = _get_telegram_users()

            for log in logs:
                ip = log.get("ip", "unknown")
                url = log.get("url", "unknown")
                timestamp = log.get("timestamp")
                time_local = log.get("datetime", "unknown")
                user_id = log.get("user_id", "default-user")

                if not timestamp:
                    continue

                msg = (
                    f"🚨 WAF ALERT (403)\n"
                    f"IP: {ip}\n"
                    f"URL: {url}\n"
                    f"Status: 403\n"
                    f"Time: {time_local}"
                )

                # ส่งให้ทุก user ที่มี telegram_chat_id
                for user in users:
                    chat_id = user.get("telegram_chat_id")
                    if chat_id:
                        try:
                            await client.send_message(int(chat_id), msg)
                        except Exception as e:
                            logger.error("Send telegram error to %s: %s", chat_id, e)

                # save alert
                db.save_alert(
                    user_id=user_id,
                    alert_id=str(timestamp),
                    ip=ip,
                    url=url,
                    status="403",
                    message="WAF 403 detected"
                )

                # mark alerted
                db.mark_log_alerted(user_id, timestamp)

            await asyncio.sleep(5)

    finally:
        await client.disconnect()
