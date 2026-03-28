from asyncio import log
from telethon import TelegramClient
from dotenv import load_dotenv
from services.dynamodb_service import DynamoDBService
from boto3.dynamodb.conditions import Attr
import asyncio
import os
import time




load_dotenv()
db = DynamoDBService()
API_ID = int(os.getenv("TELEGRAM_API_ID"))
API_HASH = os.getenv("TELEGRAM_API_HASH")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = int(os.getenv("TELEGRAM_CHAT_ID"))


alerted_events = {} # key -> timestamp
ALERT_TTL = 600  # 10 นาที


# async def send_alert(message: str):
#     client = TelegramClient(
#         "waf_alert_bot",
#         API_ID,
#         API_HASH
#     )

#     await client.start(bot_token=BOT_TOKEN)
#     await client.send_message(CHAT_ID, message)
#     await client.disconnect()

# อันนี้สำหรับทดสอบเฉยๆ ถ้าใช้จริงจะใช้ background worker ด้านล่างแทน
# async def alert_403_if_new(ip, url):
#     key = f"{ip}|{url}"
#     now = time.time()

#     if key in alerted_events and now - alerted_events[key] < ALERT_TTL:
#         return

#     alerted_events[key] = now

#     # บันทึกลง DynamoDB (sync)
#     db.save_alert(
#         "default-user",
#         str(int(now)),
#         ip,
#         url,
#         "403",
#         "WAF 403 detected"
#     )


#     msg = f"""
#         🚨 WAF ALERT (403)
#         IP: {ip}
#         URL: {url}
#         Status: 403
#         """
#     await send_alert(msg)



# 🔁 background worker
async def alert_worker():
    print("📡 Telegram Alert Worker started")

    client = TelegramClient("waf_alert_bot", API_ID, API_HASH)
    await client.start(bot_token=BOT_TOKEN)  # ← start ด้วย bot token ตรงๆ

    try:
        while True:
            logs = db.get_unalerted_403_logs()
            print("DEBUG logs:", logs)

            if logs:
                print(f"Found {len(logs)} new 403 logs")

            for log in logs:
                ip = log.get("remote_addr", "unknown")
                url = log.get("request", "unknown")
                timestamp = log.get("timestamp")
                time_local = log.get("time_local", "unknown")
                user_id = log.get("user_id", "default-user")

                if not timestamp:
                    continue

                msg = f"🚨 WAF ALERT (403)\nIP: {ip}\nURL: {url}\nStatus: 403\nTime: {time_local}"

                await client.send_message(CHAT_ID, msg)

                db.save_alert(
                    user_id=user_id,
                    alert_id=str(timestamp),
                    ip=ip,
                    url=url,
                    status="403",
                    message="WAF 403 detected"
                )

                db.mark_log_alerted(user_id, timestamp)

            await asyncio.sleep(5)

    finally:
        await client.disconnect()