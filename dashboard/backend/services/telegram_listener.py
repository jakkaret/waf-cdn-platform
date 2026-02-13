from telethon import TelegramClient
from dotenv import load_dotenv
from services.dynamodb_service import DynamoDBService

import asyncio
import os
import time

load_dotenv()

API_ID = int(os.getenv("TELEGRAM_API_ID"))
API_HASH = os.getenv("TELEGRAM_API_HASH")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = int(os.getenv("TELEGRAM_CHAT_ID"))
db = DynamoDBService()
alerted_events = {} # key -> timestamp
ALERT_TTL = 600  # 10 นาที


async def send_alert(message: str):
    client = TelegramClient(
        "waf_alert_bot",
        API_ID,
        API_HASH
    )

    await client.start(bot_token=BOT_TOKEN)
    await client.send_message(CHAT_ID, message)
    await client.disconnect()

# async def alert_403_if_new(ip, url):
#     key = f"{ip}|{url}"
#     now = time.time()

#     if key in alerted_events and now - alerted_events[key] < ALERT_TTL:
#         return

#     alerted_events[key] = now

#     # บันทึกลง DynamoDB
#     await save_alert("default-user", str(int(now)), ip, url, "403")

#     msg = f"""
#     🚨 WAF ALERT (403)
#     IP: {ip}
#     URL: {url}
#     Status: 403
#     """
#     await send_alert(msg)


async def alert_403_if_new(ip, url):
    key = f"{ip}|{url}"
    now = time.time()

    if key in alerted_events and now - alerted_events[key] < ALERT_TTL:
        return

    alerted_events[key] = now

    # บันทึกลง DynamoDB (sync)
    db.save_alert(
        "default-user",
        str(int(now)),
        ip,
        url,
        "403",
        "WAF 403 detected"
    )


    msg = f"""
    🚨 WAF ALERT (403)
    IP: {ip}
    URL: {url}
    Status: 403
    """
    await send_alert(msg)



#async def main():
#    msg = """
#        🚨 WAF ALERT
#        IP: 192.168.1.1
#        URL: /login.php
#        Attack: SQL Injection
#        Score: 0.91
#        Action: BLOCK
#        """
#    await send_alert(msg)
# asyncio.run(main())

# 🔁 background worker
async def alert_worker():
    print("📡 Telegram Alert Worker started")

    while True:
        # TODO: ตรงนี้อนาคตจะเป็น parse log จริง
        await alert_403_if_new("192.168.1.1", "/login.php")

        await asyncio.sleep(10)  # กัน CPU พัง