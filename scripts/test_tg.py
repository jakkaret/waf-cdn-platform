import os
import httpx
import asyncio
from dotenv import load_dotenv

load_dotenv()
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_BOTTOKEN")
print("Bot Token present:", bool(BOT_TOKEN))

async def test_send():
    async with httpx.AsyncClient(timeout=10.0) as client:
        for chat_id in ["8273669996", "8430139856"]:
            try:
                res = await client.post(
                    f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                    json={"chat_id": chat_id, "text": "🛡️ [WAF SYSTEM TEST] Telegram Alert Channel is Active!"}
                )
                print(f"Chat {chat_id} result:", res.status_code, res.json().get("ok"))
            except Exception as e:
                print(f"Chat {chat_id} error:", e)

asyncio.run(test_send())
