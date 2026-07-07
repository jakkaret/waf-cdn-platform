from fastapi import APIRouter, HTTPException, Depends
from services.dynamodb_service import DynamoDBService
from services.rbac import get_current_user
from services.telegram_listener import invalidate_user_cache
import os, secrets, time, httpx, asyncio, logging

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/api/alerts", tags=["alerts"])
db = DynamoDBService()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_BOTTOKEN", "")

# In-memory: code → {user_id, expires_at}
# [S4 FIX] ใช้ dict ธรรมดา แต่ cleanup อย่างถูกต้อง
_pending: dict = {}
_update_offset: int = 0


async def _cleanup_expired_codes():
    """Background task สำหรับลบ pairing codes ที่หมดอายุออกจาก _pending"""
    global _pending
    while True:
        now = time.time()
        # [S4 FIX] reassign _pending dict แทนการ .update() เพื่อลบ keys จริงๆ
        _pending = {k: v for k, v in _pending.items() if v.get("expires_at", 0) > now}
        await asyncio.sleep(60)  # cleanup ทุก 1 นาที


# GET /api/alerts/recent
@router.get("/recent")
async def get_recent_alerts(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
):
    try:
        if limit > 100:
            limit = 100
        response = db.alerts_table.scan(Limit=limit)
        alerts = response.get("Items", [])
        alerts.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
        return {"alerts": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# GET /api/alerts/connect/status
# เช็คว่า user ที่ login อยู่มี telegram_chat_id ใน DB แล้วหรือยัง
@router.get("/connect/status")
async def connect_status(current_user: dict = Depends(get_current_user)):
    chat_id = current_user.get("telegram_chat_id", "")
    return {
        "connected": bool(chat_id),
        "chat_id": str(chat_id) if chat_id else None,
    }


# POST /api/alerts/connect/start
# สร้าง one-time code ผูกกับ user_id
@router.post("/connect/start")
async def connect_start(current_user: dict = Depends(get_current_user)):
    global _pending
    if not BOT_TOKEN:
        raise HTTPException(
            status_code=500,
            detail="TELEGRAM_BOT_TOKEN not configured in .env"
        )

    code = secrets.token_hex(3).upper()   # 6-char เช่น "A3F2C1"
    user_id = current_user["user_id"]

    # [S4 FIX] ลบ code เก่าของ user นี้ออกจริงๆ ด้วยการ reassign dict ใหม่
    # .update() เดิมไม่ได้ reassign _pending จึงไม่ได้ลบ key เก่าออก
    _pending = {k: v for k, v in _pending.items() if v.get("user_id") != user_id}
    _pending[code] = {
        "user_id": user_id,
        "expires_at": time.time() + 300,  # 5 นาที
    }

    bot_username = await _get_bot_username()

    return {
        "code": code,
        "bot_username": bot_username,
        "expires_in": 300,
    }


# GET /api/alerts/connect/poll?code=XXXXXX
# frontend poll ทุก 3 วิ — เมื่อ bot รับ code
# จะ save chat_id ลง waf_users ของ user นั้น
@router.get("/connect/poll")
async def connect_poll(code: str, current_user: dict = Depends(get_current_user)):
    entry = _pending.get(code)

    if not entry:
        raise HTTPException(status_code=404, detail="Code not found or already used")

    if time.time() > entry["expires_at"]:
        _pending.pop(code, None)
        raise HTTPException(status_code=410, detail="Code expired")

    # ตรวจว่า code นี้เป็นของ user ที่ poll อยู่
    if entry["user_id"] != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Code mismatch")

    # Poll Telegram
    chat_id = await _check_telegram_for_code(code)
    logger.debug("Polling for code %s: chat_id=%s", code, chat_id)

    if chat_id:
        _pending.pop(code, None)
        # บันทึก chat_id ลง DynamoDB waf_users
        await _save_chat_id_to_user(current_user["user_id"], str(chat_id))
        # [R3 FIX] invalidate cache เพื่อให้ Telegram worker เห็น user ใหม่ทันที
        invalidate_user_cache()
        return {"status": "connected", "chat_id": str(chat_id)}

    return {"status": "waiting"}



# DELETE /api/alerts/connect  (disconnect)
@router.delete("/connect")
async def connect_disconnect(current_user: dict = Depends(get_current_user)):
    await _save_chat_id_to_user(current_user["user_id"], "")
    # [R3 FIX] invalidate cache เพื่อให้ Telegram worker ไม่ส่ง alert ไปยัง user ที่ disconnect แล้ว
    invalidate_user_cache()
    return {"status": "disconnected"}



# Helpers
async def _get_bot_username() -> str:
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://api.telegram.org/bot{BOT_TOKEN}/getMe"
            )
            if r.status_code == 200:
                return r.json()["result"]["username"]
    except Exception:
        pass
    return "automatedwafbot"


async def _check_telegram_for_code(target_code: str):
    global _update_offset
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.get(
                f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
                params={"offset": _update_offset, "timeout": 1, "limit": 50},
            )
            if r.status_code != 200:
                return None

            for update in r.json().get("result", []):
                _update_offset = update["update_id"] + 1
                msg     = update.get("message", {})
                text    = (msg.get("text") or "").strip()
                chat_id = msg.get("chat", {}).get("id")

                code_recv = None
                if text.upper().startswith("/START "):
                    code_recv = text.split(None, 1)[1].strip().upper()
                elif text.strip().upper() == target_code:
                    code_recv = text.strip().upper()

                if code_recv == target_code and chat_id:
                    # ส่ง welcome message
                    await client.post(
                        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                        json={
                            "chat_id": chat_id,
                            "text": (
                                "✅ *WAF Dashboard Connected!*\n\n"
                                "คุณจะได้รับแจ้งเตือนอัตโนมัติเมื่อ WAF ตรวจพบการโจมตี \n\n"
                                "_ระบบพร้อมแล้ว ไม่ต้องทำอะไรเพิ่มเติม_"
                            ),
                            "parse_mode": "Markdown",
                        },
                    )
                    return chat_id
    except Exception as e:
        print("Telegram poll error:", e)
    return None


async def _save_chat_id_to_user(user_id: str, chat_id: str):
    #อัพเดต telegram_chat_id ใน waf_users 
    try:
        db.waf_users.update_item(
            Key={"user_id": user_id},
            UpdateExpression="SET telegram_chat_id = :c",
            ExpressionAttributeValues={":c": chat_id},
        )
        print(f"Updated user {user_id} with chat_id {chat_id}")
    except Exception as e:
        print("Failed to save chat_id:", e)
        raise HTTPException(status_code=500, detail="Failed to save chat ID to database")
