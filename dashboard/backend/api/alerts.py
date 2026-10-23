# pyrefly: ignore [missing-import]
from fastapi import APIRouter, HTTPException, Depends
from services.dynamodb_service import DynamoDBService
# Imported from the sibling router rather than duplicated: this is the one
# place alert tenant-scoping is decided, and a second copy would be a
# second thing to get wrong (this endpoint's own hand-rolled filter is
# exactly what went wrong before).
from api.ai_summary import _visible_alerts_for_user, visible_incident_scopes
from db import pool
from pydantic import BaseModel, Field
from services import audit_log, notification_prefs
from services.txn import atomic
from services.tenant_service import get_user_origins_and_domains
from services.rbac import get_current_user, auth_service
from services import telegram_listener
from services.telegram_listener import invalidate_user_cache
import os, secrets, time, httpx, asyncio, logging, uuid, html
from typing import Optional

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
    limit: int = 200,
    current_user: dict = Depends(get_current_user),
):
    try:
        if limit > 500:
            limit = 500
        # 2026-09-23: this used to filter on a.get("user_id") == user_id.
        # waf_alerts' user_id has always been the constant "default-user"
        # written by services/telegram_listener.py, so that comparison was
        # false for every real account -- this endpoint returned an empty
        # list to every non-admin, which is why the Alerts page showed no
        # incidents while the dashboard's own notification feed (which used
        # the scoping below) showed unread ones. Same scoping as the feed
        # now: exact origin attribution, viewer/editor grants included.
        alerts = _visible_alerts_for_user(current_user, max_items=2000)

        return {"alerts": alerts[:limit]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# GET /api/alerts/incidents
# Attack incidents (services/alert_incidents.py), newest first. `incident`
# fetches one by id (the Telegram link), still only within the caller's scopes.
@router.get("/incidents")
async def get_incidents(
    limit: int = 20,
    origin: Optional[str] = None,
    incident: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    scopes = sorted(await asyncio.to_thread(visible_incident_scopes, current_user))
    if origin:
        scopes = [s for s in scopes if s == origin]
    if not scopes:
        return {"incidents": []}
    sql = ("SELECT i.incident_id::text AS incident_id, i.scope, i.origin_id::text AS origin_id, o.label, "
           "i.opened_at, i.last_seen_at, i.closed_at, i.blocked_count, i.ip_count, i.top_ips, i.top_types, "
           "i.top_paths, i.summary, i.summary_by_ai FROM alert_incidents i LEFT JOIN origins o ON o.id = i.origin_id "
           "WHERE i.scope = ANY(%s)")
    params: list = [scopes]
    if incident:
        try:
            uuid.UUID(incident)
        except ValueError:
            raise HTTPException(status_code=404, detail="Incident not found")
        sql += " AND i.incident_id = %s::uuid"
        params.append(incident)
    sql += " ORDER BY i.closed_at IS NULL DESC, i.opened_at DESC LIMIT %s"
    params.append(max(1, min(int(limit), 100)))
    rows = await asyncio.to_thread(pool.q, sql, tuple(params))
    for r in rows:
        for k in ("opened_at", "last_seen_at", "closed_at"):
            r[k] = r[k].isoformat() if r[k] else None
    return {"incidents": rows}


# Notification preferences (services/notification_prefs.py): per site, what
# this person is told on Telegram, and the site's attack sensitivity.
class PrefsUpdate(BaseModel):
    attacks: Optional[bool] = None
    outages: Optional[bool] = None
    certs: Optional[bool] = None
    team: Optional[bool] = None
    digest: Optional[bool] = None


class SensitivityUpdate(BaseModel):
    sensitivity: str = Field(pattern="^(low|medium|high)$")


def _my_sites(user_id: str) -> list:
    origin_ids, _active, _domains = get_user_origins_and_domains(user_id)
    sites = []
    for oid in origin_ids:
        origin = db.get_origin_by_id(oid)
        role = notification_prefs.role_on(origin, user_id)
        if origin and role:
            sites.append((origin, role))
    return sites


@router.get("/preferences")
async def get_preferences(current_user: dict = Depends(get_current_user)):
    user_id = current_user["user_id"]
    sites = await asyncio.to_thread(_my_sites, user_id)
    levels = await asyncio.to_thread(notification_prefs.sensitivities, [o["id"] for o, _r in sites])
    rows = {}
    if sites:
        rows = {str(r["origin_id"]): r for r in await asyncio.to_thread(
            pool.q, "SELECT * FROM notification_prefs WHERE user_id = %s::uuid", (user_id,))}
    return {
        "telegram_connected": bool(current_user.get("telegram_chat_id")),
        "levels": {k: {"total": t, "per_ip": i} for k, (t, i) in notification_prefs.SENSITIVITY.items()},
        "sites": [{
            "origin_id": o["id"], "label": o.get("label"), "role": role,
            "sensitivity": levels.get(o["id"], notification_prefs.DEFAULT_SENSITIVITY),
            "can_set_sensitivity": role in ("owner", "editor"),
            "prefs": notification_prefs.effective(role, rows.get(o["id"])),
            "changeable": sorted(notification_prefs.CHANGEABLE[role]),
        } for o, role in sites],
    }


@router.put("/preferences/{origin_id}")
async def put_preferences(origin_id: str, body: PrefsUpdate, current_user: dict = Depends(get_current_user)):
    origin = await asyncio.to_thread(db.get_origin_by_id, origin_id)
    role = notification_prefs.role_on(origin, current_user["user_id"])
    if not role:
        raise HTTPException(status_code=404, detail="Site not found")
    prefs = await asyncio.to_thread(notification_prefs.set_prefs, current_user["user_id"], origin["id"], role,
                                    body.model_dump(exclude_none=True))
    return {"prefs": prefs}


@router.put("/sensitivity/{origin_id}")
async def put_sensitivity(origin_id: str, body: SensitivityUpdate, current_user: dict = Depends(get_current_user)):
    origin = await asyncio.to_thread(db.get_origin_by_id, origin_id)
    role = notification_prefs.role_on(origin, current_user["user_id"])
    if not role:
        raise HTTPException(status_code=404, detail="Site not found")
    if role not in ("owner", "editor"):
        raise HTTPException(status_code=403, detail="Only the owner or an editor can change this site's sensitivity")
    await asyncio.to_thread(_set_sensitivity_audited, origin["id"], body.sensitivity, current_user)
    return {"sensitivity": body.sensitivity}


SENSITIVITY_TH = {"low": "ต่ำ", "medium": "กลาง", "high": "สูง"}


def _set_sensitivity_audited(origin_id: str, sensitivity: str, user: dict) -> None:
    with atomic():
        notification_prefs.set_sensitivity(origin_id, sensitivity, user["user_id"])
        audit_log.write_audit_event(
            scope_id=origin_id,
            actor_user_id=user.get("user_id"),
            actor_username=user.get("username", ""),
            action="alerts.sensitivity",
            summary=f"ตั้งความไวการแจ้งเตือนการโจมตีเป็น {SENSITIVITY_TH[sensitivity]}",
            details={"sensitivity": sensitivity},
        )


# Test message: only to the caller's own chat, at most once a minute per
# person. It lists what they receive now, so a wrong setting shows up too.
TEST_INTERVAL_SECONDS = 60
TEST_MAX_SITES = 20
_last_test: dict = {}
KIND_TH = {"attacks": "การโจมตี", "outages": "เว็บเปิดไม่ได้", "certs": "ใบรับรอง",
           "team": "คนอื่นแก้เว็บ", "digest": "สรุปรายวัน"}
ROLE_EN = {"owner": "Owner", "editor": "Editor", "viewer": "Viewer"}


def _test_message(user: dict) -> str:
    sites = _my_sites(user["user_id"])
    rows = {str(r["origin_id"]): r for r in pool.q(
        "SELECT * FROM notification_prefs WHERE user_id = %s::uuid", (user["user_id"],))} if sites else {}
    lines = ["🧪 <b>ทดสอบการแจ้งเตือน</b>",
             "ถ้าเห็นข้อความนี้ แปลว่า Telegram ของคุณรับแจ้งเตือนจาก WAF ได้", "", "ตอนนี้คุณรับเรื่องเหล่านี้:"]
    for origin, role in sites[:TEST_MAX_SITES]:
        on = notification_prefs.effective(role, rows.get(origin["id"]))
        kinds = ", ".join(KIND_TH[k] for k in notification_prefs.KINDS if on[k]) or "ปิดทั้งหมด"
        lines.append(f"• <b>{html.escape(origin.get('label') or 'เว็บไม่มีชื่อ', quote=False)}</b> ({ROLE_EN[role]}): {kinds}")
    if len(sites) > TEST_MAX_SITES:
        lines.append(f"• และอีก {len(sites) - TEST_MAX_SITES} เว็บ")
    if user.get("role") == "admin":
        lines.append("• <b>Support</b>: เหตุการณ์ที่ระบุเว็บไม่ได้ และใบรับรองของโดเมนแพลตฟอร์ม")
    elif not sites:
        lines.append("ยังไม่มีเว็บในบัญชีนี้ จึงยังไม่มีอะไรส่งมา")
    return "\n".join(lines)


def _test_failure(reason: str) -> HTTPException:
    r = reason.lower()
    if r == "no bot":
        return HTTPException(status_code=503, detail="ระบบยังไม่ได้ตั้งบอท Telegram แจ้ง Support")
    if "blocked" in r:
        return HTTPException(status_code=400, detail="คุณบล็อกบอทอยู่ เปิดแชตกับบอทใน Telegram แล้วกด Restart จากนั้นลองใหม่")
    if "chat not found" in r or "deactivated" in r:
        return HTTPException(status_code=400, detail="ไม่พบแชตนี้ใน Telegram ยกเลิกการเชื่อมแล้วเชื่อมใหม่")
    if "too many" in r:
        return HTTPException(status_code=429, detail="Telegram ให้รอสักครู่ ลองใหม่อีกครั้ง")
    return HTTPException(status_code=502, detail="ส่งไม่สำเร็จ ลองใหม่อีกครั้ง")


@router.post("/test")
async def send_test(current_user: dict = Depends(get_current_user)):
    chat_id = current_user.get("telegram_chat_id")
    if not chat_id:
        raise HTTPException(status_code=400, detail="ยังไม่ได้เชื่อม Telegram")
    now = time.monotonic()
    wait = TEST_INTERVAL_SECONDS - (now - _last_test.get(current_user["user_id"], -TEST_INTERVAL_SECONDS))
    if wait > 0:
        raise HTTPException(status_code=429, detail=f"ส่งทดสอบได้นาทีละครั้ง รออีก {int(wait) + 1} วินาที")
    _last_test[current_user["user_id"]] = now
    text = await asyncio.to_thread(_test_message, current_user)
    from services.site_alerts import _base_url
    base = _base_url()
    failure = await telegram_listener.send_telegram_to(
        chat_id, text, [("ตั้งค่าการแจ้งเตือน", f"{base}/alerts")] if base else None)
    if failure:
        raise _test_failure(failure)
    return {"sent": True}


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
        auth_service.set_telegram_chat_id(user_id, chat_id)
        print(f"Updated user {user_id} with chat_id {chat_id}")
    except Exception as e:
        print("Failed to save chat_id:", e)
        raise HTTPException(status_code=500, detail="Failed to save chat ID to database")
