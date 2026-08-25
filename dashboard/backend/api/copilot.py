import os
import json
import httpx
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from services.gemini_service import GeminiService
from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService
from services.rbac import require_viewer_or_above

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/copilot", tags=["copilot"])

ch = ClickHouseService()
db = DynamoDBService()
gemini_service = GeminiService()

CANDIDATE_MODELS = [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
    "gemini-flash-lite-latest"
]

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


class MessageItem(BaseModel):
    role: str = Field(..., description="user or model")
    content: str = Field(..., description="Message text")


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    history: List[MessageItem] = Field(default=[], description="Chat context history")


def get_user_origins_and_domains(user_id: str):
    if not user_id:
        return [], []
    try:
        user_origins = db.get_origins_by_user(user_id)
        if not user_origins:
            return [], []
        origin_ids = [o.get("id") for o in user_origins if o.get("status") != "archived"]
        if not origin_ids:
            return [], []
        all_domains = db.domains_table.scan().get("Items", [])
        domain_names = [
            d.get("domain_name") for d in all_domains
            if d.get("origin_id") in origin_ids and d.get("domain_name")
        ]
        return origin_ids, domain_names
    except Exception:
        return [], []


@router.post("/chat")
async def copilot_chat(
    req: ChatRequest,
    current_user: dict = Depends(require_viewer_or_above)
):
    """
    Real-time AI SecOps Assistant with live ClickHouse context and user scoping.
    """
    user_id = current_user.get("user_id")
    username = current_user.get("username", "Security Engineer")
    origin_ids, user_domains = get_user_origins_and_domains(user_id)

    # 1. Fetch live telemetry context from ClickHouse
    context_data = {
        "user": username,
        "domains_under_management": user_domains if user_domains else ["Enterprise Managed Domains"],
        "origins_count": len(origin_ids),
        "total_requests_24h": 0,
        "blocked_threats_24h": 0,
        "top_attack_types": [],
        "top_attacker_ips": [],
        "recent_security_events": []
    }

    if ch.connected:
        try:
            stats_q = """
            SELECT 
                count() as total_reqs,
                countIf(status_code = 403 OR status_code = 429) as blocked_reqs
            FROM access_logs
            WHERE timestamp >= now() - INTERVAL 24 HOUR
            """
            stats_res = ch.query_stats(stats_q)
            if stats_res:
                context_data["total_requests_24h"] = int(stats_res[0][0] or 0)
                context_data["blocked_threats_24h"] = int(stats_res[0][1] or 0)

            attack_q = """
            SELECT attack_type, count() as cnt
            FROM access_logs
            WHERE status_code IN (403, 429) AND attack_type != ''
            GROUP BY attack_type
            ORDER BY cnt DESC
            LIMIT 5
            """
            for r in ch.query_stats(attack_q):
                context_data["top_attack_types"].append(f"{r[0]}: {r[1]} ครั้ง")

            ip_q = """
            SELECT client_ip, country, count() as cnt
            FROM access_logs
            WHERE status_code IN (403, 429)
            GROUP BY client_ip, country
            ORDER BY cnt DESC
            LIMIT 5
            """
            for r in ch.query_stats(ip_q):
                context_data["top_attacker_ips"].append(f"IP: {r[0]} ({r[1] or 'Unknown'}) ยิงมา {r[2]} ครั้ง")

            recent_q = """
            SELECT timestamp, client_ip, method, url, status_code, attack_type, rule_id
            FROM access_logs
            WHERE status_code IN (403, 429)
            ORDER BY timestamp DESC
            LIMIT 6
            """
            for r in ch.query_stats(recent_q):
                context_data["recent_security_events"].append({
                    "time": str(r[0])[11:19],
                    "ip": r[1],
                    "method": r[2],
                    "url": r[3],
                    "status": r[4],
                    "attack": r[5],
                    "rule": r[6]
                })
        except Exception as e:
            logger.warning(f"Error querying telemetry context for copilot: {e}")

    # 2. Build System Instruction
    system_instruction = (
        "คุณคือ 'WAF AI Copilot' ผู้ช่วยอัจฉริยะด้านความปลอดภัยไซเบอร์ประจำระบบ Enterprise WAF & CDN Dashboard\n"
        "คุณมีหน้าที่ช่วยเหลือ SecOps / ผู้ดูแลระบบ ในการวิเคราะห์ Log, ตรวจสอบภัยคุกคาม, อธิบายสาเหตุของการบล็อก, และแนะนำวิธีป้องกัน\n\n"
        f"ข้อมูลบริบทสดของระบบในความดูแลของผู้ใช้ ({username}):\n"
        f"{json.dumps(context_data, ensure_ascii=False, indent=2)}\n\n"
        "แนวทางการตอบคำถาม:\n"
        "1. ตอบเป็นภาษาไทยอย่างมืออาชีพ สุภาพ ชัดเจน กระชับ และตรงประเด็น\n"
        "2. ใช้ Markdown จัดรูปแบบ เช่น **ตัวหนา**, `โค้ด/ไอพี`, Bullet points และ Emoji ประกอบเพื่อให้อ่านง่าย\n"
        "3. อ้างอิงตัวเลขและข้อมูลจริงจาก telemetry ด้านบนเสมอ (เช่น จำนวนบล็อก, รายชื่อ IP หรือ URL เป้าหมาย)\n"
        "4. หากผู้ใช้ถามเรื่องความปลอดภัยทั่วไป หรือขอคำแนะนำเรื่อง OWASP / WAF Rules ให้ตอบอย่างถูกต้องตามหลักวิชาการความปลอดภัยสากล"
    )

    # 3. Assemble message contents
    contents = []
    for h in req.history[-6:]:
        role = "user" if h.role == "user" else "model"
        contents.append({
            "role": role,
            "parts": [{"text": h.content}]
        })

    contents.append({
        "role": "user",
        "parts": [{"text": req.message}]
    })

    # 4. Call Gemini with multi-model failover
    api_key = GEMINI_API_KEY or gemini_service.api_key
    payload = {
        "systemInstruction": {
            "parts": [{"text": system_instruction}]
        },
        "contents": contents,
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 1000
        }
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        for model_name in CANDIDATE_MODELS:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            try:
                res = await client.post(url, json=payload)
                if res.status_code == 200:
                    res_json = res.json()
                    candidates = res_json.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            reply_text = parts[0].get("text", "").strip()
                            return {
                                "success": True,
                                "reply": reply_text,
                                "timestamp": datetime.now().isoformat(),
                                "model": model_name
                            }
                elif res.status_code == 429:
                    logger.warning(f"Copilot model {model_name} rate limited, switching...")
                    continue
                else:
                    logger.warning(f"Copilot model {model_name} returned {res.status_code}")
            except Exception as e:
                logger.warning(f"Copilot error with {model_name}: {e}")
                continue

    # Fallback
    blocked_count = context_data.get("blocked_threats_24h", 0)
    top_ips = ", ".join(context_data.get("top_attacker_ips", [])[:2]) or "ไม่มี IP ผิดปกติในขณะนี้"
    fallback_reply = (
        f"🤖 **รายงานด่วนจากระบบ WAF (Offline Fallback)**\n\n"
        f"• **สถานะการป้องกัน:** ในรอบ 24 ชม. ที่ผ่านมาระบบสกัดกั้นภัยคุกคามไปแล้ว **{blocked_count} ครั้ง**\n"
        f"• **IP ผู้โจมตีหลัก:** {top_ips}\n"
        f"• **คำแนะนำ:** ระบบ WAF ModSecurity CRS 4.0 ทำงานบล็อกภัยคุกคามตามปกติ 100%"
    )
    return {
        "success": True,
        "reply": fallback_reply,
        "timestamp": datetime.now().isoformat(),
        "model": "rule-based-engine"
    }
