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
from services.rbac import require_viewer_or_above
from services.tenant_service import get_user_origins_and_domains, build_tenant_origin_filter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/copilot", tags=["copilot"])

ch = ClickHouseService()
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
    is_admin = current_user.get("role") == "admin"
    origin_ids, _active_origins, user_domains = get_user_origins_and_domains(user_id)
    # An admin with no domains still legitimately has global scope ("ALL");
    # a non-admin with no domains has no scope at all -- these are not the
    # same case and must not share a query path.
    has_scope = is_admin or bool(user_domains)

    # 1. Fetch live telemetry context from ClickHouse -- 2026-09-20 fix: this
    # used to query access_logs with no tenant filter whatsoever (confirmed
    # live: a zero-origin account asking "which IPs are attacking me" got
    # back other tenants' real attacker IPs, payloads and timestamps,
    # labelled in the prompt below as "this user's own system"). Every query
    # is now scoped through the same build_tenant_origin_filter used by
    # GET /api/analytics/summary, and a non-admin with zero origins skips
    # querying entirely rather than asking ClickHouse an unscoped question.
    context_data = {
        "user": username,
        "domains_under_management": user_domains or (["ALL (Admin - Global Visibility)"] if is_admin else []),
        "origins_count": len(origin_ids),
        "total_requests_24h": 0,
        "blocked_threats_24h": 0,
        "top_attack_types": [],
        "top_attacker_ips": [],
        "recent_security_events": []
    }

    if ch.connected and has_scope:
        try:
            origin_clause = build_tenant_origin_filter("ALL", user_domains, is_admin)
            scope_sql = f"AND {origin_clause}" if origin_clause else ""

            stats_q = f"""
            SELECT
                count() as total_reqs,
                countIf(status_code = 403 OR status_code = 429) as blocked_reqs
            FROM access_logs
            WHERE timestamp >= now() - INTERVAL 24 HOUR {scope_sql}
            """
            stats_res = ch.query_stats(stats_q)
            if stats_res:
                context_data["total_requests_24h"] = int(stats_res[0][0] or 0)
                context_data["blocked_threats_24h"] = int(stats_res[0][1] or 0)

            attack_q = f"""
            SELECT attack_type, count() as cnt
            FROM access_logs
            WHERE status_code IN (403, 429) AND attack_type != '' {scope_sql}
            GROUP BY attack_type
            ORDER BY cnt DESC
            LIMIT 5
            """
            for r in ch.query_stats(attack_q):
                context_data["top_attack_types"].append(f"{r[0]}: {r[1]} ครั้ง")

            ip_q = f"""
            SELECT client_ip, country, count() as cnt
            FROM access_logs
            WHERE status_code IN (403, 429) {scope_sql}
            GROUP BY client_ip, country
            ORDER BY cnt DESC
            LIMIT 5
            """
            for r in ch.query_stats(ip_q):
                context_data["top_attacker_ips"].append(f"IP: {r[0]} ({r[1] or 'Unknown'}) ยิงมา {r[2]} ครั้ง")

            recent_q = f"""
            SELECT timestamp, client_ip, method, url, status_code, attack_type, rule_id
            FROM access_logs
            WHERE status_code IN (403, 429) {scope_sql}
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
    no_scope_notice = (
        "\n\n⚠️ สำคัญที่สุด: บัญชีนี้ยังไม่มี Origin Server ผูกไว้เลย ตัวเลขและรายการด้านบนจึงเป็นศูนย์/ว่างเปล่าโดยตั้งใจ "
        "ห้ามอ้างอิง สมมติ หรือหยิบยก IP, URL, จำนวนครั้ง หรือเหตุการณ์ใดๆ มาตอบเด็ดขาด แม้จะฟังดูสมเหตุสมผลหรือมีใน "
        "ความรู้ทั่วไปของคุณก็ตาม ให้ตอบตรงไปตรงมาว่าบัญชีนี้ยังไม่มีข้อมูลทราฟฟิก เพราะยังไม่ได้เพิ่ม Origin Server "
        "และแนะนำให้ไปที่หน้า Origin Servers เพื่อเพิ่มก่อน\n"
    ) if not has_scope else ""

    system_instruction = (
        "คุณคือ 'WAF AI Copilot' ผู้ช่วยอัจฉริยะด้านความปลอดภัยไซเบอร์ประจำระบบ Enterprise WAF & CDN Dashboard\n"
        "คุณมีหน้าที่ช่วยเหลือ SecOps / ผู้ดูแลระบบ ในการวิเคราะห์ Log, ตรวจสอบภัยคุกคาม, อธิบายสาเหตุของการบล็อก, และแนะนำวิธีป้องกัน\n\n"
        f"ข้อมูลบริบทสดของระบบในความดูแลของผู้ใช้ ({username}):\n"
        f"{json.dumps(context_data, ensure_ascii=False, indent=2)}"
        f"{no_scope_notice}\n\n"
        "แนวทางการตอบคำถาม:\n"
        "1. ตอบเป็นภาษาไทยอย่างมืออาชีพ สุภาพ ชัดเจน กระชับ และตรงประเด็น\n"
        "2. ใช้ Markdown จัดรูปแบบ เช่น **ตัวหนา**, `โค้ด/ไอพี`, Bullet points และ Emoji ประกอบเพื่อให้อ่านง่าย\n"
        "3. อ้างอิงตัวเลขและข้อมูลจริงจาก telemetry ด้านบนเสมอ (เช่น จำนวนบล็อก, รายชื่อ IP หรือ URL เป้าหมาย) "
        "ห้ามอ้างอิงหรือสมมติข้อมูลใดๆ ที่ไม่ได้อยู่ใน telemetry ด้านบน\n"
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
