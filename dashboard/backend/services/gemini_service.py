import os
import time
import json
import logging
import httpx
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

load_dotenv()
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
BASE_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

class GeminiService:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
        # LRU Cache: hash(attack_key) -> {"summary": text, "timestamp": time.time()}
        self._attack_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 300  # 5 minutes cache for duplicate attack signatures

    def _get_attack_signature_key(self, data: Dict[str, Any]) -> str:
        """Create a compact signature key for deduplication"""
        url = str(data.get("url") or data.get("request_uri") or "").split("?")[0]
        method = str(data.get("method") or "GET")
        rule_id = str(data.get("rule_id") or "0")
        attack_type = str(data.get("attack_type") or "unknown")
        return f"{method}:{url}:{rule_id}:{attack_type}"

    async def explain_attack(self, data: Dict[str, Any]) -> str:
        """
        Explain a blocked attack in 1-2 concise Thai sentences for SecOps alert.
        Uses in-memory cache to avoid repeated API calls for same attack types.
        """
        sig_key = self._get_attack_signature_key(data)
        now = time.time()

        # Check cache
        if sig_key in self._attack_cache:
            cached = self._attack_cache[sig_key]
            if now - cached["timestamp"] < self._cache_ttl:
                return cached["summary"]

        ip = str(data.get("ip") or data.get("client_ip") or "Unknown")
        url = str(data.get("url") or data.get("request_uri") or "/")
        method = str(data.get("method") or "GET")
        rule_id = str(data.get("rule_id") or "OWASP-CRS")
        attack_type = str(data.get("attack_type") or "WAF Security Block")
        status = str(data.get("status") or data.get("status_code") or "403")
        country = str(data.get("country") or "")

        prompt = (
            "คุณคือ AI Security Analyst ประจำระบบ WAF จงวิเคราะห์และสรุปเหตุการณ์การโจมตีนี้ให้เข้าใจง่าย "
            "ใน 1-2 ประโยคสั้นๆ ภาษาไทย โดยบอกว่าผู้โจมตีพยายามทำอะไร (เช่น แอบดูไฟล์ลับ, ยิง SQLi, เจาะหลังบ้าน) "
            "และระบบ WAF บล็อกไว้ได้อย่างไร (ห้ามเกริ่น ตอบสรุปเนื้อหาทันที):\n"
            f"- Client IP: {ip} {f'({country})' if country else ''}\n"
            f"- Target URL: {url}\n"
            f"- Method: {method}\n"
            f"- Rule Triggered: {rule_id} ({attack_type})\n"
            f"- Action: {status} Blocked"
        )

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(
                    f"{BASE_URL}?key={self.api_key}",
                    json={
                        "contents": [{
                            "parts": [{"text": prompt}]
                        }],
                        "generationConfig": {
                            "temperature": 0.2,
                            "maxOutputTokens": 150
                        }
                    }
                )

                if res.status_code == 200:
                    res_json = res.json()
                    candidates = res_json.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            summary_text = parts[0].get("text", "").strip()
                            # Save to cache
                            self._attack_cache[sig_key] = {
                                "summary": summary_text,
                                "timestamp": now
                            }
                            return summary_text
                else:
                    logger.error(f"Gemini API error: {res.status_code} {res.text}")

        except Exception as e:
            logger.error(f"Failed to call Gemini API for attack explanation: {e}")

        # Intelligent rule-based fallback if API is unavailable
        fallback_msg = f"ตรวจพบการส่งคำขอที่มีความเสี่ยง ({attack_type}) ไปยัง {url} โดยระบบ WAF ได้ทำการบล็อก ({status}) เพื่อความปลอดภัยเรียบร้อยแล้ว"
        return fallback_msg

    async def parse_natural_time_range(self, query_text: str) -> Dict[str, Any]:
        """
        Parse user's natural language time request (e.g. 'สรุป 3 วันล่าสุด', 'เมื่อวานถึงเที่ยงวันนี้')
        into ISO/SQL timestamps.
        """
        now = datetime.now()
        prompt = (
            f"Current local time: {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"User query in Thai/English: \"{query_text}\"\n"
            "Convert this natural language query into a precise start_time and end_time range for database querying.\n"
            "Return ONLY a valid JSON object in this exact format (no markdown, no backticks):\n"
            "{\n"
            "  \"start_time\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "  \"end_time\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "  \"description\": \"คำอธิบายช่วงเวลาเป็นภาษาไทย เช่น 'ช่วง 3 วันล่าสุด'\"\n"
            "}"
        )

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.post(
                    f"{BASE_URL}?key={self.api_key}",
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.1,
                            "responseMimeType": "application/json"
                        }
                    }
                )
                if res.status_code == 200:
                    res_json = res.json()
                    candidates = res_json.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        return json.loads(text)
        except Exception as e:
            logger.error(f"Failed to parse time range with Gemini: {e}")

        # Default fallback: last 24 hours
        start = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        end = now.strftime("%Y-%m-%d %H:%M:%S")
        return {
            "start_time": start,
            "end_time": end,
            "description": "ช่วง 24 ชั่วโมงล่าสุด (ค่าเริ่มต้น)"
        }

    async def generate_range_summary(self, time_desc: str, stats: Dict[str, Any]) -> str:
        """
        Generate comprehensive SecOps executive summary for dashboard display.
        """
        prompt = (
            "คุณคือ AI Senior Security Operations Lead จงสรุปรายงานสถานการณ์ความปลอดภัยของระบบ WAF & CDN "
            f"สำหรับช่วง: {time_desc} โดยใช้ภาษาไทยที่อ่านง่าย ชัดเจน ตรงประเด็นสำหรับผู้บริหารและวิศวกร\n\n"
            f"สถิติเหตุการณ์จากระบบ:\n{json.dumps(stats, ensure_ascii=False, indent=2)}\n\n"
            "กรุณาสรุปตามหัวข้อต่อไปนี้:\n"
            "1. 🛡️ สรุปภาพรวมความปลอดภัย (ระดับความเสี่ยง, อัตราการบล็อก)\n"
            "2. ⚠️ รูปแบบการโจมตีที่พบบ่อย (Top Attack Vectors & Targets)\n"
            "3. 💡 ข้อเสนอแนะในการปรับปรุงความปลอดภัย (Actionable Recommendations)"
        )

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(
                    f"{BASE_URL}?key={self.api_key}",
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.3,
                            "maxOutputTokens": 800
                        }
                    }
                )
                if res.status_code == 200:
                    candidates = res.json().get("candidates", [])
                    if candidates:
                        return candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "").strip()
        except Exception as e:
            logger.error(f"Failed to generate range summary: {e}")

        return "ไม่สามารถสร้างบทสรุป AI ได้ในขณะนี้ โปรดตรวจสอบการเชื่อมต่อ API"

gemini_service = GeminiService()
