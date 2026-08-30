import os
import time
import json
import logging
import httpx
from dotenv import load_dotenv
from datetime import datetime, timedelta
from typing import Dict, Any, List

load_dotenv()
logger = logging.getLogger(__name__)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
BASE_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"

# T10: static Thai label for every ml/feature_engineering.py FEATURE_COLUMNS
# entry, used both to compose the no-Gemini-available fallback sentence and
# to keep the Gemini prompt's feature names understandable if it ever quotes
# them back. Keep in sync with FEATURE_COLUMNS (ml/feature_engineering.py:133-147).
FEATURE_LABELS_TH: Dict[str, str] = {
    "special_char_count": "จำนวนอักขระพิเศษที่พบในคำขอ",
    "special_char_ratio": "สัดส่วนอักขระพิเศษต่อความยาวคำขอ",
    "keyword_matches": "จำนวนคำสำคัญที่เข้าข่ายการโจมตีที่พบ",
    "html_tag_matches": "จำนวนแท็ก HTML ที่พบในคำขอ",
    "path_traversal_depth": "ความพยายามไต่ระดับไดเรกทอรีนอกขอบเขต (Path Traversal)",
    "quote_unbalanced": "เครื่องหมายคำพูดที่ไม่สมดุลในคำขอ",
    "has_sql_operator": "การพบคำสั่งหรือโอเปอเรเตอร์ SQL ที่น่าสงสัย",
    "has_ssrf_token": "การพบคำที่เกี่ยวข้องกับการโจมตี SSRF",
    "has_ssti_nosql": "การพบรูปแบบการโจมตี SSTI หรือ NoSQL Injection",
    "is_oversized_payload": "ขนาดคำขอที่ใหญ่ผิดปกติ",
    "is_clean_structure": "โครงสร้างคำขอที่ดูปกติ ไม่มีสัญญาณผิดปกติ",
    "has_excessive_params": "จำนวนพารามิเตอร์ที่มากเกินไป",
    "method_is_post": "การใช้ HTTP Method แบบ POST",
}


class GeminiService:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model = os.getenv("GEMINI_MODEL", "gemini-flash-lite-latest")
        # LRU Cache: hash(attack_key) -> {"summary": text, "timestamp": time.time()}
        self._attack_cache: Dict[str, Dict[str, Any]] = {}
        # Separate cache for attribution explanations (T10), keyed on its own
        # signature shape but honouring the same self._cache_ttl.
        self._attribution_cache: Dict[str, Dict[str, Any]] = {}
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

    @staticmethod
    def _truncate(value: Any, limit: int) -> str:
        """Bound any attacker-influenced field (request URL/method/body) before
        it is concatenated into a Gemini prompt (T10 security constraint)."""
        text = str(value or "")
        return text if len(text) <= limit else text[:limit] + "...(truncated)"

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        """Never raises: a malformed/missing `contribution` (acceptance
        criterion 2 requires explain_attribution to never raise, not just to
        survive network failures) degrades to `default` instead of
        propagating a ValueError/TypeError out of sorting/formatting."""
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _as_attribution_items(attribution: Any) -> List[Dict[str, Any]]:
        """Total, never-raising coercion of `attribution` into a list of
        dict-shaped items.

        This is the single choke point every other helper below routes
        through, so a caller cannot bypass it by accident: `attribution`
        not being a list at all (a string, a dict, an int, ...) yields [];
        a list containing non-dict entries (None, a bare string, ...)
        silently drops just those entries. This is the actual last line of
        defence for the fallback path -- it must be total, not merely
        likely-safe, because detection availability must never depend on
        every element of `attribution` having the expected shape.
        """
        if not isinstance(attribution, list):
            return []
        return [item for item in attribution if isinstance(item, dict)]

    def _top_contributors(self, attribution: Any, limit: int = 5) -> List[Dict[str, Any]]:
        items = self._as_attribution_items(attribution)
        return sorted(
            items,
            key=lambda item: abs(self._safe_float(item.get("contribution"))),
            reverse=True,
        )[:limit]

    def _get_attribution_signature_key(self, request_context: Dict[str, Any],
                                         attribution: Any) -> str:
        """Create a compact signature key for deduplication, mirroring
        _get_attack_signature_key's shape."""
        url = self._truncate(str(request_context.get("url") or "").split("?")[0], 120)
        method = str(request_context.get("method") or "GET")
        top = self._top_contributors(attribution, limit=3)
        top_key = "|".join(
            f"{item.get('feature')}:{round(self._safe_float(item.get('contribution')), 4)}"
            for item in top
        )
        return f"{method}:{url}:{top_key}"

    @staticmethod
    def _label_for_feature(feature_name: Any) -> str:
        """Static Thai label for one feature name, tolerating a missing or
        unrecognised name instead of raising or returning the string
        "None"."""
        if not feature_name:
            return "ปัจจัยที่ไม่ระบุชื่อ"
        return FEATURE_LABELS_TH.get(str(feature_name), str(feature_name))

    def _fallback_attribution_explanation(self, attribution: Any) -> str:
        """Genuinely useful fallback (acceptance criterion 3): compose a Thai
        sentence from the top contributing features using their static Thai
        labels, so the operator still learns which signals drove the
        decision even with Gemini fully unavailable.

        Routes through _top_contributors()/_as_attribution_items(), so a
        malformed `attribution` (wrong type entirely, or containing None /
        bare strings / dicts missing "feature" or "contribution") degrades
        gracefully instead of raising -- this is the guaranteed-safe path
        and must be total.
        """
        top = self._top_contributors(attribution, limit=3)
        if not top:
            return "ระบบไม่มีข้อมูลปัจจัย (attribution) ที่เพียงพอสำหรับอธิบายผลการวิเคราะห์นี้"

        labels = [self._label_for_feature(item.get("feature")) for item in top]
        joined = ", ".join(labels)
        return f"ปัจจัยหลักที่ระบบใช้ในการวิเคราะห์คำขอนี้ ได้แก่ {joined} ซึ่งเป็นสัญญาณสำคัญที่ทำให้โมเดลให้คะแนนความผิดปกติดังกล่าว"

    # Absolute last-resort string: used only if _fallback_attribution_explanation
    # itself somehow raises. Pure string literal -- no attribute access, no
    # formatting of caller-controlled data -- so it cannot itself fail.
    _ULTIMATE_FALLBACK_TH = "ระบบไม่สามารถสร้างคำอธิบายผลการวิเคราะห์ได้ในขณะนี้"

    async def explain_attribution(self, request_context: Dict[str, Any],
                                    attribution: Any) -> str:
        """
        Explain the model's per-feature attribution (T9's `attribution` list)
        in 1-2 concise Thai sentences for the operator reading a /predict or
        /predict-and-suggest response.

        Mirrors explain_attack's cache/HTTP/fallback shape (acceptance
        criterion 2): in-memory cache keyed on a signature honouring
        self._cache_ttl, an httpx call to the same BASE_URL with ?key=, and
        on any non-200 response or exception, falls through to the static
        fallback below -- never raises.

        This is defended in depth, on purpose, so a single guard someone
        later refactors away cannot reintroduce a 500 (binding project
        constraint: detection availability outranks explanation
        availability, always):
          1. `attribution` is normalised once, up front, through
             _as_attribution_items() -- not a list, or containing non-dict
             entries (None, bare strings, ...), can never reach a bare
             `.get()` call anywhere below.
          2. Everything that builds the prompt and calls Gemini is inside
             one try/except, so a malformed *value* within an otherwise
             well-formed item (e.g. a non-numeric `contribution`, handled by
             _safe_float) degrades to the fallback the same way a network
             failure does.
          3. The fallback call itself -- the thing that is supposed to be
             the guaranteed-safe path -- is inside its *own* try/except, one
             level further out, backstopped by a hardcoded string literal
             that cannot itself raise. So even a defect inside the fallback
             composer cannot escape this method.

        `attribution` may legitimately be absent, or malformed, or simply
        not a list at all (T9 omits it rather than failing; an older or
        misbehaving ML service might send anything); all of that is handled
        here as a normal case with no Gemini call at all when there is
        nothing usable to explain, not as an error.
        """
        normalized = self._as_attribution_items(attribution)

        try:
            if not normalized:
                return self._fallback_attribution_explanation(normalized)

            sig_key = self._get_attribution_signature_key(request_context, normalized)
            now = time.time()

            if sig_key in self._attribution_cache:
                cached = self._attribution_cache[sig_key]
                if now - cached["timestamp"] < self._cache_ttl:
                    return cached["explanation"]

            # Request URL/method are attacker-influenced (T10 security
            # constraint) -- truncate before they reach the prompt. Feature
            # names/values/contributions come from the model, not the caller.
            url = self._truncate(request_context.get("url") or request_context.get("request_uri") or "/", 200)
            method = self._truncate(request_context.get("method") or "GET", 10)

            top_contributors = self._top_contributors(normalized, limit=5)
            contributor_lines = "\n".join(
                f"- {self._truncate(item.get('feature', ''), 60)}: "
                f"value={item.get('value')}, contribution={item.get('contribution')}"
                for item in top_contributors
            )

            prompt = (
                "คุณคือ AI Security Analyst ประจำระบบ WAF จงอธิบายว่าทำไมโมเดล Machine Learning "
                "จึงประเมินคำขอ HTTP นี้ตามค่าปัจจัย (feature attribution) ด้านล่าง โดยสรุปเป็นภาษาไทย "
                "1-2 ประโยคสั้นๆ ระบุปัจจัยหลักที่มีผลต่อผลการวิเคราะห์ (ห้ามเกริ่น ตอบสรุปเนื้อหาทันที):\n"
                f"- Method: {method}\n"
                f"- URL: {url}\n"
                f"- ปัจจัยที่มีผลมากที่สุด:\n{contributor_lines}"
            )

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
                            explanation_text = parts[0].get("text", "").strip()
                            if explanation_text:
                                self._attribution_cache[sig_key] = {
                                    "explanation": explanation_text,
                                    "timestamp": now
                                }
                                return explanation_text
                else:
                    logger.error(f"Gemini API error (attribution): {res.status_code} {res.text}")

        except Exception as e:
            logger.error(f"Failed to build/call Gemini API for attribution explanation: {e}")

        # Guaranteed-safe path, guarded again: even if the fallback composer
        # itself defects in the future, this method still returns a plain
        # string rather than raising out to the caller.
        try:
            return self._fallback_attribution_explanation(normalized)
        except Exception as e:
            logger.error(f"Fallback attribution explanation itself failed: {e}")
            return self._ULTIMATE_FALLBACK_TH

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
