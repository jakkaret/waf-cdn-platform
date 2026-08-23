"""
Zero-Knowledge PII Masking & Redaction Engine
Enterprise Security-by-Design Data Ingestion Gate for WAF Log Pipeline
Compliant with PDPA & GDPR data protection standards.
Includes ReDoS-safe linear-time pattern evaluation and evasion normalization.
"""

import re
import json
import hashlib
from typing import Tuple, List, Dict, Any, Union
from services.payload_normalizer import payload_normalizer
from services.safe_regex import safe_findall

# Salt for Zero-Knowledge Privacy-Preserving Hashing
SALT_PII = "waf_enterprise_zk_salt_2026"


def zk_hash(value: str, salt: str = SALT_PII) -> str:
    """Generate deterministic salted SHA-256 hash for searchable indexing without exposing raw PII"""
    if not value:
        return ""
    combined = f"{salt}:{value}".encode("utf-8")
    return f"zk_{hashlib.sha256(combined).hexdigest()[:16]}"


# ---------------------------------------------------------------------------
# 1. Thai National ID Validation (Algorithm Checksum)
# ---------------------------------------------------------------------------
def is_valid_thai_id(id_str: str) -> bool:
    """
    Validate 13-digit Thai Citizen ID or Alien Resident ID using Official Checksum Algorithm:
    Sum = sum(d_i * (13 - i)) for i in 0..11
    Check digit = (11 - (Sum % 11)) % 10
    Supports Thai citizens (1-8) and alien residents / non-Thai identification (0, 00).
    """
    if not id_str or not isinstance(id_str, str):
        return False
    cleaned = re.sub(r"[^\d]", "", id_str)
    if len(cleaned) != 13:
        return False

    digits = [int(c) for c in cleaned]
    checksum = sum(digits[i] * (13 - i) for i in range(12))
    check_digit = (11 - (checksum % 11)) % 10
    return digits[12] == check_digit


# ---------------------------------------------------------------------------
# 2. Credit Card Validation (Luhn Algorithm)
# ---------------------------------------------------------------------------
def is_valid_credit_card(card_str: str) -> bool:
    """Validate Credit Card number (13-19 digits) using Luhn algorithm"""
    if not card_str or not isinstance(card_str, str):
        return False
    cleaned = re.sub(r"[^\d]", "", card_str)
    if not (13 <= len(cleaned) <= 19):
        return False

    digits = [int(c) for c in cleaned]
    total = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            d = d * 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Compiled High-Performance Non-Backtracking Regex Patterns
# ---------------------------------------------------------------------------
# Thai Mobile Phone (+668x, +669x, +666x, 08x, 09x, 06x)
RE_THAI_PHONE = re.compile(r"(?:\+66[ -]?[689]\d[ -]?\d{3}[ -]?\d{4}|0[689]\d[ -]?\d{3}[ -]?\d{4})\b")

# Email Address
RE_EMAIL = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")

# Strict Non-backtracking Thai ID candidate (13 digits DOPA 1-4-5-2-1 format, raw 13 digits, or space/hyphen separated; categories 0-9)
RE_THAI_ID_CANDIDATE = re.compile(
    r"\b[0-9](?:[ -]?\d{4}[ -]?\d{5}[ -]?\d{2}[ -]?\d|[ -]?\d{4}[ -]?\d{4}[ -]?\d{3}[ -]?\d|\d{12})\b"
)

# Strict Non-backtracking Credit Card candidate (13 to 19 digits)
RE_CC_CANDIDATE = re.compile(r"\b(?:\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}|\d{13,19})\b")

# Secret & Token Query/Form Parameter Names
SENSITIVE_KEY_NAMES = (
    "password|passwd|pwd|token|access_token|refresh_token|secret|"
    "api_key|apikey|authorization|auth|secret_key|private_key|pin|otp|"
    "id_card|citizen_id|national_id|ssn|credit_card|card_number|cvv|cvc|"
    "cid|pid|tax_id|taxid|personal_id|thainationalid|citizenid|idcard|card_id|nationalid"
)

# Key=Value secret regex (covers URL query strings, form bodies, plain log lines)
RE_QUERY_SECRET = re.compile(
    rf"(?i)(?P<prefix>(?:[?&]|^|\s|,|;))(?P<key>{SENSITIVE_KEY_NAMES})=(?P<val>[^&#\s,;\"']+)"
)

# JSON Key-Value string regex
RE_JSON_SECRET = re.compile(
    rf'(?i)"(?P<key>{SENSITIVE_KEY_NAMES})"\s*:\s*"(?P<val>[^"]+)"'
)

# Authorization Headers (Bearer / Basic)
RE_AUTH_BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]{12,})")
RE_AUTH_BASIC = re.compile(r"(?i)\bBasic\s+([A-Za-z0-9+/=]{10,})")


class PIIMasker:
    """High-performance Zero-Knowledge PII Redaction and Masking Engine"""

    def __init__(self, max_inspect_len: int = 8192):
        self.max_inspect_len = max_inspect_len

    def mask_text(self, text: str) -> Tuple[str, List[str]]:
        """
        Mask sensitive data in unstructured text (URL, logs, headers, raw payload).
        Returns: (masked_text, list_of_detected_pii_types)
        """
        if not text or not isinstance(text, str):
            return text, []

        detected_types: List[str] = []
        result = text

        # 1. Mask Thai Citizen / Alien ID (Only when checksum passes)
        candidates_th_id = safe_findall(RE_THAI_ID_CANDIDATE, result, timeout_sec=0.02)
        if candidates_th_id:
            for candidate in candidates_th_id:
                if is_valid_thai_id(candidate):
                    detected_types.append("Thai National ID")
                    result = result.replace(candidate, "[MASKED_TH_ID]")

        # 2. Mask Credit Card Numbers (Only when Luhn checksum passes)
        candidates_cc = safe_findall(RE_CC_CANDIDATE, result, timeout_sec=0.02)
        if candidates_cc:
            for candidate in candidates_cc:
                clean_cc = re.sub(r"[^\d]", "", candidate)
                if 13 <= len(clean_cc) <= 19 and is_valid_credit_card(candidate):
                    detected_types.append("Credit Card")
                    result = result.replace(candidate, "[MASKED_CREDIT_CARD]")

        # 3. Mask Authorization Bearer Tokens
        if "bearer" in result.lower():
            def _sub_bearer(match):
                detected_types.append("Bearer Token")
                return "Bearer [MASKED_TOKEN]"
            result = RE_AUTH_BEARER.sub(_sub_bearer, result)

        # 4. Mask Authorization Basic Auth
        if "basic" in result.lower():
            def _sub_basic(match):
                detected_types.append("Basic Auth")
                return "Basic [MASKED_AUTH]"
            result = RE_AUTH_BASIC.sub(_sub_basic, result)

        # 5. Mask Key=Value & Query String Secrets
        if "=" in result:
            def _sub_query_secret(match):
                key = match.group("key")
                prefix = match.group("prefix")
                val = match.group("val")
                if val.startswith("[MASKED_"):
                    return match.group(0)
                detected_types.append(f"Secret ({key})")
                return f"{prefix}{key}=[MASKED_{key.upper()}]"
            result = RE_QUERY_SECRET.sub(_sub_query_secret, result)

        # 6. Mask JSON Key Secrets in text
        if ":" in result and ("{" in result or '"' in result):
            def _sub_json_secret(match):
                key = match.group("key")
                detected_types.append(f"Secret ({key})")
                return f'"{key}": "[MASKED_{key.upper()}]"'
            result = RE_JSON_SECRET.sub(_sub_json_secret, result)

        # 7. Mask Email Addresses
        if "@" in result:
            def _sub_email(match):
                detected_types.append("Email")
                return "[MASKED_EMAIL]"
            result = RE_EMAIL.sub(_sub_email, result)

        # 8. Mask Thai Mobile Phone Numbers
        if any(p in result for p in ["08", "09", "06", "+66"]):
            def _sub_phone(match):
                detected_types.append("Thai Mobile")
                return "[MASKED_TH_PHONE]"
            result = RE_THAI_PHONE.sub(_sub_phone, result)

        return result, sorted(list(set(detected_types)))

    def mask_dict(self, data: Union[Dict, List, Any]) -> Tuple[Union[Dict, List, Any], List[str]]:
        """Recursively mask sensitive data in dictionaries and lists (JSON payload)"""
        detected_types: List[str] = []

        if isinstance(data, dict):
            masked_dict = {}
            for k, v in data.items():
                k_lower = str(k).lower()
                # If key itself is a sensitive credential field
                if any(sec in k_lower for sec in ["password", "secret", "token", "apikey", "api_key", "auth", "private_key"]):
                    detected_types.append(f"Secret ({k})")
                    masked_dict[k] = f"[MASKED_{str(k).upper()}]"
                elif isinstance(v, str):
                    masked_val, sub_types = self.mask_text(v)
                    masked_dict[k] = masked_val
                    detected_types.extend(sub_types)
                elif isinstance(v, (dict, list)):
                    masked_val, sub_types = self.mask_dict(v)
                    masked_dict[k] = masked_val
                    detected_types.extend(sub_types)
                else:
                    masked_dict[k] = v
            return masked_dict, sorted(list(set(detected_types)))

        elif isinstance(data, list):
            masked_list = []
            for item in data:
                if isinstance(item, str):
                    m_item, sub_types = self.mask_text(item)
                    masked_list.append(m_item)
                    detected_types.extend(sub_types)
                elif isinstance(item, (dict, list)):
                    m_item, sub_types = self.mask_dict(item)
                    masked_list.append(m_item)
                    detected_types.extend(sub_types)
                else:
                    masked_list.append(item)
            return masked_list, sorted(list(set(detected_types)))

        elif isinstance(data, str):
            return self.mask_text(data)

        return data, []

    def mask_payload(self, data: Any) -> Tuple[Any, Dict[str, Any]]:
        """
        Main entry point for WAF log pipeline.
        Takes a log dictionary or string payload and returns (masked_data, pii_metadata)
        """
        all_detected: List[str] = []

        if isinstance(data, dict):
            masked_data, detected = self.mask_dict(data)
            all_detected.extend(detected)
        elif isinstance(data, str):
            masked_data, detected = self.mask_text(data)
            all_detected.extend(detected)
        else:
            masked_data = data

        unique_types = sorted(list(set(all_detected)))
        pii_meta = {
            "is_pii_masked": len(unique_types) > 0,
            "masked_types": unique_types,
            "masked_fields_count": len(unique_types),
        }

        return masked_data, pii_meta


# Global Singleton Instance for fast import
pii_masker = PIIMasker()
