"""
Explainable WAF Engine — Root-Cause Analysis & Token Attribution Service
Translates ModSecurity CRS and Custom Rule triggers into human-readable SecOps insights,
attributing exact offending tokens/payloads with confidence scores and actionable remediations.
Includes full evasion-resilience (Unicode NFKC, Multi-layer URL decoding, HTML entity unescape)
and ReDoS-safe execution with time budgets.
"""

import re
from typing import Dict, Any, Optional, Tuple, List
from services.payload_normalizer import payload_normalizer
from services.safe_regex import safe_search

# Token attribution pattern maps with strict linear-time bounded regexes
SIGNATURE_PATTERNS = [
    # 1. SQL Injection (SQLi)
    {
        "category": "SQL Injection (SQLi)",
        "crs_prefix": ("942", "942100", "942110", "942120", "942130", "942140", "942150", "942160", "942170", "942180", "942190", "942200", "942260", "942370", "942430", "942440"),
        "regex": re.compile(
            r"(?i)("
            r"'\s*or\s+(?:'?[0-9]'?='?[0-9]'?|true|false)|"
            r"\bunion(?:\s+all)?\s+select\b|"
            r"\bselect\s+(?:\*|[\w,\s`\"'\.()]{1,150})\s+from\s+[\w`\"'\.]+\b|"
            r"\bwaitfor\s+delay\b|"
            r"\bsleep\s*\(\s*\d+\s*\)|"
            r"\bbenchmark\s*\(\s*\d+|"
            r"\bdrop\s+table\b|"
            r"\bexec\s*\(\s*xp_cmdshell|"
            r"\binformation_schema\b|"
            r"--\s|/\*.*?\*/|"
            r"\bor\s+\d+=\d+|"
            r"\band\s+\d+=\d+"
            r")"
        ),
        "explanation": "ตรวจพบรูปแบบ SQL Injection Payload ใน URL/Query หรือ Request Body ซึ่งพยายามแทรกคำสั่ง SQL เข้าสู่ฐานข้อมูล (ตรวจพบ: '{token}')",
        "remediation": "ใช้ Parameterized Queries / Prepared Statements (เช่น PDO, ORM, SQLAlchemy) และห้ามนำ Input ไปต่อ String ใน SQL Query โดยตรง",
        "confidence": 0.95
    },
    # 2. Cross-Site Scripting (XSS)
    {
        "category": "Cross-Site Scripting (XSS)",
        "crs_prefix": ("941", "941100", "941110", "941120", "941130", "941140", "941150", "941160", "941170", "941180", "941190", "941200", "941370"),
        "regex": re.compile(
            r"(?i)("
            r"<script\b[^>]*>(?:(?!<\/script>)[\s\S]){0,1000}<\/script>|"
            r"<script\b[^>]*>|"
            r"javascript:\s*[^\s\"'>]+|"
            r"(?:onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=\s*['\"]?[^'\">\s]+|"
            r"\balert\s*\([^)]*\)|"
            r"document\.cookie|"
            r"\beval\s*\([^)]*\)|"
            r"<iframe\b[^>]*>|"
            r"<svg\b[^>]*onload|"
            r"<img\b[^>]+onerror"
            r")"
        ),
        "explanation": "ตรวจพบ Cross-Site Scripting (XSS) Payload ซึ่งพยายามแทรก HTML/JavaScript Tag หรือ Event Handler อันตราย ('{token}')",
        "remediation": "ทำ Context-Aware Output Encoding (เช่น HTML Entities, DOMPurify) ก่อนเรนเดอร์ และตั้งค่า Content-Security-Policy (CSP) Header",
        "confidence": 0.95
    },
    # 3. Path Traversal & LFI
    {
        "category": "Path Traversal (LFI)",
        "crs_prefix": ("930", "930100", "930110", "930120", "930130"),
        "regex": re.compile(
            r"(?i)("
            r"(?:\.\.[/\\]){1,}|"
            r"/etc/passwd|/etc/shadow|/etc/hosts|"
            r"boot\.ini|windows/system32|"
            r"php://filter|php://input"
            r")"
        ),
        "explanation": "ตรวจพบความพยายามทำ Path Traversal / File Inclusion เพื่อเข้าถึงไฟล์ระบบบนเซิร์ฟเวอร์ ('{token}')",
        "remediation": "หลีกเลี่ยงการรับชื่อไฟล์หรือ Path จาก User Input, ใช้ Path Boundary Checking (เช่น realpath / basename) และจำกัดสิทธิ์อ่านไฟล์",
        "confidence": 0.92
    },
    # 4. Remote Code Execution (RCE) / Command Injection
    {
        "category": "Remote Code Execution (RCE)",
        "crs_prefix": ("932", "932100", "932110", "932120", "932130", "932140", "932150"),
        "regex": re.compile(
            r"(?i)("
            r"(?:[;&|`]\s*|\$\()(?:cat|ls|id|whoami|curl|wget|nc|uname|sh|bash|powershell|cmd)\b|"
            r"\$\([^)]+\)|"
            r"\$\{IFS\}|"
            r"/bin/(?:bash|sh|zsh)|"
            r"powershell\.exe|cmd\.exe"
            r")"
        ),
        "explanation": "ตรวจพบ Command Injection / RCE Signature ซึ่งพยายามสั่งรัน System Commands บน OS ('{token}')",
        "remediation": "หลีกเลี่ยงการส่งต่อ Input ไปยัง OS Shell (เช่น exec, system, popen) ให้ใช้ฟังก์ชัน API เฉพาะของภาษาแทน",
        "confidence": 0.94
    },
    # 5. PHP Injection
    {
        "category": "PHP Code Injection",
        "crs_prefix": ("933", "933100", "933110", "933120", "933130", "933140", "933150"),
        "regex": re.compile(
            r"(?i)("
            r"<\?php|"
            r"phpinfo\s*\(\s*\)|"
            r"passthru\s*\([^)]*\)|"
            r"assert\s*\([^)]*\)|"
            r"base64_decode\s*\([^)]*\)"
            r")"
        ),
        "explanation": "ตรวจพบความพยายามแทรกคำสั่ง PHP Code Injection เพื่อรันโค้ดบน Interpreter ('{token}')",
        "remediation": "ปิดฟังก์ชันอันตรายใน php.ini (เช่น disable_functions=exec,passthru,shell_exec,system) และหลีกเลี่ยง eval()",
        "confidence": 0.90
    },
    # 6. PII Leakage Protection (Custom 990002)
    {
        "category": "PII Data Leakage Prevention",
        "crs_prefix": ("990002", "PII-GUARD"),
        "regex": re.compile(
            r"(?i)("
            r"(?:thai_id|citizen_id|id_card)=[0-9]{13}|"
            r"bearer\s+[A-Za-z0-9_\-\.]{15,}|"
            r"password=[^&#\s]+"
            r")"
        ),
        "explanation": "ตรวจพบการส่งข้อมูลส่วนบุคคลที่ละเอียดอ่อน (PII เช่น บัตรประชาชน หรือ Token) ผ่านช่องทาง URL ไม่ปลอดภัย",
        "remediation": "ส่งข้อมูลส่วนบุคคลผ่าน HTTPS Request Body ที่เข้ารหัสเท่านั้น (POST/PUT) และทำ Data Masking/Tokenization ที่ Client",
        "confidence": 0.98
    },
    # 7. Custom Sync Test Rule (Custom 990001)
    {
        "category": "Custom Rule Block",
        "crs_prefix": ("990001", "CUSTOM-990001"),
        "regex": re.compile(r"/test-waf-sync-rule"),
        "explanation": "ทราฟฟิกตรงกับเงื่อนไข Custom Rule 990001 (WAF Sync Test Verification)",
        "remediation": "ตรวจสอบกฎที่สร้างขึ้นในเมนู Rules Management บน Dashboard",
        "confidence": 1.0
    },
    # 8. Context-Aware BOLA / IDOR Guard (Custom 990003 & 990030-990035)
    {
        "category": "Broken Object Level Authorization (BOLA)",
        "crs_prefix": ("990003", "990030", "990031", "990032", "990033", "BOLA-GUARD"),
        "regex": re.compile(r"(?i)(?:bola|idor|cross-tenant|unauthorized_object|spoofed_user|/api/(?:v[0-9]+/)?(?:users|tenants|accounts|orders)/[a-zA-Z0-9_\-]+)"),
        "explanation": "ตรวจพบความพยายามเข้าถึงทรัพยากรข้าม Tenant หรือข้าม User ID (Broken Object Level Authorization / BOLA)",
        "remediation": "ตรวจสอบความถูกต้องของ JWT Claims เทียบกับ Path Parameter ใน Request และบังคับใช้ Zero-Trust Tenancy Boundary",
        "confidence": 0.96
    }
]


class ExplainabilityService:
    """Service to generate Root-Cause Explanations and Token Attribution for WAF Events"""

    def __init__(self):
        pass

    def explain_event(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a log entry and produce explainability metadata.
        Returns: {
            "matched_token": str,
            "category": str,
            "root_cause_explanation": str,
            "remediation_hint": str,
            "confidence_score": float,
            "explain_summary": str
        }
        """
        raw_url = str(log_entry.get("url") or log_entry.get("request_uri") or log_entry.get("uri") or "")
        rule_id = str(log_entry.get("rule_id") or log_entry.get("waf_rule_id") or "")
        attack_type = str(log_entry.get("attack_type") or log_entry.get("message") or "")
        status_code = int(log_entry.get("status") or log_entry.get("status_code") or 0)
        raw_tx = log_entry.get("raw", {})

        # Multi-stage normalization to defeat payload evasion (Unicode NFKC, recursive URL decode, HTML unescape)
        normalized_url = payload_normalizer.normalize_string(raw_url)
        normalized_attack = payload_normalizer.normalize_string(attack_type)

        search_corpus = f"{raw_url} {normalized_url} {normalized_attack} {str(raw_tx)}"

        matched_token = ""
        category = "WAF Traffic"
        root_cause = "ทราฟฟิกผ่านการตรวจสอบตามเกณฑ์ความปลอดภัยปกติ"
        remediation = "ไม่จำเป็นต้องดำเนินการแก้ไข"
        confidence = 0.5

        # 1. First, check if ModSec provided exact matched string in messages
        if isinstance(raw_tx, dict):
            tx_data = raw_tx.get("transaction", {})
            msgs = tx_data.get("messages", [])
            for m in msgs:
                details = m.get("details", {})
                match_data = details.get("data") or details.get("match")
                if match_data and isinstance(match_data, str) and len(match_data.strip()) > 1:
                    matched_token = match_data.strip()
                    break

        # 2. Check rule_id against SIGNATURE_PATTERNS
        matched_sig = None
        for sig in SIGNATURE_PATTERNS:
            if any(rule_id.startswith(p) for p in sig["crs_prefix"]):
                matched_sig = sig
                break

        # 3. Check regex match in search corpus if token or signature still needed
        if not matched_token or not matched_sig:
            for sig in SIGNATURE_PATTERNS:
                # Use safe_search with time budget limit to prevent ReDoS
                m = safe_search(sig["regex"], search_corpus, timeout_sec=0.03)
                if m:
                    if not matched_token:
                        matched_token = m.group(0)
                    if not matched_sig:
                        matched_sig = sig
                    break

        # 4. Formulate explanation based on matched signature or rule
        if matched_sig:
            category = matched_sig["category"]
            tok_display = matched_token if matched_token else (rule_id or "Anomalous Payload")
            root_cause = matched_sig["explanation"].replace("{token}", tok_display)
            remediation = matched_sig["remediation"]
            confidence = matched_sig["confidence"]
        elif status_code == 403 or (rule_id and rule_id != "None"):
            if "sql" in attack_type.lower() or "942" in rule_id:
                category = "SQL Injection (SQLi)"
                root_cause = f"ตรวจพบความผิดปกติของคำสั่งฐานข้อมูล (Rule: {rule_id})"
                remediation = "ใช้ Parameterized Queries เพื่อป้องกัน SQL Injection"
                confidence = 0.90
            elif "xss" in attack_type.lower() or "941" in rule_id:
                category = "Cross-Site Scripting (XSS)"
                root_cause = f"ตรวจพบการแทรก JavaScript / HTML Tag อันตราย (Rule: {rule_id})"
                remediation = "ใช้ Context-Aware Output Encoding และกำหนด CSP Header"
                confidence = 0.90
            elif "traversal" in attack_type.lower() or "lfi" in attack_type.lower() or "930" in rule_id:
                category = "Path Traversal (LFI)"
                root_cause = f"ตรวจพบความพยายามเข้าถึงไฟล์ระบบ (Rule: {rule_id})"
                remediation = "ตรวจสอบ Path Boundary และหลีกเลี่ยงการเปิดไฟล์ตาม User Input"
                confidence = 0.88
            else:
                category = "WAF Security Filter"
                root_cause = f"ตรวจพบทราฟฟิกละเมิดนโยบายความปลอดภัย WAF (Rule: {rule_id or 'CRS-Anomaly'})"
                remediation = "ตรวจสอบความถูกต้องของ Request และ Header ของผู้ใช้งาน"
                confidence = 0.80

        # Create concise summary
        if status_code == 403:
            explain_summary = f"Blocked ({category}) - Token: '{matched_token or rule_id}'"
        else:
            explain_summary = "Normal Traffic"

        return {
            "matched_token": matched_token,
            "category": category,
            "root_cause_explanation": root_cause,
            "remediation_hint": remediation,
            "confidence_score": round(confidence, 2),
            "explain_summary": explain_summary
        }

    def generate_mitigation_candidate(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms an analyzed threat event or offending token into a safe candidate ModSecurity SecRule.
        Validates ReDoS safety and outputs candidate fields for Blast Radius Replay & 1-Click mitigation.
        """
        import time
        exp = self.explain_event(log_entry)
        raw_url = str(log_entry.get("url") or log_entry.get("request_uri") or "")
        token = exp.get("matched_token") or ""
        category = exp.get("category") or "Threat Mitigation"
        rule_id = str(log_entry.get("rule_id") or "")
        attack_type = str(log_entry.get("attack_type") or category)
        ip = str(log_entry.get("ip") or log_entry.get("client_ip") or "")

        candidate_id = f"custom-{int(time.time()) % 900000 + 100000}"
        variable = "REQUEST_URI"
        operator = ""
        severity = "HIGH"
        reasoning = ""

        # Case 1: IP threat
        if ip and ("scanner" in attack_type.lower() or "brute" in attack_type.lower() or not token):
            variable = "REMOTE_ADDR"
            operator = f"@ipMatch {ip}/32"
            severity = "HIGH"
            reasoning = f"Direct IP isolation block for malicious source {ip}"

        # Case 2: Specific detected token
        elif token:
            safe_esc = re.escape(token)
            is_keyword = token.isalnum() or len(token) <= 5

            # Check if token is in query params
            if "?" in raw_url and token in raw_url.split("?", 1)[1]:
                variable = "ARGS"
                if is_keyword:
                    operator = f"@rx (?i)\\b{safe_esc}\\b"
                else:
                    operator = f"@rx (?i){safe_esc}"
            elif raw_url and token in raw_url:
                variable = "REQUEST_URI"
                if token.startswith("/") and len(token) > 3:
                    operator = f"@beginsWith {token}"
                elif is_keyword:
                    # Enforce strict path segment or word boundary scoping to prevent false positives on words like 'admin', 'select'
                    operator = f"@rx (?i)/(?:{safe_esc})(?:/|\\?|$)|\\b{safe_esc}\\b"
                else:
                    operator = f"@rx (?i){safe_esc}"
            else:
                variable = "REQUEST_URI|REQUEST_HEADERS"
                if is_keyword:
                    operator = f"@containsWord {token}"
                else:
                    operator = f"@contains {token}"

            severity = "CRITICAL" if any(k in category.lower() for k in ["sql", "rce", "traversal", "php"]) else "HIGH"
            reasoning = f"Targeted rule mitigating offending {category} token '{token}' with strict boundary scoping"

        # Case 3: URL path-based fallback
        elif raw_url and raw_url != "/":
            path_only = raw_url.split("?")[0]
            variable = "REQUEST_URI"
            operator = f"@beginsWith {path_only}"
            severity = "HIGH"
            reasoning = f"Path boundary restriction for anomalous path '{path_only}'"

        else:
            variable = "REQUEST_URI"
            operator = "@contains /api/v1/suspicious"
            severity = "MEDIUM"
            reasoning = "Generic safety perimeter fallback rule"

        # Verify ReDoS Safety
        from services.safe_regex import validate_regex_safety
        pattern_check = operator[4:].strip() if operator.startswith("@rx ") else operator
        is_safe, safety_issue = validate_regex_safety(pattern_check) if not operator.startswith("@ipMatch") else (True, "OK")

        # Generate standard ModSecurity SecRule syntax
        secrule_text = (
            f"# Auto-Mitigation Candidate Rule (Category: {category})\n"
            f"SecRule {variable} \"{operator}\" \\\n"
            f"    \"id:{candidate_id.replace('custom-', '')},phase:2,deny,status:403,"
            f"severity:{severity},log,msg:'Auto-Mitigated {category} attempt: {attack_type}'\""
        )

        return {
            "candidate_rule": {
                "id": candidate_id,
                "variable": variable,
                "operator": operator,
                "severity": severity,
                "message": f"Auto-Mitigation for {category} ({attack_type})"
            },
            "id": candidate_id,
            "variable": variable,
            "operator": operator,
            "severity": severity,
            "secrule_syntax": secrule_text,
            "category": category,
            "matched_token": token,
            "redos_safe": is_safe,
            "safety_issue": safety_issue if not is_safe else None,
            "confidence": exp.get("confidence_score", 0.95),
            "reasoning": reasoning,
            "explanation": exp
        }


# Global Singleton Instance
explainability_service = ExplainabilityService()
