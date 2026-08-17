import os
import re
import json
import urllib.parse
import fcntl
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any

CUSTOM_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modsecurity", "custom-rules")
AUTO_RULES_FILE = os.path.join(CUSTOM_RULES_DIR, "auto_generated_rules.conf")

# Next available Rule ID counter
START_RULE_ID = 1000500

def generate_modsec_pattern(url: str, body: str = "") -> str:
    """
    Extract a safe, targeted Regex / String match pattern for ModSecurity SecRule.
    """
    raw_str = f"{url} {body}".strip()
    decoded_str = urllib.parse.unquote(raw_str)

    # 1. SQL Injection Patterns
    if re.search(r"union\s+select", decoded_str, re.I):
        return r"@rx (?i)union\s+select"
    if re.search(r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1", decoded_str, re.I):
        return r"@rx (?i)or\s+['\"]?1['\"]?\s*=\s*['\"]?1"
    if re.search(r"exec\s*\(|drop\s+table", decoded_str, re.I):
        return r"@rx (?i)(exec\s*\(|drop\s+table)"

    # 2. XSS Patterns
    if re.search(r"<script|javascript:|onerror\s*=", decoded_str, re.I):
        return r"@rx (?i)(<script|javascript:|onerror\s*=)"

    # 3. Path Traversal
    if "../" in decoded_str or "..\\" in decoded_str:
        return r"@rx (\.\./|\.\.\\)"

    # 4. Command Injection / RCE
    if re.search(r"(\||;|`)\s*(cat|nc|wget|curl|bash|sh)\s", decoded_str, re.I):
        return r"@rx (?i)(?:\||;|`)\s*(cat|nc|wget|curl|bash|sh)\s"

    # Fallback: Escaped specific query fragment
    if body:
        safe_body = re.escape(body[:40])
        return f"@rx {safe_body}"

    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        safe_query = re.escape(parsed.query[:40])
        return f"@rx {safe_query}"

    safe_uri = re.escape(parsed.path[:40])
    return f"@rx {safe_uri}"

def generate_pending_rule(url: str, method: str = "GET", body: str = "", attack_type: str = "Anomaly") -> Dict[str, Any]:
    """
    Generate ModSecurity SecRule directive data for pending approval.
    """
    # 1. Sanitize attack_type to prevent Rule Injection
    safe_attack_type = re.sub(r"[^a-zA-Z0-9_\-\s]", "", attack_type)
    if not safe_attack_type:
        safe_attack_type = "Anomaly"

    pattern = generate_modsec_pattern(url, body)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    secrule_template = f"""SecRule REQUEST_URI|REQUEST_BODY "{pattern}" \\
    "id:{{RULE_ID}},\\
    phase:2,\\
    deny,\\
    status:403,\\
    severity:CRITICAL,\\
    log,\\
    msg:'ML Auto-Generated WAF Rule: Blocked {safe_attack_type} Pattern'\""""

    return {
        "pattern": pattern,
        "variable": "REQUEST_URI|REQUEST_BODY",
        "attack_type": safe_attack_type,
        "severity": "CRITICAL",
        "secrule_template": secrule_template,
        "source_url": url[:100],
        "source_method": method,
        "timestamp": timestamp
    }

if __name__ == "__main__":
    res = generate_pending_rule("/login?user=admin' OR '1'='1' --", "GET", attack_type="SQL Injection")
    print(json.dumps(res, indent=2))
