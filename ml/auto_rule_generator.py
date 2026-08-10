import os
import re
import json
import urllib.parse
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
        return r"@rx union\s+select"
    if re.search(r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1", decoded_str, re.I):
        return r"@rx or\s+['\"]?1['\"]?\s*=\s*['\"]?1"
    if re.search(r"exec\s*\(|drop\s+table", decoded_str, re.I):
        return r"@rx (exec\s*\(|drop\s+table)"

    # 2. XSS Patterns
    if re.search(r"<script|javascript:|onerror\s*=", decoded_str, re.I):
        return r"@rx (<script|javascript:|onerror\s*=)"

    # 3. Path Traversal
    if "../" in decoded_str or "..\\" in decoded_str:
        return r"@rx (\.\./|\.\.\\)"

    # 4. Command Injection / RCE
    if re.search(r"\||;|`", decoded_str) and re.search(r"(cat|nc|wget|curl|bash|sh)\s", decoded_str, re.I):
        return r"@rx (cat|nc|wget|curl|bash|sh)\s"

    # Fallback: Escaped specific query fragment
    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        safe_query = re.escape(parsed.query[:40])
        return f"@rx {safe_query}"

    safe_uri = re.escape(parsed.path[:40])
    return f"@rx {safe_uri}"

def get_next_rule_id() -> int:
    """Read existing auto-generated rules file to find highest Rule ID."""
    os.makedirs(CUSTOM_RULES_DIR, exist_ok=True)
    if not os.path.exists(AUTO_RULES_FILE):
        return START_RULE_ID

    with open(AUTO_RULES_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    rule_ids = [int(m) for m in re.findall(r"id:(\d+)", content)]
    if rule_ids:
        return max(max(rule_ids) + 1, START_RULE_ID)
    return START_RULE_ID

def generate_and_save_secrule(url: str, method: str = "GET", body: str = "", attack_type: str = "Anomaly") -> Dict[str, Any]:
    """
    Generate ModSecurity SecRule directive and write to modsecurity/custom-rules/auto_generated_rules.conf.
    """
    rule_id = get_next_rule_id()
    pattern = generate_modsec_pattern(url, body)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sec_directive = f"""# ------------------------------------------------------------------------
# ML Auto-Generated WAF Rule (ID: {rule_id})
# Created: {timestamp}
# Source Target: {method} {url[:60]}
# ------------------------------------------------------------------------
SecRule REQUEST_URI|REQUEST_BODY "{pattern}" \\
    "id:{rule_id},\\
    phase:2,\\
    deny,\\
    status:403,\\
    severity:CRITICAL,\\
    log,\\
    msg:'ML Auto-Generated WAF Rule: Blocked {attack_type} Pattern'"
"""

    # Append to auto_generated_rules.conf
    os.makedirs(CUSTOM_RULES_DIR, exist_ok=True)
    with open(AUTO_RULES_FILE, "a", encoding="utf-8") as f:
        f.write(sec_directive + "\n")

    print(f"[+] Successfully generated and saved ModSecurity Rule #{rule_id} to {AUTO_RULES_FILE}")

    return {
        "success": True,
        "rule_id": rule_id,
        "pattern": pattern,
        "secrule_code": sec_directive.strip(),
        "file_path": AUTO_RULES_FILE,
        "timestamp": timestamp
    }

if __name__ == "__main__":
    res = generate_and_save_secrule("/login?user=admin' OR '1'='1' --", "GET", attack_type="SQL Injection")
    print(json.dumps(res, indent=2))
