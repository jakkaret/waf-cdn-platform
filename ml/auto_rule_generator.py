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

# Kept as-is in a literal pattern; every other byte is written as \xHH. Not "%": ModSecurity's
# config parser reads it as the start of a macro (%{VAR}), and a pattern ending in "%" (a query cut
# at 40 characters) made the whole rules file fail to load.
_LITERAL_SAFE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_/=&,:-")
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def regex_literal(text: str) -> str:
    """PCRE pattern that matches `text` literally, built from safe characters and \\xHH escapes only.

    The pattern comes from request data (attacker-controlled) and is placed inside the
    double-quoted operator of a SecRule. re.escape() leaves `"` alone, so a payload with a
    quote could close the operator and append its own actions (e.g. ctl:ruleEngine=Off).
    Escaping every other UTF-8 byte as \\xHH leaves no quote, backslash-quote, whitespace
    or control character in the output, and PCRE matches the same bytes as before.
    """
    return "".join(chr(b) if chr(b) in _LITERAL_SAFE_CHARS else f"\\x{b:02x}" for b in text.encode("utf-8"))


def assert_secrule_safe(pattern: str) -> None:
    """Raise ValueError if `pattern` could break out of a double-quoted SecRule operator."""
    if _CONTROL_CHARS.search(pattern):
        raise ValueError("SecRule pattern contains a control character")
    for i, ch in enumerate(pattern):
        if ch == '"' and (len(pattern[:i]) - len(pattern[:i].rstrip("\\"))) % 2 == 0:
            raise ValueError("SecRule pattern contains an unescaped double quote")
    if (len(pattern) - len(pattern.rstrip("\\"))) % 2 == 1:
        raise ValueError("SecRule pattern ends with a backslash that would escape the closing quote")


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

    # 5. SSRF / Cloud Metadata
    if "169.254.169.254" in decoded_str or "metadata.google" in decoded_str:
        return r"@rx (?i)(169\.254\.169\.254|metadata\.google)"

    # 6. SSTI (Template Injection)
    if re.search(r"\{\{.*?\}\}|\$\{.*?\}", decoded_str):
        return r"@rx (\{\{.*?\}\}|\$\{.*?\})"

    # 7. NoSQL / Log4j Injection
    if re.search(r"\$ne|\$gt|\$where|\$\{jndi:", decoded_str, re.I):
        return r"@rx (?i)(\$ne|\$gt|\$where|\$\{jndi:)"

    # Fallback: literal match of the first 40 characters (regex_literal keeps it SecRule-safe)
    if body:
        return f"@rx {regex_literal(body[:40])}"

    parsed = urllib.parse.urlparse(url)
    if parsed.query:
        return f"@rx {regex_literal(parsed.query[:40])}"

    return f"@rx {regex_literal(parsed.path[:40])}"

def generate_pending_rule(url: str, method: str = "GET", body: str = "", attack_type: str = "Anomaly") -> Dict[str, Any]:
    """
    Generate ModSecurity SecRule directive data for pending approval.
    """
    # 1. Sanitize attack_type to prevent Rule Injection
    safe_attack_type = re.sub(r"[^a-zA-Z0-9_\-\s]", "", attack_type)
    if not safe_attack_type:
        safe_attack_type = "Anomaly"

    pattern = generate_modsec_pattern(url, body)
    assert_secrule_safe(pattern)
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
