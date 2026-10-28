"""Normalize one CDN edge access-log record into the access_logs row shape.

Moved here from the removed CDN log forwarder module (its file-tailing forwarder and
the DynamoDB waf_logs writer were dead code) so the live caller, the CDN
ingest endpoint in api/cdn.py, keeps working after that file was removed.
"""
import time
from datetime import datetime

from services.geoip import country_code

SEVERITY_NUM_MAP = {
    "0": "CRITICAL",
    "1": "CRITICAL",
    "2": "CRITICAL",
    "3": "HIGH",
    "4": "MEDIUM",
    "5": "LOW",
    "6": "INFO",
    "7": "DEBUG",
    0: "CRITICAL",
    1: "CRITICAL",
    2: "CRITICAL",
    3: "HIGH",
    4: "MEDIUM",
    5: "LOW",
    6: "INFO",
    7: "DEBUG",
}


# The inline ML gate (services/ml_gate.py) answers a request itself: its 403 or
# challenge page is not a ModSecurity block, so its row must not read as one.
ML_RULE_ID = "ML-GEN3"
ML_ATTACK_TYPES = {"block": "ML Block", "challenge": "ML Challenge"}


def label_ml_action(row, action):
    """A normalize_cdn_access row, relabelled when the ML gate blocked or
    challenged the request (ml_gate.recalled_action)."""
    attack_type = ML_ATTACK_TYPES.get(action)
    if attack_type:
        row["attack_type"] = attack_type
        row["rule_id"] = ML_RULE_ID
    return row


def normalize_cdn_access(data, region):
    method = data.get("method", "")
    # Prioritize actual request URI with query parameters over internal error_page path
    url = data.get("request_uri") or data.get("uri") or data.get("url") or ""
    status_code = int(data.get("status", 0))
    is_blocked = (status_code == 403)
    
    req_time = data.get("request_time", "0")
    try:
        latency_ms = int(float(req_time) * 1000)
    except (ValueError, TypeError):
        latency_ms = 0

    # country: resolved from the CLIENT's IP by services/geoip.py. This used
    # to be _REGION_TO_COUNTRY.get(region) -- the country of the *edge node*
    # the request happened to land on, presented as if it were the client's.
    # Every request through edge-th was therefore "TH" regardless of who sent
    # it, which is why the dashboard's country breakdown was a single bar.
    client_ip = data.get("remote_addr") or data.get("ip") or data.get("client_ip")
    country = country_code(client_ip)

    # Extract Rule ID & Severity from Edge Logs
    raw_rule = data.get("rule_id") or data.get("waf_rule_id") or data.get("matched_rule_id")
    raw_sev = data.get("severity") or data.get("waf_severity")
    
    severity = None
    if raw_sev is not None:
        severity = SEVERITY_NUM_MAP.get(str(raw_sev).strip(), str(raw_sev).upper())
    elif is_blocked:
        severity = "CRITICAL"

    attack_type = data.get("attack_type") or data.get("message")
    if is_blocked and not attack_type:
        attack_type = f"WAF Block (Rule {raw_rule})" if raw_rule else "WAF Security Block"

    return {
        "request_id": data.get("request_id", ""),
        "ip": data.get("remote_addr") or data.get("ip") or data.get("client_ip"),
        "method": method,
        "url": url,
        "status": status_code,
        "user_agent": data.get("http_user_agent", ""),
        # Edge-side counterpart of log_forward.py's own host attribution.
        # Reads whichever key the edge's cdn_json log_format supplies; edge
        # nodes running a format older than 2026-09-22 send none, and those
        # rows keep host = '' and fall back to keyword matching.
        "host": data.get("host") or data.get("http_host"),
        "timestamp": int(time.time()),
        "datetime": data.get("time", datetime.utcnow().isoformat() + "Z"),
        "source": "cdn",
        "region": region.upper(),
        "country": country,
        "edge_node": f"edge-{region.lower()}",
        "cache_status": data.get("cache_status", "MISS"),
        "latency_ms": latency_ms,
        "rule_id": str(raw_rule) if raw_rule else ("WAF-CRS" if is_blocked else None),
        "severity": severity,
        "attack_type": attack_type,
        "alert": False,
        "raw": data
    }
