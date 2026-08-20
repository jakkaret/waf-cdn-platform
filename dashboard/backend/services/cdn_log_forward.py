import asyncio
import json
import os
import time
import logging
from datetime import datetime
from services.dynamodb_service import DynamoDBService
from services.clickhouse_service import ClickHouseService

logger = logging.getLogger(__name__)
db = DynamoDBService()
ch = ClickHouseService()

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

def save_hybrid_log(data: dict):
    if ch.connected:
        ch.save_log("access_logs", data)
    db.save_log(data)

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../")
)

REGIONS = ["sg", "jp", "th"]

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

    _REGION_TO_COUNTRY = {"sg": "SG", "jp": "JP", "th": "TH"}
    country = _REGION_TO_COUNTRY.get(region.lower(), region.upper())

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

async def tail_file(path):
    print("CDN Log Forward Opening:", path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, 'w') as f:
            pass

    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue
            yield line.strip()

async def process_cdn_log(region):
    log_path = os.path.join(BASE_DIR, f"logs/cdn/{region}/access.json")
    async for line in tail_file(log_path):
        try:
            raw = json.loads(line)
            logs_to_process = raw.get("logs", [raw]) if isinstance(raw, dict) else [raw]
            
            for log_entry in logs_to_process:
                if not isinstance(log_entry, dict):
                    continue
                data = normalize_cdn_access(log_entry, region)
                save_hybrid_log(data)
                
        except Exception as e:
            print(f"cdn log error ({region}):", e)

async def cdn_log_forward_worker():
    print("🚀 Starting CDN log forwarder...")
    tasks = [process_cdn_log(region) for region in REGIONS]
    await asyncio.gather(*tasks)
