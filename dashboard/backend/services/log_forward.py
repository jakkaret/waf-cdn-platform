import asyncio
import json
import logging
import os
import time
from datetime import datetime
from services.dynamodb_service import DynamoDBService
from services.clickhouse_service import ClickHouseService
from services.telegram_listener import dispatch_telegram_alert

logger = logging.getLogger(__name__)

db = DynamoDBService()
ch = ClickHouseService()
log_buffer = {}

KNOWN_EDGE_IPS = {"45.154.26.91", "172.18.0.2"}

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

ACCESS_LOG = os.path.join(BASE_DIR, "logs/nginx/access.json")
AUDIT_LOG = os.path.join(BASE_DIR, "logs/modsecurity/audit.json")
MERGE_TIMEOUT = 5


# -----------------------------
# ACCESS LOG NORMALIZE
# -----------------------------
def normalize_access(data):
    req = data.get("request", "")
    method, url = None, None

    if req:
        parts = req.split(" ")
        if len(parts) >= 2:
            method = parts[0]
            url = parts[1]

    status_code = int(data.get("status", 0))
    is_blocked = (status_code == 403)

    return {
        "request_id": data.get("request_id"),
        "ip": data.get("remote_addr"),
        "method": method,
        "url": url,
        "status": status_code,
        "user_agent": data.get("http_user_agent"),

        "body_bytes_sent": int(data.get("body_bytes_sent", 0)),
        "http_referer": data.get("http_referer"),

        "timestamp": int(time.time()),
        "datetime": datetime.utcnow().isoformat() + "Z",
        "source": "nginx",

        "attack_type": data.get("attack_type") or ("WAF Block" if is_blocked else None),
        "rule_id": data.get("rule_id") or data.get("waf_rule_id"),
        "severity": data.get("severity") or ("CRITICAL" if is_blocked else None),
        "alert": False,

        "request_length": len(url or ""),
        "has_query": "?" in (url or ""),
        "is_suspicious_path": any(x in (url or "").lower() for x in ["admin", "login", "wp", "sql"]),

        "raw": data
    }


# -----------------------------
# MODSEC NORMALIZE
# -----------------------------
def normalize_modsec(data):
    tx = data.get("transaction", {})
    req = tx.get("request", {})
    res = tx.get("response", {})
    headers = req.get("headers", {})
    msgs = tx.get("messages", [])

    request_id = (
        headers.get("X-Request-ID")
        or headers.get("x-request-id")
        or tx.get("transaction", {}).get("id")
        or tx.get("unique_id")
    )
    attack_type = None
    rule_id = None
    severity = None

    if msgs:
        specific_rule = None
        for m in msgs:
            details = m.get("details", {})
            rid = str(details.get("ruleId") or m.get("ruleId") or "")
            if rid and rid not in ["949110", "980130"]:
                specific_rule = m
                break
        if not specific_rule and msgs:
            specific_rule = msgs[0]

        if specific_rule:
            attack_type = specific_rule.get("message")
            details = specific_rule.get("details", {})
            rule_id = str(details.get("ruleId") or specific_rule.get("ruleId") or "")
            raw_sev = details.get("severity") or specific_rule.get("severity")
            if raw_sev is not None:
                severity = SEVERITY_NUM_MAP.get(str(raw_sev).strip(), str(raw_sev).upper())

    url = req.get("uri", "")
    http_code = int(res.get("http_code", 0))

    if http_code == 403 and not severity:
        severity = "CRITICAL"

    return {
        "request_id": request_id,
        "ip": tx.get("client_ip"),
        "method": req.get("method"),
        "url": url,
        "status": http_code,
        "user_agent": headers.get("User-Agent") or headers.get("user-agent"),

        "body_bytes_sent": len(res.get("body", "")),
        "http_referer": headers.get("Referer") or headers.get("referer"),

        "timestamp": int(time.time()),
        "datetime": datetime.utcnow().isoformat() + "Z",
        "source": "modsec",

        "attack_type": attack_type,
        "rule_id": rule_id,
        "severity": severity,
        "alert": False,

        "request_length": len(url),
        "has_query": "?" in url,
        "is_suspicious_path": any(x in url.lower() for x in ["admin", "login", "wp", "sql", "attack"]),

        "client_port": tx.get("client_port"),
        "server_ip": tx.get("host_ip"),

        "raw": data,
    }


# -----------------------------
# MERGE LOGIC
# -----------------------------
def try_merge(key):
    entry = log_buffer.get(key)
    if not entry:
        return

    if "access" in entry and "modsec" in entry:
        access = entry["access"]
        modsec = entry["modsec"]

        merged = {
            **access,
            **modsec,
            "source": "merged",
            "alert": False
        }

        if not merged.get("rule_id"):
            merged["rule_id"] = access.get("rule_id") or modsec.get("rule_id")
        if not merged.get("severity"):
            merged["severity"] = access.get("severity") or modsec.get("severity")

        print("🔥 MERGED:", key, "Rule:", merged.get("rule_id"), "Sev:", merged.get("severity"))
        save_hybrid_log(merged)

        # Trigger Telegram Alert for blocked attack
        if merged.get("status") in [403, 429] or merged.get("severity") in ["CRITICAL", "HIGH"]:
            asyncio.create_task(dispatch_telegram_alert(merged))

        del log_buffer[key]


# -----------------------------
# FALLBACK CLEANER
# -----------------------------
async def flush_old_logs():
    while True:
        now = time.time()

        for key in list(log_buffer.keys()):
            entry = log_buffer[key]
            created = entry.get("ts", now)

            if now - created > MERGE_TIMEOUT:
                data = entry.get("modsec") or entry.get("access")

                if data:
                    print("⚠️ FALLBACK SAVE:", key)
                    save_hybrid_log(data)
                    if data.get("status") in [403, 429] or data.get("severity") in ["CRITICAL", "HIGH"]:
                        asyncio.create_task(dispatch_telegram_alert(data))

                del log_buffer[key]

        await asyncio.sleep(1)


# -----------------------------
# FILE TAIL
# -----------------------------
async def tail_file(path):
    logger.info("Opening log file: %s", path)
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue
            yield line.strip()


# -----------------------------
# PROCESS ACCESS (Skip CDN Edge duplicates)
# -----------------------------
async def process_access_log():
    async for line in tail_file(ACCESS_LOG):
        try:
            raw = json.loads(line)
            remote_ip = str(raw.get("remote_addr", "")).strip()
            
            if remote_ip in KNOWN_EDGE_IPS:
                continue

            data = normalize_access(raw)
            key = data.get("request_id")
            if not key:
                continue
            logger.debug("ACCESS: %s", key)
            log_buffer.setdefault(key, {"ts": time.time()})
            log_buffer[key]["access"] = data
            try_merge(key)
        except Exception as e:
            logger.error("access log parse error: %s", e)


# -----------------------------
# PROCESS MODSEC
# -----------------------------
async def process_audit_log():
    async for line in tail_file(AUDIT_LOG):
        try:
            raw = json.loads(line)
            data = normalize_modsec(raw)
            key = data.get("request_id")
            if not key:
                continue
            logger.debug("MODSEC: %s", key)
            log_buffer.setdefault(key, {"ts": time.time()})
            log_buffer[key]["modsec"] = data
            try_merge(key)
        except Exception as e:
            logger.error("audit log parse error: %s", e)


# -----------------------------
# WORKER
# -----------------------------
async def log_forward_worker():
    logger.info("🚀 Starting log forwarder...")
    await asyncio.gather(
        process_access_log(),
        process_audit_log(),
        flush_old_logs()
    )
