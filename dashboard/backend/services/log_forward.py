import asyncio
import json
import logging
import os
import time
from datetime import datetime
from services.dynamodb_service import DynamoDBService
from services.clickhouse_service import ClickHouseService

logger = logging.getLogger(__name__)


db = DynamoDBService()
ch = ClickHouseService()
log_buffer = {}

def save_hybrid_log(data: dict):
    if ch.connected:
        ch.save_log("access_logs", data)
    db.save_log(data)

BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../")
)

ACCESS_LOG = os.path.join(BASE_DIR, "logs/nginx/access.json")

AUDIT_LOG = os.path.join(BASE_DIR, "logs/modsecurity/audit.json")

MERGE_TIMEOUT = 5  # วินาที


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

    return {
        "request_id": data.get("request_id"),
        "ip": data.get("remote_addr"),
        "method": method,
        "url": url,
        "status": int(data.get("status", 0)),
        "user_agent": data.get("http_user_agent"),

        "body_bytes_sent": int(data.get("body_bytes_sent", 0)),
        "http_referer": data.get("http_referer"),

        "timestamp": int(time.time()),
        "datetime": datetime.utcnow().isoformat() + "Z",
        "source": "nginx",

        "attack_type": None,
        "rule_id": None,
        "severity": None,
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

    # 🔥 ใช้ header ก่อน แล้ว fallback
    request_id = (
    headers.get("X-Request-ID")
    or headers.get("x-request-id")
    or tx.get("transaction", {}).get("id")   # 🔥 สำคัญ
    or tx.get("unique_id")
    )
    attack_type = None
    rule_id = None
    severity = None

    if msgs:
        attack_type = msgs[0].get("message")
        rule_id = msgs[0].get("details", {}).get("ruleId")
        severity = msgs[0].get("details", {}).get("severity")

    url = req.get("uri", "")

    return {
        "request_id": request_id,
        "ip": tx.get("client_ip"),
        "method": req.get("method"),
        "url": url,
        "status": int(res.get("http_code", 0)),
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
            **modsec,  # modsec override

            "source": "merged",
            "alert": False
        }

        print("🔥 MERGED:", key)
        save_hybrid_log(merged)
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
# PROCESS ACCESS
# -----------------------------
async def process_access_log():
    async for line in tail_file(ACCESS_LOG):
        try:
            raw = json.loads(line)
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