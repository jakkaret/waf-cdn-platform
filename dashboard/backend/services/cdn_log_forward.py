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
    url = data.get("uri", "")
    
    req_time = data.get("request_time", "0")
    try:
        latency_ms = int(float(req_time) * 1000)
    except (ValueError, TypeError):
        latency_ms = 0

    # Map edge region to ISO country code for GeoIP analytics
    # Uses the edge node's region as a reliable approximation —
    # requests are routed to the closest regional edge by GeoDNS
    _REGION_TO_COUNTRY = {"sg": "SG", "jp": "JP", "th": "TH"}
    country = _REGION_TO_COUNTRY.get(region.lower(), region.upper())

    return {
        "request_id": data.get("request_id", ""),
        "ip": data.get("remote_addr"),
        "method": method,
        "url": url,
        "status": int(data.get("status", 0)),
        "user_agent": data.get("http_user_agent", ""),
        "timestamp": int(time.time()),
        "datetime": data.get("time", datetime.utcnow().isoformat() + "Z"),
        "source": "cdn",
        "region": region.upper(),
        "country": country,
        "edge_node": f"edge-{region.lower()}",
        "cache_status": data.get("cache_status", "MISS"),
        "latency_ms": latency_ms,
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
            data = normalize_cdn_access(raw, region)
            save_hybrid_log(data)
        except Exception as e:
            print(f"cdn log error ({region}):", e)

async def cdn_log_forward_worker():
    print("🚀 Starting CDN log forwarder...")
    tasks = [process_cdn_log(region) for region in REGIONS]
    await asyncio.gather(*tasks)
