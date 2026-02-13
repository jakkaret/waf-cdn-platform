import asyncio
import json
import os
import time
from services.dynamodb_service import DynamoDBService
from decimal import Decimal

db = DynamoDBService()
BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../")
)
ACCESS_LOG = os.path.join(BASE_DIR, "logs/nginx/access.json")
AUDIT_LOG = os.path.join(BASE_DIR, "logs/modsecurity/audit.json")
async def tail_file(path):
    print("Opening log file:", path)

    if not os.path.exists(path):
        print("❌ File not found:", path)

    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue
            print("RAW LINE:", line)
            yield line.strip()

async def process_access_log():
    async for line in tail_file(ACCESS_LOG):
        try:
            data = json.loads(line)
            db.save_log(data)
        except Exception as e:
            print("access error:", e)

async def process_audit_log():
    async for line in tail_file(AUDIT_LOG):
        try:
            data = json.loads(line)
            db.save_log(data)
        except Exception as e:
            print("audit error:", e)

async def log_forward_worker():
    print("📡 Starting realtime log forwarder...")
    await asyncio.gather(
        process_access_log(),
        process_audit_log()
    )
