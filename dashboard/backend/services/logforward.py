import os
import json
import threading
import urllib.request
import urllib.error
from datetime import datetime
import time
from dynamodb_service import DynamoDBService

SEEN_IDS = set()


async def compute_ttl(seconds=60 * 60 * 24 * 90):
    return int(time.time()) + seconds


# Configuration
LOG_FILES = [
    {
        "path": "logs/modsecurity/audit.json",
        "type": "json",
    },
     {
         "path": "../logs/nginx/access.log",
         "type": "nginx",
     }
]

DESTINATION_URL = "http://localhost:9000/log"
POINTER_FILE = "./pointer.txt"


async def read_json(log_file):
    offset = 0
    pointer_file_name = f"{POINTER_FILE}_{os.path.basename(log_file)}"
    if os.path.exists(pointer_file_name):
        with open(pointer_file_name, "r", encoding="utf-8") as pointer_file:
            offset = int((pointer_file.read() or "0").strip() or 0)

    with open(log_file, "rb") as f:
        f.seek(offset)
        for line in f:
            try:
                line = line.decode("utf-8", errors="ignore")
                json_data = json.loads(line)
                tx = json_data.get("transaction", {})
                req = tx.get("request", {})
                res = tx.get("response", {})
                headers = {k.lower(): v for k, v in req.get("headers", {}).items()}

                event = {
                    "timestamp": tx.get("time_stamp"),
                    "ingest_time": datetime.utcnow().isoformat() + "Z",
                    "client_ip": tx.get("client_ip"),
                    "client_port": tx.get("client_port"),
                    "host_ip": tx.get("host_ip"),
                    "host_port": tx.get("host_port"),
                    "method": req.get("method"),
                    "uri": req.get("uri"),
                    "ruleId": tx.get("ruleId"),
                    "http_version": req.get("http_version"),
                    "user_agent": headers.get("user-agent"),
                    "status_code": res.get("http_code"),
                    "body_bytes_sent": tx.get("content_length"),
                    "request_time": tx.get("request_time"),
                    "unique_id": tx.get("unique_id"),
                    "messages": json_data.get("messages", []),
                    "source": "modsec",
                }

                normalized = normalize_event(event)
                append_event_to_file(normalized)

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print("ERROR:", e)

        with open(pointer_file_name, "w", encoding="utf-8") as pointer_file:
            pointer_file.write(str(f.tell()))


async def normalize_event(event):
    status = event.get("status_code")
    try:
        status_code = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_code = None

    messages = event.get("messages", [])
    ruleId = None
    message = None
    severity = None
    if messages:
        details = messages[0].get("details", {})
        ruleId = details.get("ruleId")
        message = messages[0].get("message")
        severity = details.get("severity")

    return {
        "timestamp": event.get("timestamp"),
        "client_ip": event.get("client_ip"),
        "client_port": event.get("client_port"),
        "host_ip": event.get("host_ip"),
        "host_port": event.get("host_port"),
        "method": event.get("method"),
        "uri": event.get("uri"),
        "http_version": event.get("http_version"),
        "status_code": status_code,
        "body_bytes_sent": event.get("content_length"),
        "user_agent": event.get("user_agent"),
        "request_time": event.get("request_time"),
        "ruleId": ruleId,
        "message": message,
        "severity": severity,
        "unique_id": event.get("unique_id"),
        "source": event.get("source"),
        "alert": False,
        "processed": False,
        "ttl": compute_ttl(),
    }



# async def append_event(event):
#     """
#     บันทึก WAF log ลงใน DynamoDB (waf_logs table)
#     """
#     unique_id = event.get("unique_id")
#     if unique_id:
#         if unique_id in SEEN_IDS:
#             return
#         SEEN_IDS.add(unique_id)

#     # บันทึกลง DynamoDB โดยใช้ dynamodb_service
#     save_log_to_dynamodb(event)

async def save_log_to_dynamodb(event):
    """
    ฟังก์ชันสำหรับบันทึก WAF logs ลง DynamoDB โดยเฉพาะ
    """
    try:
        # สร้าง instance ของ DynamoDBService
        db_service = DynamoDBService()
        
        # บันทึก log ลง waf_logs table
        success = db_service.save_log(event)
        
        if success:
            print(f"✅ Saved WAF log to DynamoDB: {event.get('unique_id', 'unknown')}")
        else:
            print(f"❌ Failed to save WAF log: {event.get('unique_id', 'unknown')}")
            
        return success
    except Exception as e:
        print(f"❌ Error saving WAF log to DynamoDB: {e}")
        return False


async def save_waf_log_direct(event_data):
    """
    ฟังก์ชันสำหรับบันทึก WAF log โดยตรงลง DynamoDB โดยไม่ต้องผ่านการประมวลผลไฟล์
    """
    try:
        # สร้าง instance ของ DynamoDBService
        db_service = DynamoDBService()
        
        # บันทึก log ลง waf_logs table
        success = db_service.save_log(event_data)
        
        if success:
            print(f"✅ Directly saved WAF log to DynamoDB: {event_data.get('unique_id', 'unknown')}")
        else:
            print(f"❌ Failed to directly save WAF log: {event_data.get('unique_id', 'unknown')}")
            
        return success
    except Exception as e:
        print(f"❌ Error directly saving WAF log to DynamoDB: {e}")
        return False
async def log_worker():
    print("📡 Telegram logs Worker started")

    while True:
        # TODO: ตรงนี้อนาคตจะเป็น parse log จริง
        await alert_403_if_new("192.168.1.1", "/login.php")

        await asyncio.sleep(10)  # กัน CPU พัง


def main():
    # อ่านและบันทึก logs จากไฟล์
    read_json(LOG_FILES[0]["path"])
    
    # ตัวอย่างการบันทึก WAF log โดยตรง
    sample_waf_log = {
        "client_ip": "",
        "method": "POST",
        "uri": "/login.php",
        "status_code": 403,
        "ruleId": "932100",
        "message": "SQL Injection Attack Detected",
        "severity": "CRITICAL",
        "unique_id": "test-123",
        "source": "modsec",
        "alert": True,
        "processed": False
    }
    save_waf_log_direct(sample_waf_log)
if __name__ == "__main__":
    main()
