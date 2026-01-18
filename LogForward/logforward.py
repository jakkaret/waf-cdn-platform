
import os
import json
import threading
import urllib.request
import urllib.error
from datetime import datetime

# Configuration
LOG_FILES = [
    {
        "path": "logs/modsecurity/audit/audit.json",
        "type": "json",
    }
    # {
    #     "path": "../logs/nginx/access_ssl.log",
    #     "type": "nginx",
    # }
]

DESTINATION_URL = "http://localhost:9000/log"
POINTER_FILE = "LogForward/pointer.txt"
def read_json(log_file):
    offset = 0
    # โหลด offset ล่าสุด
    if os.path.exists(POINTER_FILE):
        with open(POINTER_FILE, "r", encoding="utf-8") as pointer_file:
            offset = int(pointer_file.read() or 0)

    with open(log_file, "r", encoding="utf-8") as f:
        f.seek(offset)  # ไปตำแหน่งล่าสุด
        for line in f:
            try:
                json_data = json.loads(line)
                tx = json_data.get("transaction", {})

                req = tx.get("request", {})
                res = tx.get("response", {})
                headers = req.get("headers", {})

                event = {
                    "timestamp": tx.get("time_stamp"),
                    "ingest_time": datetime.utcnow().isoformat() + "Z",
                    "client": {
                        "ip": tx.get("client_ip"),
                        "port": tx.get("client_port"),
                    },
                    "server": {
                        "ip": tx.get("host_ip"),
                        "port": tx.get("host_port"),
                        "id": tx.get("server_id"),
                    },
                    "request": {
                        "method": req.get("method"),
                        "version": req.get("http_version"),
                        "uri": req.get("uri"),
                        "headers": {
                            "User-Agent": headers.get("User-Agent"),
                            "Host": headers.get("Host"),
                            "Accept": headers.get("Accept"),
                            "Accept-Language": headers.get("Accept-Language"),
                            "Accept-Encoding": headers.get("Accept-Encoding"),
                            "Connection": headers.get("Connection"),
                            "Upgrade-Insecure-Requests": headers.get("Upgrade-Insecure-Requests"),
                            "Sec-Fetch-User": headers.get("Sec-Fetch-User"),
                            "Sec-Fetch-Site": headers.get("Sec-Fetch-Site"),
                            "Sec-Fetch-Mode": headers.get("Sec-Fetch-Mode"),
                            "Sec-Fetch-Dest": headers.get("Sec-Fetch-Dest"),
                            "sec-ch-ua": headers.get("sec-ch-ua"),
                            "sec-ch-ua-platform": headers.get("sec-ch-ua-platform"),
                            "sec-ch-ua-mobile": headers.get("sec-ch-ua-mobile"),
                        }
                    },
                    "response": {
                        "http_code": res.get("http_code"),
                        "body_len": len(res.get("body", "")) if res.get("body") else 0,
                        "headers": res.get("headers"),
                    },
                    "unique_id": tx.get("unique_id")
                }

                append_event_to_file(event)

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print("ERROR:", e)

        # หลังจากอ่านเสร็จ → บันทึกตำแหน่งล่าสุด
        with open(POINTER_FILE, "w", encoding="utf-8") as pointer_file:
            pointer_file.write(str(f.tell()))
def append_event_to_file(event, output_file="LogForward/events.jsonl"):
    SEEN_IDS = set()
    if event["unique_id"] in SEEN_IDS:
        return
    SEEN_IDS.add(event["unique_id"])

    with open(output_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
# def normalize_json(json_data):
#     return json_data

def main():
    read_json(LOG_FILES[0]["path"])

if __name__ == "__main__":
    main()