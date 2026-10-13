import os
import sys
import asyncio
import json
import urllib.request
import urllib.parse
from typing import Dict, Any

# ML API Endpoints. Gen 3 only since 2026-10-13 (the RandomForest is retired, as in
# dashboard/backend/api/ml.py): /predict-gen3 decides, /generate-rule-gen3 names the
# detector rules. ML_PREDICT_URL still overrides the scoring endpoint.
BASE_ML_URL = os.environ.get("ML_API_URL", "http://127.0.0.1:5000").rstrip("/")
PREDICT_URL = os.environ.get("ML_PREDICT_URL") or f"{BASE_ML_URL}/predict-gen3"
RULE_GEN_URL = f"{BASE_ML_URL}/generate-rule-gen3"
# Same token as the backend (dashboard/backend/api/ml.py) when the ML service is remote.
ML_HEADERS = {"Content-Type": "application/json"}
if os.environ.get("ML_SERVICE_TOKEN"):
    ML_HEADERS["X-WAF-ML-Token"] = os.environ["ML_SERVICE_TOKEN"]

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Log targets: All CDN Edge Nodes (TH, SG, JP) + Main Origin WAF
TARGET_LOG_FILES = {
    "TH": os.path.join(BASE_DIR, "logs/cdn/th/access.json"),
    "SG": os.path.join(BASE_DIR, "logs/cdn/sg/access.json"),
    "JP": os.path.join(BASE_DIR, "logs/cdn/jp/access.json"),
    "MAIN-WAF": os.path.join(BASE_DIR, "logs/nginx/access.json")
}

def send_prediction_request(url: str, method: str = "GET", body: str = "") -> Dict[str, Any]:
    """Synchronous HTTP call to FastAPI ML Microservice with fast timeout."""
    try:
        data = json.dumps({"url": url, "method": method, "body": body}).encode("utf-8")
        req = urllib.request.Request(PREDICT_URL, data=data, headers=ML_HEADERS, method="POST")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        # Ignore silent network hiccups
        pass
    return None

def send_rule_generation_request(url: str, method: str = "GET", body: str = "") -> Dict[str, Any]:
    """Gen3-rules for a flagged request: {"detectors": [...], "rules": [...]} (printed, not queued)."""
    try:
        data = json.dumps({"url": url, "method": method, "body": body}).encode("utf-8")
        req = urllib.request.Request(RULE_GEN_URL, data=data, headers=ML_HEADERS, method="POST")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass
    return None

async def tail_log_channel(channel_name: str, log_path: str):
    """Asynchronously tail a specific log file and process events in real-time."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    if not os.path.exists(log_path):
        with open(log_path, "w", encoding="utf-8") as f:
            pass
        print(f"[*] Initialized log file for [{channel_name}]: {log_path}")

    print(f"[+] Channel [{channel_name}] active. Watching: {log_path}")

    # Open file and seek to the end
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                await asyncio.sleep(0.5)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                raw = json.loads(line)
                # Some logs arrive as array of logs or wrapped dict
                log_entries = raw.get("logs", [raw]) if isinstance(raw, dict) else [raw]

                for log_entry in log_entries:
                    if not isinstance(log_entry, dict):
                        continue

                    url = (
                        log_entry.get("request_uri") or
                        log_entry.get("uri") or
                        log_entry.get("url") or
                        log_entry.get("request") or
                        ""
                    )
                    if " " in url:
                        parts = url.split(" ")
                        method = parts[0]
                        url = parts[1] if len(parts) > 1 else url
                    else:
                        method = log_entry.get("method") or log_entry.get("request_method") or "GET"

                    body = log_entry.get("body") or log_entry.get("request_body") or ""
                    ip = (
                        log_entry.get("remote_addr") or
                        log_entry.get("client_ip") or
                        log_entry.get("ip") or
                        "unknown"
                    )

                    if not url:
                        continue

                    # Run ML Prediction in thread pool to avoid blocking async loop
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(None, send_prediction_request, url, method, body)

                    if result and (result.get("is_attack") or result.get("is_anomaly")):  # /predict-gen3 (| old /predict)
                        prob = result.get("attack_probability", 0.0) * 100
                        print(f"🚨 [{channel_name} DETECTED] IP: {ip:<15} | Prob: {prob:5.1f}% | URL: {url}")

                        # Which Gen3-rules this request would propose. Printed only: the
                        # admin queue is fed by the dashboard (predict-and-suggest).
                        rule_res = await loop.run_in_executor(None, send_rule_generation_request, url, method, body)
                        for rule in (rule_res or {}).get("rules", []):
                            print(f"✨ [{channel_name} RULE CANDIDATE] {rule.get('attack_type')}: {rule.get('pattern')}")
                    elif result:
                        print(f"✅ [{channel_name} PASS] IP: {ip:<15} | URL: {url}")

            except json.JSONDecodeError:
                pass
            except Exception as ex:
                print(f"[!] Error in channel [{channel_name}]: {ex}")

async def main():
    print("==================================================================")
    print("🚀 WAF Real-time Multi-Channel Stream Log Analyzer Starting...")
    print(f"[*] Target ML Microservice: {PREDICT_URL}")
    print(f"[*] Channels: {list(TARGET_LOG_FILES.keys())}")
    print("==================================================================")

    tasks = [
        tail_log_channel(name, path)
        for name, path in TARGET_LOG_FILES.items()
    ]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Log Analyzer stopped by user.")
