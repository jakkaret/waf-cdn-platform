import os
import sys
import asyncio
import json
import urllib.request
import urllib.parse
from typing import Dict, Any

# ML API Endpoints
BASE_ML_URL = os.environ.get("ML_API_URL", "http://127.0.0.1:5000").rstrip("/")
PREDICT_URL = f"{BASE_ML_URL}/predict" if not BASE_ML_URL.endswith("/predict") else BASE_ML_URL
RULE_GEN_URL = f"{BASE_ML_URL}/generate-rule"

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
        req = urllib.request.Request(PREDICT_URL, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        # Ignore silent network hiccups
        pass
    return None

def send_rule_generation_request(url: str, method: str = "GET", body: str = "", attack_type: str = "Anomaly") -> Dict[str, Any]:
    """Request auto-generation of ModSecurity SecRule."""
    try:
        data = json.dumps({"url": url, "method": method, "body": body, "attack_type": attack_type}).encode("utf-8")
        req = urllib.request.Request(RULE_GEN_URL, data=data, headers={"Content-Type": "application/json"}, method="POST")
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

                    if result and result.get("is_anomaly"):
                        prob = result.get("attack_probability", 0.0) * 100
                        print(f"🚨 [{channel_name} DETECTED] IP: {ip:<15} | Prob: {prob:5.1f}% | URL: {url}")

                        # Trigger Auto Rule Suggestion
                        rule_res = await loop.run_in_executor(None, send_rule_generation_request, url, method, body, "Threat Payload")
                        if rule_res and rule_res.get("pattern"):
                            print(f"✨ [{channel_name} RULE SUGGESTED] Pattern: {rule_res.get('pattern')} -> Pending Approval")
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
