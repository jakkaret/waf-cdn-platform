import os
import sys
import time
import requests
import json

# ML API Endpoint (FastAPI Microservice)
ML_API_URL = "http://localhost:5000/predict"

def analyze_single_log(request_url: str, method: str = "GET", body: str = ""):
    """Send log event to ML Microservice for prediction."""
    try:
        payload = {
            "url": request_url,
            "method": method,
            "body": body
        }
        res = requests.post(ML_API_URL, json=payload, timeout=2.0)
        if res.status_code == 200:
            return res.json()
    except Exception as e:
        print(f"[!] Error connecting to ML API: {e}")
    return None

def process_log_stream(log_file_path: str):
    """
    Tail log file and process incoming WAF logs continuously.
    """
    print(f"[*] Starting Real-time Log Stream Analyzer on: {log_file_path}")
    if not os.path.exists(log_file_path):
        print(f"[!] Log file not found at {log_file_path}. Creating sample log stream...")
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        with open(log_file_path, "w") as f:
            f.write("")

    with open(log_file_path, "r") as f:
        # Move pointer to end of file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            # Example JSON log parsing: {"ip": "1.2.3.4", "url": "/login", "method": "GET"}
            try:
                log_entry = json.loads(line.strip())
                url = log_entry.get("url") or log_entry.get("request_uri", "")
                method = log_entry.get("method", "GET")
                body = log_entry.get("body", "")
                ip = log_entry.get("ip", "unknown")

                result = analyze_single_log(url, method, body)
                if result and result.get("is_anomaly"):
                    prob = result.get("attack_probability", 0.0) * 100
                    print(f"🚨 [MALICIOUS DETECTED] IP: {ip:<15} | Prob: {prob:.1f}% | URL: {url}")
                    # ACTION: Push IP to blocklist or trigger alert
                else:
                    print(f"✅ [BENIGN PASS] IP: {ip:<15} | URL: {url}")

            except json.JSONDecodeError:
                pass

if __name__ == "__main__":
    sample_log_path = "/home/chirachot/seminar/waf_project/logs/waf_stream.log"
    process_log_stream(sample_log_path)
