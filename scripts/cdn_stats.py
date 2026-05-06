#!/usr/bin/env python3

# CDN Cache Hit/Miss Stats Collector
# Phase 1 – งาน: Cache hit/miss  (label: ริว)

# อ่าน access log (JSON) ของทุก edge node แล้ว expose
# metrics ผ่าน HTTP /metrics endpoint (port 9090)
# FastAPI dashboard สามารถ GET /api/cdn/stats ได้


import json
import os
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Config ─────────────────────────────────
REGIONS = ["sg", "jp", "us", "de", "ch"]
LOG_DIR = "/logs"          # mount point ใน container
POLL_INTERVAL = 5          # วินาที
PORT = 9090

# ── State ───────────────────────────────────
stats = defaultdict(lambda: {
    "hit": 0, "miss": 0, "bypass": 0, "expired": 0,
    "stale": 0, "updating": 0, "revalidated": 0,
    "total_requests": 0,
    "status_2xx": 0, "status_4xx": 0, "status_5xx": 0,
    "avg_response_time_ms": 0.0,
    "last_updated": None,
})

# ── File position tracking ───────────────────
file_positions = {}


def parse_log_line(line: str) -> dict | None:
    """parse JSON log line จาก nginx"""
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None


def classify_cache_status(status: str) -> str:
    """Normalize cache status ให้เป็น lowercase"""
    s = (status or "").upper()
    if s == "HIT":       return "hit"
    if s == "MISS":      return "miss"
    if s == "BYPASS":    return "bypass"
    if s == "EXPIRED":   return "expired"
    if s == "STALE":     return "stale"
    if s == "UPDATING":  return "updating"
    if s == "REVALIDATED": return "revalidated"
    return "miss"  # fallback


def tail_logs():
    """อ่าน log ใหม่จากทุก region ทุก POLL_INTERVAL วินาที"""
    global file_positions

    while True:
        for region in REGIONS:
            log_path = os.path.join(LOG_DIR, region, "access.json")
            if not os.path.exists(log_path):
                continue

            pos = file_positions.get(log_path, 0)
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    f.seek(pos)
                    new_lines = f.readlines()
                    file_positions[log_path] = f.tell()

                for line in new_lines:
                    entry = parse_log_line(line)
                    if not entry:
                        continue

                    region_key = region.upper()
                    s = stats[region_key]

                    # นับ cache status
                    cache_status = classify_cache_status(
                        entry.get("cache_status", "")
                    )
                    s[cache_status] = s.get(cache_status, 0) + 1
                    s["total_requests"] += 1

                    # นับ HTTP status
                    http_status = str(entry.get("status", "0"))
                    if http_status.startswith("2"):
                        s["status_2xx"] += 1
                    elif http_status.startswith("4"):
                        s["status_4xx"] += 1
                    elif http_status.startswith("5"):
                        s["status_5xx"] += 1

                    # avg response time
                    try:
                        rt = float(entry.get("request_time", 0)) * 1000
                        total = s["total_requests"]
                        old_avg = s["avg_response_time_ms"]
                        s["avg_response_time_ms"] = (
                            (old_avg * (total - 1) + rt) / total
                        )
                    except (ValueError, ZeroDivisionError):
                        pass

                    s["last_updated"] = datetime.utcnow().isoformat() + "Z"

            except Exception as e:
                print(f"[{region}] log read error: {e}")

        time.sleep(POLL_INTERVAL)


def compute_summary() -> dict:
    """คำนวณ summary สำหรับทุก region"""
    result = {}

    total_all = {"hit": 0, "miss": 0, "bypass": 0,
                 "total_requests": 0, "status_2xx": 0,
                 "status_4xx": 0, "status_5xx": 0}

    for region in [r.upper() for r in REGIONS]:
        s = stats[region]
        total = s["total_requests"] or 1

        hit_rate = round(s["hit"] / total * 100, 2)
        miss_rate = round(s["miss"] / total * 100, 2)

        result[region] = {
            "region": region,
            "hit":    s["hit"],
            "miss":   s["miss"],
            "bypass": s["bypass"],
            "expired": s["expired"],
            "stale":  s["stale"],
            "total_requests": s["total_requests"],
            "hit_rate_pct":  hit_rate,
            "miss_rate_pct": miss_rate,
            "status_2xx": s["status_2xx"],
            "status_4xx": s["status_4xx"],
            "status_5xx": s["status_5xx"],
            "avg_response_time_ms": round(s["avg_response_time_ms"], 2),
            "last_updated": s["last_updated"],
        }

        for k in total_all:
            total_all[k] += s.get(k, 0)

    # Global summary
    gt = total_all["total_requests"] or 1
    result["GLOBAL"] = {
        "region": "GLOBAL",
        **total_all,
        "hit_rate_pct":  round(total_all["hit"] / gt * 100, 2),
        "miss_rate_pct": round(total_all["miss"] / gt * 100, 2),
        "last_updated": datetime.utcnow().isoformat() + "Z",
    }

    return result


class StatsHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default logging

    def do_GET(self):
        if self.path in ("/metrics", "/stats", "/"):
            body = json.dumps(compute_summary(), indent=2).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    print(f"🚀 CDN Stats Collector starting on port {PORT}")
    print(f"   Watching logs in: {LOG_DIR}")
    print(f"   Regions: {', '.join(r.upper() for r in REGIONS)}")
    print(f"   Poll interval: {POLL_INTERVAL}s")

    # background thread อ่าน log
    t = threading.Thread(target=tail_logs, daemon=True)
    t.start()

    server = HTTPServer(("0.0.0.0", PORT), StatsHandler)
    print(f"   Stats endpoint: http://localhost:{PORT}/metrics")
    server.serve_forever()
