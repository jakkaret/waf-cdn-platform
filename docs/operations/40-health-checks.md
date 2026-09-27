---
title: "บทที่ 40 — Health Checks"
chapter: 40
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 40 — Health Checks

| ตรวจอะไร | คำสั่ง | ผลที่คาดหวัง |
|---|---|---|
| Backend | `curl -s http://127.0.0.1:8000/api/health` (บน Main) | `200` ภายในไม่กี่ ms |
| WAF Main | `curl -s http://localhost:8080/healthz` (ใน container, ใช้โดย healthcheck) | `200` |
| ML | `curl -s http://127.0.0.1:5000/health` | `models_loaded` เป็น true |
| control-api | `curl -s http://127.0.0.1:8070/healthz` | `200` |
| Edge | `curl -s http://<edge-ip>/healthz` | JSON `{"status":"ok","region":"edge-th"}` |
| Container | `docker ps --format '{{.Names}} {{.Status}}'` | `Up ... (healthy)` สำหรับ waf-nginx/cdn-edge-node |
| Service | `systemctl is-active waf-dashboard waf-ml waf-log-analyzer frps cloudwaf-tunnel` | `active` |
| Event loop ของ backend ค้าง | `.venv/bin/py-spy dump --pid $(systemctl show -p MainPID --value waf-dashboard)` | main thread ไม่ค้างใน I/O ของ botocore |
| Public | `https://waf-it-kku.online/api/status/public` | `200` |

## แหล่งอ้างอิง (Evidence)
- ใช้จริงระหว่างการตรวจ 2026-09-24 และ 2026-09-27
