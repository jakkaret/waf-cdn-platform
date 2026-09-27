---
title: "บทที่ 37 — การตั้งค่า Environment"
chapter: 37
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 37 — การตั้งค่า Environment

## 37.1 ตำแหน่งไฟล์ค่าตั้ง

| ไฟล์ | อ่านโดย | ตัวอย่างตัวแปร (ชื่อเท่านั้น) |
|---|---|---|
| `/root/waf_project/.env` | backend (python-dotenv ค้นหาจากไดเรกทอรีแม่), `waf-nginx` (`env_file`) | `DECEPTION_INTERNAL_KEY`, `JWT_EXPIRE_MINUTES`, `CDN_PURGE_TOKEN`, ค่า AWS/Telegram/Gemini/OAuth |
| `docker-compose.yml` | container ของ Main | `PARANOIA`, `ANOMALY_INBOUND`, `ANOMALY_OUTBOUND`, `SMTP_*`, `REDIS_URL` |
| `/root/edge_node/.env`, `/opt/edge_node/.env` | edge compose | `EDGE_REGION`, `MAIN_SERVER_IP`, `ORIGIN_PORT`, `CONTROL_API_PORT` |
| `dashboard/backend/data/system_settings.json` | SettingsService | paranoia, threshold, `auto_purge_edge_cache`, `edge_sync_interval_seconds` |
| `/etc/frp/frps.toml` | frps | พอร์ต/plugin |

## 37.2 ตัวแปรที่มีค่าเริ่มต้นในโค้ด

| ตัวแปร | ค่าเริ่มต้น | ผล |
|---|---|---|
| `JWT_EXPIRE_MINUTES` | 60 | อายุ token |
| `ACCESS_LOGS_RETENTION_DAYS` | 30 | TTL ของ `access_logs` |
| `CDN_PURGE_API_URL` | `http://localhost:8080` | ปลายทาง purge (บทที่ 24) |
| `GEOIP_DB_PATH` | `backend/data/geoip/dbip-country-lite.mmdb` | ฐาน GeoIP |

> ห้าม commit `.env` หรือคัดลอกค่าลงเอกสาร ใช้ `<REDACTED>`

## แหล่งอ้างอิง (Evidence)
- `grep -c '^VAR=' .env` (ตรวจเฉพาะการมีอยู่ของชื่อ), โค้ดที่อ้างถึงใน §37.2
