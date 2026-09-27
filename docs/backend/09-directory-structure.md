---
title: "บทที่ 09 — โครงสร้างไดเรกทอรี"
chapter: 9
part: "Part III — Backend"
status: VERIFIED
---

# บทที่ 09 — โครงสร้างไดเรกทอรี (Directory Structure)

## 9.1 ระดับ repository

| ไดเรกทอรี | เนื้อหา | ใช้ใน production |
|---|---|---|
| `dashboard/backend/` | FastAPI backend | ใช่ (`waf-dashboard`) |
| `dashboard/frontend/` | React + Vite dashboard | ใช่ (build แล้วเสิร์ฟโดย backend) |
| `ml/` | ML API, log analyzer, โมเดล (`ml/models/*.joblib`, `*.onnx`), สคริปต์ train/evaluate | ใช่ (`waf-ml`, `waf-log-analyzer`) |
| `nginx/` | Caddyfile ของ Main, template nginx/ModSecurity, includes captcha/OTP | ใช่ (mount เข้า container) |
| `modsecurity/custom-rules/` | กฎ custom (`custom-*.conf`, `ml-*.conf`, `custom-deceive.conf`) | ใช่ (mount + bundle ไป edge) |
| `cdn/control-api/` | FastAPI เล็กสำหรับ challenge, blocklist, rule bundle | ใช่ (`waf-control-api`) |
| `cdn/edge/` | template ของ edge node, entrypoint rulesync, หน้า 403/429 | ใช่ (สำเนาไปอยู่ที่ edge) |
| `cdn/geodns/` | GeoDNS server | รันอยู่ แต่ไม่ได้อยู่ในเส้นทาง DNS สาธารณะ |
| `cdn/purge-api/`, `cdn/stats/`, `cdn/docker-compose-cdn.yml` | ชุด CDN แบบจำลองในเครื่องเดียว (legacy) | ไม่พบว่ารันบน Main (DEPRECATED/UNKNOWN) |
| `tunnel/` | ซอร์สของ CloudWAF tunnel (`server.py`, `agent.py`, `protocol.py`) | ตัวที่รันจริงอยู่ที่ `/opt/cloudwaf-tunnel/server.py` |
| `scripts/` | สคริปต์ปฏิบัติการ เช่น `sync_waf_rules.py` | บางส่วน |
| `html/` | หน้า 403 ของ Main | ใช่ |
| `logs/` | log ของ nginx/ModSecurity (mount) | runtime |
| `docs/` | เอกสารชุดนี้และเอกสารเดิม | – |
| `.github/workflows/ci.yml` | CI (ruff, tsc, build) | ดูหมายเหตุบทที่ 08 |

> ใน root ของ repo บนเครื่อง production มีสคริปต์ชั่วคราวที่ไม่ได้อยู่ใน git (เช่น `patch_*.py`, `fix_*.py`) ไม่ใช่ส่วนของระบบ

## 9.2 `dashboard/backend/`

| Path | บทบาท |
|---|---|
| `main.py` | สร้างแอป, middleware, include router 24 ตัว, startup workers, เสิร์ฟ SPA |
| `api/` | 24 ไฟล์ router (ดู [API Reference](../reference/api-reference.md)) |
| `services/` | ตรรกะหลัก 40+ โมดูล เช่น `auth_service`, `rbac`, `tenant_service`, `dynamodb_service`, `clickhouse_service`, `log_forward`, `cdn_log_forward`, `telegram_listener`, `rule_manager`, `deception_service`, `geoip`, `dns_service`, `origin_service` |
| `scripts/` | สร้างตาราง DynamoDB, migration, อัปเดต GeoIP, backfill |
| `data/` | SQLite `ip_rules.db`, `rate_limits.db`, `system_settings.json`, ฐาน GeoIP (ไม่อยู่ใน git) |
| `tests/` | ชุดทดสอบ pytest 68 ไฟล์ (`conftest.py` แทนที่ DynamoDB/ClickHouse ด้วยตัวปลอม) |
| `.venv/` | virtualenv (Python 3.14) บนเครื่อง Main — ไม่อยู่ใน git |

## 9.3 `dashboard/frontend/src/`

| Path | บทบาท |
|---|---|
| `App.tsx` | กำหนด route ทั้งหมด |
| `pages/` | 35 ไฟล์หน้า รวม `pages/concepts/` |
| `components/` | layout (Sidebar, Header), ui (Drawer, Modal, Badge, StatCard ...) |
| `api/` | client เรียก backend ผ่าน axios |
| `store/` | Zustand (`authStore`, `themeStore`) |
| `types/` | TypeScript types |

## แหล่งอ้างอิง (Evidence)
- `git ls-tree -d HEAD`, `git ls-files`, `systemctl show waf-dashboard`
