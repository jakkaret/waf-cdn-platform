---
title: "บทที่ 10 — สถาปัตยกรรม API"
chapter: 10
part: "Part III — Backend"
status: VERIFIED
---

# บทที่ 10 — สถาปัตยกรรม API

## 10.1 ภาพรวม

- ทุก endpoint อยู่ใต้ `/api/...` ยกเว้นหน้า SPA และไฟล์ static
- `main.py` ลงทะเบียน router **24 ตัว** รวม **123 endpoints** (นับจาก AST ของ `api/*.py`)
- รายการเต็มพร้อมสิทธิ์ของแต่ละ endpoint: **[API Reference](../reference/api-reference.md)** (สร้างอัตโนมัติจากโค้ด)

## 10.2 กลุ่ม API (router prefix)

| Prefix | ไฟล์ | จำนวน | หน้าที่ |
|---|---|---|---|
| `/api/auth` | `api/auth.py` | 11 | สมัคร, login, logout, Google OAuth, Telegram, `/me`, ผู้ใช้ |
| `/api/origins` | `api/origins.py`, `api/domains.py` | 18 + บางส่วน | origin ของลูกค้า, ทีม (viewer/editor), captcha/OTP ต่อ origin, audit log |
| `/api/domains` | `api/domains.py` | 9 | โดเมน, การยืนยัน DNS, `check-ssl-allowed` สำหรับ Caddy |
| `/api/rules` | `api/rules.py` | 13 | custom rule (BLOCK/CHALLENGE/DECEIVE), sync, blast radius, BOLA policy |
| `/api/logs` | `api/logs.py` | 7 | ค้น log, ตัวเลือกกรอง, explain ด้วย AI, mask PII |
| `/api/alerts` | `api/alerts.py` | 5 | alert ของ tenant |
| `/api/analytics` | `api/analytics.py` | 1 | สถิติ dashboard |
| `/api/cdn` | `api/cdn.py` | 6 | สถานะ edge, log ของ CDN, `logs/ingest` จาก edge |
| `/api/ml`, `/api/ml-rules` | `api/ml.py`, `api/ml_rules.py` | 4 + 6 | proxy ไป ML service, กฎที่ ML เสนอ |
| `/api/threshold-proposals` | `api/threshold_proposals.py` | 6 | ข้อเสนอปรับ threshold (self-tuning) |
| `/api/ip-rules`, `/api/rate-limits`, `/api/limiter` | 3 ไฟล์ | 4 + 6 + 1 | IP list, rate limit, จุดตรวจของ nginx `auth_request` |
| `/api/tunnels`, `/api/tunnel` | 2 ไฟล์ | 5 + 3 | สร้าง/ดู tunnel, hook ของ frps, ยืนยัน agent |
| `/api/settings` | `api/settings.py` | 3 | ตั้งค่า WAF (paranoia, threshold) |
| `/api/ai`, `/api/copilot` | 2 ไฟล์ | 6 + 1 | สรุปด้วย AI, notification feed, postmortem, copilot |
| `/api/threat-intel` | `api/threat_intel.py` | 2 | รูปแบบการโจมตีข้ามลูกค้า |
| `/api/status` | `api/public_status.py` | 2 | สถานะสาธารณะ |
| `/api/onboarding` | `api/onboarding.py` | 1 | สถานะขั้นตอนเริ่มต้นใช้งาน |
| `/api/deception` | `api/deception.py` | 3 | `respond` (ภายใน), `templates`, `simulate` (admin) |

## 10.3 ระดับสิทธิ์ของ endpoint

| ระดับ | Dependency | จำนวน |
|---|---|---|
| admin | `require_admin` | 33 |
| viewer ขึ้นไป | `require_viewer_or_above` | 27 |
| login อย่างเดียว | `get_current_user` | 29 |
| สิทธิ์ต่อ origin | `verify_origin_ownership` / `_access` / `_edit_access` | 17 |
| internal key | `verify_internal_deception_key` | 1 |
| ไม่มี dependency | – | 16 |

**16 endpoints ที่ไม่มี dependency ด้าน auth** ไม่ได้แปลว่าไม่มีการป้องกัน แต่ตรวจเองในโค้ด:

| Endpoint | การป้องกันจริง |
|---|---|
| `/api/auth/login`, `register`, `google*`, `telegram`, `logout` | เป็นจุดเข้าสู่ระบบ; login จำกัด 5 ครั้ง/นาที |
| `/api/cdn/logs/ingest` | อนุญาตเฉพาะ IP ของ edge forwarder (`_KNOWN_EDGE_FORWARDER_IPS`) มิฉะนั้นตอบ 404 |
| `/api/domains/check-ssl-allowed` | อ่านอย่างเดียว ตอบว่าโดเมนได้รับอนุญาตออก TLS หรือไม่ (ใช้โดย Caddy) |
| `/api/limiter/check` | จุดตรวจ rate limit ของ nginx `auth_request` |
| `/api/ml/capture`, `/api/ml/shadow/decision` | ตรวจว่าเป็นคำขอ relay ภายใน (`_is_internal_relay_request`) |
| `/api/tunnel/verify-agent`, `/api/auth/tunnel/verify`, `/api/tunnels/frp-hook` | token ของ tunnel คือ credential ที่ถูกตรวจ (hash/ลายเซ็น) ตอบ 401 เหมือนกันทุกกรณีที่ไม่ผ่าน |
| `/api/status/public*` | ข้อมูลสาธารณะโดยตั้งใจ |

## 10.4 รูปแบบ response และ error

- ใช้ `HTTPException` ของ FastAPI: `400` ข้อมูลไม่ถูกต้อง, `401` ไม่ได้ login/token หมดอายุ (`WWW-Authenticate: Bearer`), `403` สิทธิ์ไม่พอ, `404` ไม่พบ (บาง endpoint ใช้ 404 แทน 403 เพื่อไม่เปิดเผยว่ามีทรัพยากร), `429` เกิน rate limit (slowapi)
- Response เป็น JSON; list มักห่อใน key เช่น `{"rules": [...]}`, `{"policies": [...]}`

## 10.5 ตัวอย่างการเรียก

```bash
# login แล้วใช้ token (ห้ามใส่รหัสผ่านจริงในสคริปต์ที่ commit)
curl -s -X POST https://<YOUR_DOMAIN>/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"<EMAIL>","password":"<REDACTED>"}'
curl -s https://<YOUR_DOMAIN>/api/rules/ -H 'Authorization: Bearer <REDACTED>'
```

## แหล่งอ้างอิง (Evidence)
- `docs/reference/api-reference.md` (สร้างจาก `api/*.py` ด้วย AST)
- `api/cdn.py:507`, `api/tunnel.py:104`, `api/tunnels.py:439`, `api/auth.py:91`
