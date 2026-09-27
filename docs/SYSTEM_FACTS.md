---
title: "System Facts"
status: VERIFIED
---

# System Facts — ข้อเท็จจริงของระบบ

เอกสารนี้คือ "แหล่งข้อเท็จจริงหลัก" ที่ทุกบทในคู่มืออ้างอิงถึง บันทึกจากการตรวจ **ซอร์สโค้ด** (repository commit `c033758`, branch `Backend`) และ **สภาพระบบที่กำลังรันจริง** (runtime) เมื่อ 2026-09-27 ด้วยคำสั่งแบบอ่านอย่างเดียว หลักฐานดิบอยู่ที่ [`_evidence/runtime-2026-09-27.md`](./_evidence/runtime-2026-09-27.md)

สถานะที่ใช้: `VERIFIED` ยืนยันแล้ว · `PARTIAL` ทำงานบางส่วน · `PLANNED` ยังไม่ได้ทำ · `UNKNOWN` ไม่มีหลักฐาน · `DEPRECATED` เลิกใช้

```text
SYSTEM
├── Infrastructure ─ 3 VM: Main (Hetzner), edge-th (KVM VPS), edge-asia (Azure)
├── Edge / CDN     ─ Caddy (TLS) → cdn-edge-node (nginx + ModSecurity CRS + cache) + log forwarder
├── Main WAF       ─ Caddy → waf-nginx (nginx + ModSecurity CRS 3.3.10) → origin / tunnel
├── Backend        ─ FastAPI (waf-dashboard, :8000), ML API (:5000), log analyzer, control-api (:8070)
├── Frontend       ─ React 18 + Vite SPA served by FastAPI
├── Data           ─ ClickHouse (logs), DynamoDB (users/origins/alerts/...), Redis, SQLite
├── Alerting       ─ waf_alerts_v2 + Telegram + Gemini summary
├── ML             ─ Random Forest (ONNX) + Isolation Forest, rule generation, threshold proposals
├── Deception      ─ ModSecurity 418 → nginx @deception → FastAPI synthetic response
└── Origin         ─ FRP tunnel / CloudWAF tunnel / lab containers (DVWA ...)
```

## 1. โครงสร้างพื้นฐาน (Infrastructure)

| Host | Provider / Type | OS | CPU / RAM / Disk | บทบาท | สถานะ |
|---|---|---|---|---|---|
| Main `178.104.53.123` | Hetzner vServer (KVM), eu-central / nbg1-dc3 | Ubuntu 26.04 LTS | 2 vCPU / 3.7 GiB / 38 GB | WAF หลัก, backend, ฐานข้อมูล, tunnel server, control-api | VERIFIED |
| edge-th `45.154.26.91` | KVM VPS (QEMU) — ผู้ให้บริการไม่ระบุใน DMI | Ubuntu 24.04.4 LTS | 1 vCPU / 1.9 GiB / 29 GB | Edge/CDN node (ไทย) | VERIFIED |
| edge-asia `57.158.25.236` | Microsoft Azure VM | Ubuntu 24.04.4 LTS | 1 vCPU / 893 MiB / 29 GB | Edge/CDN node (เอเชีย) | VERIFIED |

- โดเมนหลัก `waf-it-kku.online` — NS ของ Hostinger (`*.dns-parking.com`) **VERIFIED**
- `waf-it-kku.online` → Main (Caddy ของ Main) · `cdn.waf-it-kku.online` → 45.154.26.91 (edge-th) · โดเมนลูกค้า/แล็บชี้ CNAME มาที่ `cdn.waf-it-kku.online` **VERIFIED** (dig)
- GeoDNS (`geodns` container บน Main, พอร์ต 53) มีโค้ดเลือก edge ตามประเทศ + health check แต่ **ไม่ได้เป็น authoritative DNS ของโดเมนในอินเทอร์เน็ต** ตอนตรวจ → **PARTIAL**

## 2. Container และ Service

### Main
| ชื่อ | ชนิด | Image / คำสั่ง | พอร์ต | หน้าที่ | สถานะ |
|---|---|---|---|---|---|
| caddy-ssl-termination | container | caddy:alpine | 80, 443 | TLS termination, reverse proxy ไป dashboard (:8000) และ waf-nginx (:8080), on-demand TLS | VERIFIED |
| waf-nginx | container | owasp/modsecurity-crs:nginx | 8080, 8443 | nginx + ModSecurity + CRS 3.3.10, PL1, anomaly inbound 10, routing ไป origin/tunnel, deception | VERIFIED |
| waf-control-api | container (build `cdn/control-api`) | FastAPI | 8070 (อนุญาตเฉพาะ IP edge) | captcha/OTP challenge, blocklist, rule bundle ให้ edge | VERIFIED |
| waf-clickhouse | container | clickhouse/clickhouse-server:latest | 8123, 9000 (ไม่เปิดสู่ภายนอก) | เก็บ access log / audit log | VERIFIED |
| waf-redis | container | redis:alpine | 6379 (ไม่เปิดสู่ภายนอก) | cache / สถานะ challenge / rate limit | VERIFIED |
| dvwa | container | sagikazarmark/dvwa | ภายใน | เว็บแล็บสำหรับทดสอบ | VERIFIED |
| geodns | container | geodns:latest | 53 tcp/udp, 8053 | GeoDNS (ดูหมายเหตุ) | PARTIAL |
| waf-dashboard | systemd | `.venv/bin/python main.py` | 8000 | FastAPI API + เสิร์ฟ React SPA | VERIFIED |
| waf-ml | systemd | `uvicorn ml_api:app` | 127.0.0.1:5000 | ML inference / rule generation | VERIFIED |
| waf-log-analyzer | systemd | `async_log_analyzer.py` | – | tail log แล้วส่งเข้า ML | VERIFIED |
| cloudwaf-tunnel | systemd | `/opt/cloudwaf-tunnel/server.py` | 8050 (agent), 172.18.0.1:8060 (vhost) | tunnel server ของตัวเอง | VERIFIED |
| frps | systemd | `frps -c /etc/frp/frps.toml` | 7000 (agent), 8085 (vhost ภายใน), 127.0.0.1:7500 | FRP tunnel server | VERIFIED |

### Edge (edge-th และ edge-asia เหมือนกัน)
| ชื่อ | Image | พอร์ต | หน้าที่ | สถานะ |
|---|---|---|---|---|
| cdn-caddy-ssl | caddy:alpine | 80, 443 | TLS on-demand (ถาม Main `:8000/api/domains/check-ssl-allowed`), security headers, redirect HTTP→HTTPS | VERIFIED |
| cdn-edge-node | owasp/modsecurity-crs:nginx | ภายใน 80 | ModSecurity CRS (PL1, threshold 10), rate limit 50 r/s, proxy cache, ส่งต่อไป Main :8080, sync rule ทุก 5 วินาทีจาก control-api | VERIFIED |
| cdn-log-forwarder | python:3.11-slim | – | ส่ง access log ของ edge ไป Main `:8000` เป็น batch | VERIFIED |

## 3. เส้นทางคำขอ (Request path) ที่ยืนยันแล้ว

```text
Client ─DNS─▶ cdn.waf-it-kku.online (edge-th)
  ─HTTPS─▶ cdn-caddy-ssl ─▶ cdn-edge-node (ModSecurity + cache)
  ─HTTP:8080─▶ Main waf-nginx (ModSecurity) ─▶ frp_tunnel_router / cloudwaf_tunnel / dvwa
Dashboard: Client ─HTTPS─▶ Main Caddy ─▶ FastAPI :8000
```

## 4. Backend

| รายการ | ค่า | สถานะ |
|---|---|---|
| Framework | FastAPI (Python 3.14 venv) | VERIFIED |
| Router | 24 `include_router` ใน `main.py`, 123 endpoints ใน `api/*.py` | VERIFIED |
| Auth | JWT HS256 (`services/auth_service.py`), อายุ 60 นาที (ปรับด้วย `JWT_EXPIRE_MINUTES`), รหัสผ่านแบบ Argon2, token จาก header `Authorization: Bearer` หรือ cookie `access_token`, Google OAuth | VERIFIED |
| Role | `admin`, `viewer` (+ สิทธิ์ต่อ origin: owner `admin_user_id`, `viewer_user_ids`, `editor_user_ids`) | VERIFIED |
| Tenant isolation | `services/tenant_service.py::build_tenant_origin_filter` (fail-closed `1=0`), alerts แบ่ง partition ตาม `origin_id` | VERIFIED |

## 5. ข้อมูล (Data stores)

| Store | ใช้ทำอะไร | สถานะ |
|---|---|---|
| ClickHouse `default.access_logs`, `default.security_audit_logs` | log คำขอทุกตัวจาก Main และ edge, audit ของ deception | VERIFIED |
| DynamoDB (AWS) `waf_users`, `waf_origins`, `waf_domains`, `waf_alerts_v2`, `waf_logs`, `waf_rules`, `waf_pending_rules`, `waf_threat_patterns`, `waf_status_history`, `waf_audit_log`, `waf_postmortems`, `waf_ssl_certs` | ผู้ใช้, origin, โดเมน, alert, rule ที่รออนุมัติ ฯลฯ | VERIFIED (จากโค้ด) |
| Redis | challenge/OTP state, cache | VERIFIED |
| SQLite `dashboard/backend/data/*.db` | ip_rules, rate_limits | VERIFIED |

## 6. ความสามารถด้านความปลอดภัย

| ความสามารถ | สถานะ | หมายเหตุ |
|---|---|---|
| WAF (ModSecurity + CRS) ทั้งที่ edge และ Main | VERIFIED | ทดสอบ LFI/SQLi → 403 |
| Custom rule (BLOCK / CHALLENGE / DECEIVE) จาก dashboard | VERIFIED | `services/rule_manager.py` |
| Challenge (captcha / OTP shield) | VERIFIED (โค้ด) | control-api `/cdn-cgi/*`; OTP ทางอีเมลต้องตั้ง SMTP |
| Deception layer | VERIFIED | ทดสอบจริง 2026-09-27 |
| IP access list, rate limit | VERIFIED (โค้ด) | |
| CDN cache | VERIFIED | cache key `$host\|method\|uri+args` บน edge |
| ML anomaly + rule recommendation | PARTIAL | มีโมเดลและ endpoint; รายละเอียดในบทที่ 16 |
| GeoDNS | PARTIAL | ไม่ได้อยู่ในเส้นทาง DNS สาธารณะ |

## 7. ข้อจำกัดที่ทราบ (Known limitations)

- พอร์ต 8000 (backend) เปิดสู่อินเทอร์เน็ต — จำเป็นสำหรับ log forwarder และ Caddy `ask` ของ edge แต่ทำให้เรียก API ตรงได้โดยไม่ผ่าน WAF
- Main บันทึก IP ของ edge แทน IP จริงของผู้ใช้ สำหรับคำขอที่มาทาง edge
- Edge ใส่ `Cache-Control: public` ทับ response ที่ origin ตั้ง `no-store`
- Deception เลือก template SQLi จาก heuristic ของ argument
- Main, ฐานข้อมูล และ backend อยู่บนเครื่องเดียว (single point of failure)
