---
title: "บทที่ 03 — เทคโนโลยีที่ใช้"
chapter: 3
part: "Part I — Introduction"
status: VERIFIED
---

# บทที่ 03 — เทคโนโลยีที่ใช้ (Technology Stack)

เวอร์ชันในตารางอ่านจากไฟล์ `package.json` / `requirements.txt` หรือจากคำสั่งบนเครื่องจริง (ระบุในช่องแหล่งที่มา)

| หมวด | เทคโนโลยี | เวอร์ชัน | แหล่งที่มา | สถานะ |
|---|---|---|---|---|
| Frontend | React | ^18.3.1 | `package.json` | VERIFIED |
| Frontend | TypeScript, Vite | ^5.6.3, ^5.4.11 | `package.json` | VERIFIED |
| Frontend | Tailwind CSS | ^3.4.16 | `package.json` | VERIFIED |
| Frontend | React Router, TanStack Query, Zustand, Recharts, Axios, lucide-react | 6.28 / 5.62 / 4.5 / 2.14 / 1.7 / 0.468 | `package.json` | VERIFIED |
| Backend | Python + FastAPI + Uvicorn | Python 3.14 (venv), FastAPI 0.104.1, Uvicorn 0.24.0 | `requirements.txt`, runtime | VERIFIED |
| Backend | python-jose (JWT), argon2-cffi, slowapi, httpx, boto3, clickhouse-connect, redis, maxminddb, telethon | ตาม `requirements.txt` | `requirements.txt` | VERIFIED |
| Reverse proxy / TLS | Caddy | v2.11.4 | `caddy version` บน Main | VERIFIED |
| Reverse proxy | nginx | 1.30.4 | `nginx -v` ใน waf-nginx | VERIFIED |
| WAF | ModSecurity v3 (libmodsecurity 3.0.16) + ModSecurity-nginx 1.0.4 | – | log ของ edge ตอน reload | VERIFIED |
| WAF rules | OWASP Core Rule Set | 3.3.10 | ModSecurity audit (`OWASP_CRS/3.3.10`) | VERIFIED |
| Container image | owasp/modsecurity-crs:nginx | tag `nginx` | `docker ps` | VERIFIED |
| Log / analytics DB | ClickHouse | 26.7.3 (image `latest`) | client banner | VERIFIED |
| Application DB | AWS DynamoDB | – (managed) | `services/dynamodb_service.py` | VERIFIED |
| Cache / state | Redis | 8.10.0 | `redis-server --version` | VERIFIED |
| Local DB | SQLite | – | `dashboard/backend/data/*.db` | VERIFIED |
| ML | scikit-learn (Random Forest, Isolation Forest), ONNX Runtime, pandas | ตาม `ml/requirements-gen3.txt` | `ml/ml_api.py`, `ml/models/` | VERIFIED |
| AI summary | Google Gemini (`gemini-flash-lite-latest`) | – | `services/gemini_service.py` | VERIFIED |
| Notification | Telegram Bot API | – | `services/telegram_listener.py` | VERIFIED |
| Tunnel | frp (frps) | 0.61.1 | `frps -v` | VERIFIED |
| Tunnel | CloudWAF tunnel (Python, ของโครงการ) | – | `/opt/cloudwaf-tunnel/server.py` | VERIFIED |
| GeoIP | DB-IP Lite Country (.mmdb) | อัปเดตรายเดือน | `/etc/cron.d/waf-geoip` | VERIFIED |
| Containerization | Docker / Docker Compose | 29.1.3 / 2.40.3 (Main) | `docker version` | VERIFIED |
| Cloud | Hetzner Cloud (Main), Azure (edge-asia), KVM VPS (edge-th), AWS (DynamoDB) | – | DMI / metadata / โค้ด | VERIFIED |
| DNS | Hostinger DNS (authoritative), GeoDNS container (ไม่ได้ใช้เป็น authoritative) | – | `dig NS` | VERIFIED / PARTIAL |
| Monitoring | health endpoint (`/healthz`, `/api/health`), status page, ไม่มีระบบ monitoring ภายนอกที่ตรวจพบ | – | runtime | PARTIAL |

## แหล่งอ้างอิง (Evidence)
- `dashboard/frontend/package.json`, `dashboard/backend/requirements.txt`, `ml/requirements-gen3.txt`
- คำสั่งบน Main: `docker exec waf-nginx nginx -v`, `docker exec waf-redis redis-server --version`, `caddy version`, `frps -v`
