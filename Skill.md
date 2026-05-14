# 🛡️ Skill.md — WAF Automated + CDN System

> **คู่มือบริบทสำหรับ AI**  
> ไฟล์นี้ช่วยให้ AI เข้าใจโปรเจกต์นี้ได้ทันทีโดยไม่ต้องอธิบายซ้ำทุกครั้ง
---

## 1. โปรเจกต์คืออะไร

ระบบรักษาความปลอดภัยและกระจายโหลด Web Application แบบ production-grade ประกอบด้วย 2 ส่วนหลัก:

| ส่วน | คำอธิบาย |
|------|-----------|
| **WAF (Web Application Firewall)** | ใช้ Nginx + ModSecurity + OWASP CRS กรองและบล็อก traffic อันตราย เช่น SQLi, XSS |
| **CDN (Content Delivery Network)** | Multi-edge node (SG/JP/TH) พร้อม GeoDNS routing, proxy cache, และ Cache Purge API |

Target origin ที่ใช้ทดสอบ: **DVWA** (Damn Vulnerable Web Application)

---

## 2. Tech Stack

| Layer | Technology |
|-------|-----------|
| **WAF/Proxy** | Nginx, ModSecurity v3, OWASP CRS |
| **CDN Edge** | Nginx (proxy_cache), ModSecurity per-node |
| **GeoDNS** | Python (custom DNS server, `dnslib`) |
| **Cache Purge API** | FastAPI (Python) |
| **Dashboard Backend** | FastAPI + Uvicorn (Python) |
| **Dashboard Frontend** | HTML/CSS/JS (static files) |
| **Alert Bot** | Telegram Bot API (Telethon) |
| **Auth** | Google OAuth2 |
| **Infrastructure** | Docker, Docker Compose |
| **Cloud (optional)** | AWS (credentials ใน `.env`) |

---

## 3. Architecture & Request Flow

```
Client Request
     │
     ▼
 GeoDNS (port 5533)         ← routing ตาม source IP / CIDR
     │
     ├──► edge-sg (port 8081)  ← SG node: Nginx + WAF + Cache
     ├──► edge-jp (port 8082)  ← JP node: Nginx + WAF + Cache
     └──► edge-th (port 8086)  ← TH node: Nginx + WAF + Cache
                │
                ▼
         WAF (port 8080)       ← Nginx + ModSecurity (OWASP CRS)
                │
                ▼
          DVWA / Origin        ← target web app
```

### GeoDNS CIDR Mapping
| CIDR | Edge Node |
|------|-----------|
| `172.28.11.0/24` | SG |
| `172.28.22.0/24` | JP |
| `172.28.33.0/24` | TH |
| (fallback) | TH |

### Docker Networks
- `waf_project_waf-net` — network หลักที่ทุก service ใช้ร่วมกัน

---

## 4. โครงสร้าง Directory

```
waf_project/
├── docker-compose.yml          ← รัน WAF + DVWA (origin stack)
├── .env                        ← secrets จริง (อย่าแก้โดยตรง)
├── .env.example                ← template env
│
├── nginx/                      ← Nginx config templates สำหรับ WAF หลัก
│   └── templates/
│       ├── conf.d/default.conf.template
│       ├── modsecurity.d/
│       └── conf/               ← SSL certs (server.key, server.crt)
│
├── modsecurity/
│   └── custom-rules/           ← custom ModSecurity rules
│
├── logs/
│   ├── modsecurity/            ← WAF block logs
│   └── nginx/                  ← Nginx access/error logs
│
├── html/
│   └── 403.html                ← หน้าบล็อก custom
│
├── cdn/                        ← CDN stack แยกต่างหาก
│   ├── docker-compose-cdn.yml  ← รัน CDN edges + geodns + purge-api
│   ├── .env.example
│   ├── edge/
│   │   └── templates/          ← Nginx + ModSecurity templates ต่อ node
│   ├── geodns/
│   │   └── server.py           ← GeoDNS Python server
│   ├── purge-api/
│   │   └── main.py             ← Cache Purge FastAPI service
│   └── scripts/
│       ├── smoke-test-cdn.sh
│       ├── purge-cache.sh
│       └── test-geodns-routing.sh
│
├── dashboard/
│   ├── backend/
│   │   ├── main.py             ← FastAPI app entry point
│   │   ├── requirements.txt
│   │   ├── api/
│   │   │   ├── alerts.py       ← WAF alert endpoints
│   │   │   ├── auth.py         ← Google OAuth2
│   │   │   ├── cdn.py          ← CDN node stats + purge API
│   │   │   └── rules.py        ← WAF rule management
│   │   └── services/           ← business logic layer
│   └── frontend/               ← static HTML/CSS/JS
│
└── scripts/
    ├── cdn_stats.py            ← CDN stats collector
    └── purge-cache.sh          ← purge helper script
```

---

## 5. Service Ports (สรุป)

| Service | Port | คำอธิบาย |
|---------|------|-----------|
| Dashboard / API | `8000` | FastAPI backend + Swagger UI |
| WAF (Nginx+ModSecurity) | `8080` | Reverse proxy หน้า DVWA |
| WAF HTTPS | `8443` | HTTPS endpoint |
| CDN Edge SG | `8081` | Singapore edge node |
| CDN Edge JP | `8082` | Japan edge node |
| CDN Edge TH | `8086` | Thailand edge node |
| Cache Purge API | `8090` | FastAPI purge service |
| GeoDNS | `5533` | DNS (UDP/TCP) |

---

## 6. คำสั่งสำคัญที่ใช้บ่อย

### เริ่มต้น Origin Stack (WAF + DVWA)
```bash
cd /Users/boss/project/waf_project
docker compose up -d
docker compose ps
```

### เริ่มต้น CDN Stack
```bash
cd /Users/boss/project/waf_project/cdn
docker compose -f docker-compose-cdn.yml up -d --build
```

### หยุด CDN Stack
```bash
cd /Users/boss/project/waf_project/cdn
docker compose -f docker-compose-cdn.yml down --remove-orphans
```

### ตรวจสอบ Health
```bash
curl http://localhost:8081/healthz   # SG
curl http://localhost:8082/healthz   # JP
curl http://localhost:8086/healthz   # TH
curl http://localhost:8090/healthz   # Purge API
```

### รัน Dashboard Backend
```bash
cd /Users/boss/project/waf_project/dashboard/backend
source .venv/bin/activate
uvicorn main:app --reload
# หรือ
python3 main.py
```

### ทดสอบ CDN
```bash
cd /Users/boss/project/waf_project/cdn
./scripts/smoke-test-cdn.sh
./scripts/test-geodns-routing.sh
./scripts/purge-cache.sh /dvwa/images/login_logo.png ALL
```

### ดู WAF Logs
```bash
tail -f /Users/boss/project/waf_project/logs/modsecurity/modsec_audit.log
tail -f /Users/boss/project/waf_project/logs/nginx/access.log
```

---

## 7. Environment Variables สำคัญ

| Variable | ใช้ทำอะไร | ค่า default |
|----------|-----------|-------------|
| `CDN_PURGE_TOKEN` | Token สำหรับ Cache Purge API | `cdn-secret-token` |
| `WAF_NETWORK_NAME` | Docker network ที่ CDN เชื่อมกับ origin | `waf_project_waf-net` |
| `TELEGRAM_BOT_TOKEN` | Token สำหรับ WAF alert bot | — |
| `TELEGRAM_CHAT_ID` | Chat ID รับ alert | — |
| `GOOGLE_CLIENT_ID/SECRET` | OAuth2 สำหรับ Dashboard login | — |
| `AWS_ACCESS_KEY_ID/SECRET` | AWS credentials (optional) | — |

---

## 8. Cache Policy (CDN)

| Condition | ผล |
|-----------|-----|
| Request method ไม่ใช่ GET/HEAD | BYPASS |
| มี `Authorization` header | BYPASS |
| มี `PHPSESSID` หรือ `security=` cookie | BYPASS |
| มี `Cache-Control: no-cache/no-store` | BYPASS |
| มี query string ใน URL | BYPASS |
| Static assets (`.jpg`, `.png`, `.css`, `.js`) | Cache 1 ชั่วโมง |
| Dynamic content (default) | Cache 10 นาที |

Debug headers ที่ดูได้: `X-Cache-Status`, `X-Edge-Region`

---

## 9. Dashboard API Endpoints

| Method | Path | คำอธิบาย |
|--------|------|-----------|
| `GET` | `/` | หน้า Dashboard หลัก |
| `GET` | `/cdn.html` | หน้า CDN monitoring |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/api/cdn/nodes` | สถานะ CDN nodes |
| `GET` | `/api/cdn/stats` | CDN stats รวม |
| `GET` | `/api/cdn/stats/{region}` | CDN stats ต่อ region |
| `POST` | `/api/cdn/purge?url=...&region=ALL` | Purge cache |
| `GET` | `/api/alerts` | WAF alerts |
| `GET/POST` | `/api/rules` | จัดการ WAF rules |
| `GET` | `/api/auth/google/...` | Google OAuth2 flow |

---

## 10. Rules & Constraints (อย่าลืม!)

> ⚠️ **ข้อห้ามและข้อควรระวัง**

- **อย่าแก้ไฟล์ `.env` โดยตรง** — ใช้ `.env.example` เป็น template เสมอ
- **Config Nginx จริงอยู่ที่** `nginx/templates/` (WAF) และ `cdn/edge/templates/` (CDN edge)
- **Custom ModSecurity rules อยู่ที่** `modsecurity/custom-rules/`
- **CDN stack แยก compose** กับ origin stack — ต้องรัน origin ก่อน แล้วค่อยรัน CDN
- **Network ต้องตรงกัน** — CDN ต้องเชื่อมกับ `waf_project_waf-net` ไม่งั้น origin จะเข้าไม่ได้
- **Purge token** ต้องเปลี่ยนจาก `cdn-secret-token` ก่อน deploy จริง
- **PARANOIA level** ปัจจุบันตั้งไว้ที่ `1` (ModSecurity) — เพิ่มได้แต่ต้อง test false positive ก่อน
- **ANOMALY_INBOUND/OUTBOUND** ตั้งที่ `10` — ปรับลดได้ถ้าต้องการ strict มากขึ้น
