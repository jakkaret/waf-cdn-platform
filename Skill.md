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
| **Dashboard Frontend** | **React 18 + Vite** (TypeScript), TailwindCSS, React Router v6 |
| **State Management** | Zustand (global) + React Query (server state / data fetching) |
| **Charts** | Recharts |
| **Alert Bot** | Telegram Bot API (Telethon) |
| **Auth** | Google OAuth2 + JWT |
| **Infrastructure** | Docker, Docker Compose |
| **Cloud (optional)** | AWS DynamoDB, S3 |

### Frontend Stack รายละเอียด (React + Vite)

| Package | Version | ใช้ทำอะไร |
|---------|---------|-----------|
| `react` + `react-dom` | ^18.x | UI framework หลัก |
| `vite` | ^5.x | Build tool + Dev server (HMR) |
| `typescript` | ^5.x | Type safety |
| `react-router-dom` | ^6.x | Client-side routing |
| `tailwindcss` | ^3.x | Utility-first CSS |
| `@tanstack/react-query` | ^5.x | Server state, caching, polling |
| `zustand` | ^4.x | Global UI state (sidebar, auth) |
| `recharts` | ^2.x | Dashboard charts (Bar, Doughnut, Line) |
| `axios` | ^1.x | HTTP client พร้อม interceptor |
| `lucide-react` | latest | Icon library |

#### โครงสร้าง Frontend (React + Vite)
```
dashboard/frontend/
├── index.html
├── vite.config.ts          ← proxy /api → localhost:8000
├── tailwind.config.ts
├── src/
│   ├── main.tsx            ← entry point
│   ├── App.tsx             ← Router + Layout wrapper
│   ├── api/
│   │   ├── axios.ts        ← axios instance + auth interceptor
│   │   ├── logs.ts
│   │   ├── rules.ts
│   │   ├── alerts.ts
│   │   └── cdn.ts
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx
│   │   │   └── TopBar.tsx
│   │   └── ui/             ← reusable: Card, Badge, Modal, Table
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── Logs.tsx
│   │   ├── Rules.tsx
│   │   ├── Alerts.tsx
│   │   ├── CDN.tsx
│   │   └── UserRoles.tsx
│   ├── store/
│   │   └── authStore.ts    ← Zustand: token, user, role
│   └── types/
│       └── index.ts        ← shared TypeScript types
```

#### Vite Proxy Config (ตัวอย่าง)
```ts
// vite.config.ts
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
```

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
├── docker-compose.yml
├── .env
├── .env.example
│
├── nginx/
│   └── templates/
│       ├── conf.d/default.conf.template
│       ├── modsecurity.d/
│       └── conf/               ← SSL certs
│
├── modsecurity/
│   └── custom-rules/
│
├── logs/
│   ├── modsecurity/
│   └── nginx/
│
├── html/
│   └── 403.html
│
├── cdn/
│   ├── docker-compose-cdn.yml
│   ├── .env.example
│   ├── edge/
│   │   └── templates/
│   ├── geodns/
│   │   └── server.py
│   ├── purge-api/
│   │   └── main.py
│   └── scripts/
│
├── dashboard/
│   ├── backend/
│   │   ├── main.py
│   │   ├── requirements.txt
│   │   ├── api/
│   │   │   ├── alerts.py
│   │   │   ├── auth.py
│   │   │   ├── cdn.py
│   │   │   └── rules.py
│   │   └── services/
│   └── frontend/               ← React + Vite project root
│       ├── index.html
│       ├── vite.config.ts
│       ├── package.json
│       ├── tailwind.config.ts
│       └── src/
│           ├── main.tsx
│           ├── App.tsx
│           ├── api/
│           ├── components/
│           ├── pages/
│           ├── store/
│           └── types/
│
└── scripts/
    ├── cdn_stats.py
    └── purge-cache.sh
```

---

## 5. Service Ports (สรุป)

| Service | Port | คำอธิบาย |
|---------|------|-----------|
| Dashboard / API | `8000` | FastAPI backend + Swagger UI |
| **Dashboard Frontend (Dev)** | **`5173`** | Vite dev server (React HMR) |
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

### รัน Dashboard Backend
```bash
cd /Users/boss/project/waf_project/dashboard/backend
source .venv/bin/activate
uvicorn main:app --reload
```

### รัน Dashboard Frontend (React + Vite)
```bash
cd /Users/boss/project/waf_project/dashboard/frontend
npm install          # ครั้งแรก
npm run dev          # dev server port 5173
npm run build        # build to dist/
npm run preview      # preview production build
```

### ตรวจสอบ Health
```bash
curl http://localhost:8081/healthz   # SG
curl http://localhost:8082/healthz   # JP
curl http://localhost:8086/healthz   # TH
curl http://localhost:8090/healthz   # Purge API
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
| `VITE_API_BASE_URL` | Base URL สำหรับ React frontend (production) | `http://localhost:8000` |

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
| `GET` | `/` | serve React app (production) |
| `GET` | `/docs` | Swagger UI |
| `GET` | `/api/cdn/nodes` | สถานะ CDN nodes |
| `GET` | `/api/cdn/stats` | CDN stats รวม |
| `GET` | `/api/cdn/stats/{region}` | CDN stats ต่อ region |
| `POST` | `/api/cdn/purge?url=...&region=ALL` | Purge cache |
| `GET` | `/api/alerts/recent` | WAF alerts |
| `GET/POST` | `/api/rules/` | จัดการ WAF rules |
| `PUT/DELETE` | `/api/rules/{rule_id}` | แก้ไข/ลบ rule |
| `GET` | `/api/auth/me` | ข้อมูล user ปัจจุบัน |
| `GET` | `/api/auth/google/...` | Google OAuth2 flow |
| `GET` | `/api/logs/recent?limit=N` | WAF logs ล่าสุด |

---

## 10. Rules & Constraints (อย่าลืม!)

> ⚠️ **ข้อห้ามและข้อควรระวัง**

- **อย่าแก้ไฟล์ `.env` โดยตรง** — ใช้ `.env.example` เป็น template เสมอ
- **Config Nginx จริงอยู่ที่** `nginx/templates/` (WAF) และ `cdn/edge/templates/` (CDN edge)
- **Custom ModSecurity rules อยู่ที่** `modsecurity/custom-rules/`
- **CDN stack แยก compose** กับ origin stack — ต้องรัน origin ก่อน แล้วค่อยรัน CDN
- **Network ต้องตรงกัน** — CDN ต้องเชื่อมกับ `waf_project_waf-net`
- **Purge token** ต้องเปลี่ยนจาก `cdn-secret-token` ก่อน deploy จริง
- **PARANOIA level** ปัจจุบันตั้งไว้ที่ `1` — เพิ่มได้แต่ต้อง test false positive ก่อน
- **ANOMALY_INBOUND/OUTBOUND** ตั้งที่ `10`
- **Frontend dev port คือ `5173`** (Vite) ไม่ใช่ `8000` — Vite proxy /api ไปยัง FastAPI โดยอัตโนมัติ
- **React build output** อยู่ที่ `dashboard/frontend/dist/` — FastAPI serve ด้วย `StaticFiles`

---

## 11. Development Phases (แผนงาน 5 ระยะ)

### PHASE 1 — Core CDN ✅ (เสร็จแล้ว)

> เป้าหมาย: สร้าง CDN infrastructure พื้นฐานให้ทำงานได้จริง

| งาน | สถานะ | รายละเอียด |
|-----|-------|-----------|
| **Multi Node (Edge Servers)** | ✅ | สร้าง edge node SG/JP/TH ด้วย Docker Compose แต่ละ node รัน Nginx + ModSecurity แยกกัน รับ traffic บน port 8081/8082/8086 |
| **Reverse Proxy + Origin Separation** | ✅ | แต่ละ edge node ทำหน้าที่ reverse proxy ไปยัง origin (WAF port 8080) โดยผ่าน Docker network `waf_project_waf-net` |
| **Cache System (หัวใจ CDN)** | ✅ | ใช้ `proxy_cache` ของ Nginx เป็น cache layer หลัก กำหนด cache zone แยกต่อ node |
| **Cache Policy** | ✅ | กำหนด rule ว่า request ไหน cache ได้ เช่น bypass ถ้ามี query string, cookie session, หรือ Authorization header |
| **Cache Hit/Miss** | ✅ | เพิ่ม response header `X-Cache-Status` (HIT/MISS/BYPASS) และ `X-Edge-Region` เพื่อ debug ได้ง่าย |
| **Cache Purge (Invalidate)** | ✅ | FastAPI service บน port 8090 รับ `POST /purge?url=...&region=ALL` พร้อม Bearer token เพื่อส่ง purge command ไปยังทุก edge node |

---

### PHASE 2 — CDN Behavior 🔄 (กำลังทำ)

> เป้าหมาย: เพิ่ม behavior ขั้นสูงให้ CDN ทำงานได้ intelligent มากขึ้น

| งาน | สถานะ | รายละเอียด |
|-----|-------|-----------|
| **Geo Routing** | ✅ | Python DNS server (`dnslib`) บน port 5533 รับ DNS query แล้ว map CIDR ของ client IP ไปยัง edge node ที่เหมาะสม (SG/JP/TH) |
| **Rate Limiting per Edge** | ⬜ TODO | กำหนด `limit_req_zone` และ `limit_req` ใน Nginx config ของแต่ละ edge node สามารถตั้ง RPS และ burst ต่าง node ได้ |
| **TLS / HTTPS (Edge SSL)** | ⬜ TODO | ทุก edge node รองรับ HTTPS ด้วย self-signed cert (สำหรับ dev) และ TLSv1.2/1.3 ใช้ config เดียวกับ WAF หลัก |
| **Static vs Dynamic Routing** | ⬜ TODO | แยก location block ใน Nginx: static assets (`.jpg`, `.css`, `.js`) ไปเส้น cache นาน, dynamic content cache สั้นหรือ bypass |

---

### PHASE 3 — Reliability ⬜ (ยังไม่เริ่ม)

> เป้าหมาย: ทำให้ระบบ CDN ทนต่อความล้มเหลว (fault tolerant)

| งาน | สถานะ | รายละเอียด |
|-----|-------|-----------|
| **Health Check** | ⬜ TODO | เพิ่ม `/healthz` endpoint ทุก edge node + Purge API — ใช้สำหรับ load balancer และ monitoring ตรวจสอบว่า node ยังทำงานอยู่ |
| **Failover** | ⬜ TODO | กำหนด fallback logic ใน GeoDNS: ถ้า node ที่ routing ไปไม่ตอบสนอง ให้ redirect ไปยัง node สำรอง เช่น SG → TH |

---

### PHASE 4 — Monitoring & Logging ⬜ (ยังไม่เริ่ม)

> เป้าหมาย: ให้ทีมมองเห็น traffic และ performance ของ CDN ได้แบบ real-time

| งาน | สถานะ | รายละเอียด |
|-----|-------|-----------|
| **Central Log** | ⬜ TODO | รวบรวม access log และ WAF log จากทุก edge node ส่งมายังที่เดียว (DynamoDB หรือ log aggregator) เพื่อให้ Dashboard query ได้ |
| **Metrics Dashboard** | ⬜ TODO | หน้า CDN ใน React Dashboard แสดง: สถานะแต่ละ node, cache hit ratio, request count per region, top blocked IPs — ดึงข้อมูลผ่าน `/api/cdn/stats` |
| **Latency Tracking** | ⬜ TODO | วัด response time ของแต่ละ edge node บันทึก `request_time` จาก Nginx log และแสดงเป็น chart ใน Dashboard |

---

### PHASE 5 — Security Integration ⬜ (ยังไม่เริ่ม)

> เป้าหมาย: ผสาน WAF security เข้ากับทุก edge node ของ CDN

| งาน | สถานะ | รายละเอียด |
|-----|-------|-----------|
| **เชื่อม WAF ทุก Edge** | ⬜ TODO | ติดตั้ง ModSecurity + OWASP CRS บนทุก CDN edge node (ปัจจุบัน WAF อยู่แค่ origin) เพื่อให้ block attack ได้ตั้งแต่ edge ก่อนถึง origin |
| **Rule Sync** | ⬜ TODO | Custom ModSecurity rules ที่สร้างผ่าน Dashboard ต้องถูก sync ไปยังทุก edge node อัตโนมัติ เช่น ผ่าน shared volume หรือ API push |
| **Global Block** | ⬜ TODO | เพิ่มฟีเจอร์ block IP / CIDR แบบ global ผ่าน Dashboard ครั้งเดียวแต่มีผลกับทุก edge node พร้อมกัน |

---

## 12. สรุปสถานะโดยรวม

| Phase | ชื่อ | สถานะ |
|-------|------|-------|
| Phase 1 | Core CDN | ✅ เสร็จ |
| Phase 2 | CDN Behavior | 🔄 กำลังทำ |
| Phase 3 | Reliability | ⬜ ยังไม่เริ่ม |
| Phase 4 | Monitoring & Logging | ⬜ ยังไม่เริ่ม |
| Phase 5 | Security Integration | ⬜ ยังไม่เริ่ม |