# 📘 Master Development Plan: WAF & Multi-Tenant CDN Platform

## 1. Overview & System Architecture

ระบบ WAF CDN Platform เป็นระบบ Multi-tenant Web Application Firewall & Content Delivery Network ที่ช่วยให้ผู้ใช้งาน (Users) สามารถนำ Web Origin (เซิร์ฟเวอร์เว็บไซต์ของตนเอง) มาผูกกับระบบ WAF CDN เพื่อรับการปกป้องจากภัยคุกคาม (เช่น SQL Injection, XSS, DDoS) และเพิ่มความเร็วในการโหลดด้วย Multi-Region Caching (SG, JP, TH) พร้อมระบบออก SSL Certificate อัตโนมัติ (Auto-HTTPS)

### 🌊 Full Traffic Flow
```
[ User / Client ] 
       │ (HTTPS Request: https://app.example.com)
       ▼
  [ GeoDNS ] (Port 5533) ──── Resolves Client IP to Nearest Region (SG/JP/TH)
       │
       ▼
 [ CDN Edge Node ] (Nginx + Cache) ──── Checks Cache (Hit/Miss/Bypass)
       │ (Cache Miss)
       ▼
   [ WAF Engine ] (ModSecurity + OWASP CRS) ──── Inspects SQLi / XSS / Rate Limit
       │ (Passed WAF Rules)
       ▼
 [ Nginx Reverse Proxy ] ──── Dynamic Host Routing via origin_ip:port
       │
       ▼
 [ Target Web Origin ] (Customer Server, e.g., DVWA at 192.168.1.50:80)
```

---

## 2. Master Data Model & Database Schemas (DynamoDB)

ระบบใช้ Amazon DynamoDB (หรือ DynamoDB-Local บนพอร์ต 8000/8001) แยกตามตารางต่อไปนี้:

### 2.1 Table: `waf_users`
- **Partition Key (`PK`)**: `user_id` (String UUID)
- **Attributes**:
  - `email` (String, Unique)
  - `name` (String)
  - `password_hash` (String, bcrypt)
  - `role` (String: `admin` | `origin_admin` | `viewer`)
  - `telegram_chat_id` (String, Optional)
  - `created_at` (String ISO8601)

### 2.2 Table: `waf_origins`
- **Partition Key (`PK`)**: `id` (String UUID)
- **Global Secondary Index (`GSI`)**: `admin_user_id-index` (`admin_user_id` as PK)
- **Attributes**:
  - `admin_user_id` (String UUID)
  - `label` (String, e.g. "E-Commerce App")
  - `ip` (String IPv4/v6)
  - `port` (Number, 1-65535)
  - `status` (String: `pending` | `active` | `suspended`)
  - `health_status` (String: `online` | `offline` | `unknown`)
  - `last_health_check` (String ISO8601)
  - `created_at` (String ISO8601)
  - `updated_at` (String ISO8601)

### 2.3 Table: `waf_domains`
- **Partition Key (`PK`)**: `id` (String UUID)
- **Global Secondary Index (`GSI`)**: `origin_id-index` (`origin_id` as PK), `domain_name-index` (`domain_name` as PK)
- **Attributes**:
  - `origin_id` (String UUID)
  - `domain_name` (String, e.g. "shop.example.com")
  - `verification_token` (String, e.g. "waf-token-abc123xyz")
  - `dns_verified` (Boolean, default `false`)
  - `ssl_status` (String: `none` | `pending` | `active` | `failed`)
  - `created_at` (String ISO8601)

### 2.4 Table: `waf_ssl_certs`
- **Partition Key (`PK`)**: `id` (String UUID)
- **Global Secondary Index (`GSI`)**: `domain_id-index` (`domain_id` as PK)
- **Attributes**:
  - `domain_id` (String UUID)
  - `cert_path` (String, path to `fullchain.pem`)
  - `key_path` (String, path to `privkey.pem`)
  - `issuer` (String, e.g. "Let's Encrypt Authority X3")
  - `expires_at` (String ISO8601)
  - `auto_renew` (Boolean, default `true`)
  - `updated_at` (String ISO8601)

### 2.5 Existing Tables: `waf_rules`, `waf_logs`, `waf_alerts`
- `waf_rules`: เก็บ Custom WAF rules (Rule ID, status, content, origin_id)
- `waf_logs`: เก็บ Access Logs และ Attack Logs
- `waf_alerts`: เก็บการแจ้งเตือน Telegram / System Alerts

---

## 3. Comprehensive Master File Structure

```
waf_project/
├── .env.example                       # Shared environment config
├── docker-compose.yml                 # Origin WAF + Local DynamoDB + DVWA
├── Dev-Plan/                          # Full Documentation & Vibe Coding Prompts
│   ├── README.md
│   ├── 00-MASTER-DEV-PLAN.md
│   ├── PHASE-1-ORIGIN-FOUNDATION.md
│   ├── PHASE-2-DOMAIN-DNS.md
│   ├── PHASE-3-SSL-AUTO-HTTPS.md
│   ├── PHASE-4-HEALTH-PER-ORIGIN-WAF.md
│   └── PHASE-5-MULTI-NODE-CDN-INTEGRATION.md
├── cdn/                               # Multi-Region CDN Stack (Phase 5)
│   ├── docker-compose-cdn.yml
│   ├── geodns/
│   ├── edge/
│   ├── purge-api/
│   └── scripts/
└── dashboard/
    ├── backend/                       # FastAPI Backend
    │   ├── main.py                    # App entry point
    │   ├── api/
    │   │   ├── auth.py                # JWT & OAuth
    │   │   ├── origins.py             # Phase 1: Origin CRUD
    │   │   ├── domains.py             # Phase 2: Domain & DNS API
    │   │   ├── ssl.py                 # Phase 3: SSL API
    │   │   ├── rules.py               # Phase 4: WAF Rules API
    │   │   ├── cdn.py                 # Phase 5: CDN API
    │   │   └── alerts.py              # Alerting API
    │   ├── services/
    │   │   ├── dynamodb_service.py    # Tables & Queries
    │   │   ├── rbac.py                # Multi-tenant middleware
    │   │   ├── origin_service.py      # Origin business logic
    │   │   ├── dns_service.py         # DNS resolution & verification
    │   │   ├── ssl_service.py         # Certbot & SSL manager
    │   │   ├── nginx_config_service.py# Jinja2 vhost generator
    │   │   ├── health_check_worker.py # Origin Health Pinger
    │   │   ├── ssl_renew_worker.py    # SSL Expiry & Renew Worker
    │   │   └── rule_manager.py        # ModSecurity Rule Sync
    │   └── templates/
    │       └── nginx/
    │           └── origin.conf.j2     # Dynamic Nginx template
    └── frontend/                      # React 18 + Vite + TailwindCSS
        ├── src/
        │   ├── App.tsx                # Main Router
        │   ├── api/                   # Axios API Clients
        │   ├── components/
        │   │   ├── AddOriginModal.tsx
        │   │   ├── DomainSetupWizard.tsx
        │   │   ├── DnsInstructions.tsx
        │   │   ├── SslStatusCard.tsx
        │   │   ├── ProvisioningStatus.tsx
        │   │   └── HealthBadge.tsx
        │   └── pages/
        │       ├── Origins.tsx        # Origins List
        │       ├── OriginDetail.tsx   # Origin Dashboard
        │       ├── Dashboard.tsx      # Main WAF Dashboard
        │       ├── Rules.tsx          # Rules Management
        │       ├── Alerts.tsx         # Alerts Page
        │       └── CDN.tsx            # CDN Nodes & Purge UI
```

---

## 4. Execution Phases Summary

1. **Phase 1: Multi-tenant & Origin Management** — สร้างตาราง DynamoDB, Middleware เช็คสิทธิ์ ownership, Backend CRUD API `/api/origins` และ UI สำหรับเพิ่ม/จัดการ Origins
2. **Phase 2: Domain Setup & DNS Verification** — ระบบผูก Domain กับ Origin, สุ่มสร้าง Verification Token, รัน `dnspython` เช็ค CNAME/TXT และ Wizard UI แสดงขั้นตอนตั้งค่า DNS
3. **Phase 3: Auto-HTTPS & Nginx Config Gen** — Certbot ACME Client สำหรับออก SSL จาก Let's Encrypt, Jinja2 Template สร้าง Nginx Server Block ราย Origin พร้อม Auto-Renew Cron
4. **Phase 4: Origin Health & Per-Origin WAF** — Background Worker ตรวจสอบสถานะ Origin IP ทุก 60 วินาที, แจ้งเตือน Telegram เมื่อ Origin ล่ม, แยก ModSecurity Rule ราย Origin
5. **Phase 5: Multi-Region CDN & GeoDNS Integration** — สตาร์ท CDN Edge Nodes 3 Region (SG/JP/TH), GeoDNS Auto-routing, Distributed Cache Purge API และ Script ทดสอบระบบทั้งตัว
