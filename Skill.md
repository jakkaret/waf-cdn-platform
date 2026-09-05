---
name: WAF & CDN Platform Architecture
description: Architecture overview, tech stack, and structural map of the WAF & CDN Project
---

# 🏗️ Skill.md — Architecture & Tech Stack

> **วัตถุประสงค์:** เอกสารนี้คือคู่มือโครงสร้างและสถาปัตยกรรมระบบ (Architecture) สำหรับใช้เป็นแนวทางอ้างอิงของ AI เพื่อความเข้าใจภาพรวมของโปรเจกต์อย่างถูกต้อง

## 1. System Overview

โปรเจกต์นี้คือ **WAF + CDN management dashboard** ที่ออกแบบมาเพื่อควบคุม Web Application Firewall (ModSecurity), จัดการ Edge nodes, จัดทำ Access Controls, และทำ ML-assisted threat detection จากส่วนกลางแบบ Zero-Trust

## 2. Tech Stack

### 🎨 Frontend (Dashboard)
- **Framework:** React 18, Vite, TypeScript
- **State Management:** Zustand (Auth/Global), TanStack Query (Server state / Polling)
- **Routing:** React Router (พร้อม Protected / Admin Routes)
- **Styling:** TailwindCSS (Custom Design System, Dark Theme, CSS Variables)
- **Components/UI:** Radix UI, Lucide-react (Icons), Recharts (Charts), React-hot-toast

### ⚙️ Backend (Control API)
- **Framework:** FastAPI (Python), Uvicorn
- **Auth:** python-jose, argon2-cffi
- **Rate Limiting:** slowapi, Redis client
- **Background Tasks:** Celery / Asyncio Workers

### 🏢 Infrastructure (Core Stack & Edge)
- **WAF Engine:** Nginx + OWASP ModSecurity CRS 4.0
- **SSL Termination:** Caddy (Auto-HTTPS / Let's Encrypt)
- **Database (Logs & Analytics):** ClickHouse (Columnar, Time-series)
- **Database (Auth / Config):** AWS DynamoDB (LocalMock) -> มีแผนย้ายไป PostgreSQL (Supabase)
- **Caching & Rate Limiting:** Redis
- **Testing Target:** DVWA (Damn Vulnerable Web Application)

### 🤖 Machine Learning
- **Models:** Random Forest + Isolation Forest (Hybrid approach)
- **Use Case:** Payload simulation, anomaly scoring, and automated SecRule suggestions.

## 3. High-level Architecture

ระบบถูกออกแบบเป็นหลายเลเยอร์ดังนี้:
1.  **Frontend Layer:** ผู้ใช้ (Admin/Viewer) จะจัดการระบบทั้งหมดผ่าน React Dashboard
2.  **API Control Plane:** FastAPI รับส่งคำสั่งไปจัดการข้อมูล Configuration, Auth, ML Rules, Alerts
3.  **Core Data Services:** ClickHouse (สำหรับมอนิเตอร์ Logs หลักแสนรายการแบบเรียลไทม์), Redis (จำกัด Rate limits), DynamoDB (เก็บ Origin/Domains/Users)
4.  **Edge Delivery (CDN Stack):** โหนดกระจายสัญญาณ SG, JP, TH ที่ทำงานด้วย Nginx พร้อมรับคำสั่ง Sync WAF Rules (`scripts/sync_waf_rules.py`) อัตโนมัติ 
5.  **Zero-Trust Ingress:** Caddy รับ HTTPS traffic ก่อนส่งเข้า Nginx WAF หากผู้ใช้ใช้ Zero-Trust จะมี WAF Tunnel Agent เชื่อมต่อระหว่าง Origin ในบ้าน กับ Tunnel Server ที่ระบบ
6.  **Alerts System:** Forward การโจมตีร้ายแรงเข้าหา Telegram Bot ให้ผู้ใช้โดยตรง

## 4. Key Workflows & Scripts

*   **WAF Sync (`scripts/sync_waf_rules.py`):** โค้ดดึงข้อมูล WAF rules จาก FastAPI มาเขียนเป็น `.conf` และ Reload Nginx ข้ามเซิร์ฟเวอร์
*   **CDN Forwarder (`services/cdn_log_forward.py`):** ตัวอ่าน log ของ CDN Edge และเสริมข้อมูลภูมิภาค (Country) ส่งเข้า ClickHouse
*   **DNS Worker (`services/dns_verification_worker.py`):** รัน background เช็ค CNAME/TXT ของ Domain เพื่อเปิดระบบ Proxy
*   **Playwright E2E (`dashboard/frontend/e2e.spec.ts`):** ทดสอบ User Flows (Login, Create Origin, Quota limit) อัตโนมัติใน CI/CD

## 5. Security & Permission Principles

- **Tenant Isolation:** ข้อมูล Logs และ Domains ต้องคัดกรองตามเจ้าของ User เสมอ
- **Role-based (Admin/Viewer):** ฟีเจอร์ที่อันตราย (Delete, Purge, Add Rule, Block IP, Change User Role) สงวนไว้ให้ `admin` เท่านั้น
- **Soft Delete:** การลบเซิร์ฟเวอร์ (Origin) จะทำผ่านระบบ Archive (`status: archived`) เพื่อให้ประวัติ Log คงอยู่และกด Restore ได้
