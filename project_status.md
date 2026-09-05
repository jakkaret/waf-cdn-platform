# 🛡️ WAF + CDN Platform — สถานะโปรเจคปัจจุบัน

> อัปเดตล่าสุด: 31 กรกฎาคม 2026 (เสร็จสิ้นการอัปเกรดระบบ Archive & Restore)

---

## 📊 ภาพรวมความคืบหน้า (Progress Overview)

| Phase | หัวข้อ | สถานะ | ความสมบูรณ์ |
|:------|:--------|:------:|:-----------:|
| **Phase 1** | Core Platform | ✅ เสร็จสมบูรณ์ | 100% |
| **Phase 2** | Zero-Trust Network | ✅ โครงสร้างพร้อมทดสอบ | 85% |
| **Phase 3** | Domain & SSL Automation | ✅ เสร็จสมบูรณ์ | 100% |
| **Phase 4** | Analytics & Advanced Protection | ✅ เสร็จสมบูรณ์ | 100% |
| **Phase 5** | QA & Production Readiness | ✅ มี E2E Tests + CI/CD | 95% |

---

## ✅ ฟีเจอร์ที่พัฒนาเพิ่มเติมล่าสุด

### 1. WAF Config Sync System (Phase 1)
- **Script Sync อัตโนมัติ:** สร้าง `scripts/sync_waf_rules.py` ดึงกฎ WAF จาก API แปลงเป็น ModSecurity Rules format อัปโหลดไปยัง CDN Edge SG/JP/TH และสั่ง reload Nginx อัตโนมัติ
- **API Endpoint:** เพิ่ม `POST /api/rules/sync` เพื่อใช้รันสคริปต์นี้จากฝั่ง Dashboard API
- **UI Management:** เพิ่มปุ่ม **"🔄 Sync to Edge Nodes"** ในหน้า Custom Rules บน Dashboard เพื่อให้ Admin อัปเดตข้อมูลไปยังโหนดปลายทางแบบ Real-time

### 2. Quota Management System (Phase 1)
- **ขีดจำกัดยืดหยุ่น:** ปรับปรุง backend ให้รองรับการจำกัดโควตา (Default คือ 5 Origins ต่อบัญชี และ 10 Domains ต่อ Origin) ตั้งค่าผ่าน env vars ได้
- **API Endpoint:** เพิ่ม `GET /api/origins/quota` สำหรับอ่านข้อมูลการใช้งานเทียบกับโควตา
- **UI Progress Bar:** เพิ่มแถบแสดงสถานะโควตา (เขียว/เหลือง/แดง) ในหน้า Origins พร้อมทั้งบล็อกปุ่ม Add Origin และขึ้นคำเตือนเมื่อโควตาเต็ม

### 3. DNS & SSL UI Improvements (Phase 3)
- **ปรับปรุงปุ่ม Verify DNS:** ปรับให้เรียกใช้ API สำหรับ verify domain และอัปเดตสถานะแบบ Real-time พร้อมแสดงข้อความเตือน/สำเร็จแทนการเปิด wizard ซ้ำ
- **SSL Certificates Status Tab:** นำข้อมูลใบรับรองความปลอดภัยที่ออกโดย Let's Encrypt / ZeroSSL มาแสดงผลจริงในหน้าโฮสต์ (แสดงสถานะ 🔒 Active, วันหมดอายุ, และ Issuer) แทนการใช้ placeholder

### 4. ClickHouse Country Log Ingest (Phase 4)
- **Ingestion Pipeline:** อัปเดต `cdn_log_forward.py` ให้ดึงข้อมูลภูมิภาคของ Edge Node และบันทึกฟิลด์ `country` ลง ClickHouse ทำให้ข้อมูลทราฟฟิกแยกแยะรายประเทศได้สมบูรณ์และถูกต้อง

### 5. Playwright E2E Tests & CI/CD Pipeline (Phase 5)
- **Playwright Test Suite:** เพิ่มการทดสอบ UI ครบวงจร (`playwright.config.ts` และ `e2e.spec.ts`) ครอบคลุมการทำงานของระบบ Auth, Origins, WAF Rules, และ Dashboard Pages
- **GitHub Actions CI/CD:** เพิ่ม `.github/workflows/ci.yml` รันอัตโนมัติเมื่อมีการ push/PR ประกอบด้วย 5 jobs:
  1. Python Backend Linting (Ruff)
  2. Frontend Type Checking (tsc)
  3. Frontend Production Build
  4. Backend Testing (Pytest + LocalStack DynamoDB mock)
  5. E2E Browser Testing (Playwright)

### 6. Archive & Restore / Cancel Setup System (Phase 1)
- **ระบบ Archive & Restore:** เปลี่ยนระบบการลบ Origin จากเดิม Hard Delete เป็น Soft Delete โดยเปลี่ยนสถานะเป็น `'archived'` ใน DynamoDB เพื่อรักษาสถิติการทำงานและประวัติทราฟฟิก
- **Cancel Setup สำหรับ Pending:** เพิ่มตรรกะตรวจเช็คความเหมาะสมของหน้าจอ หากเซิร์ฟเวอร์มีสถานะเป็น `'pending'` (ยังตั้งค่าไม่เสร็จ) จะเปลี่ยนปุ่มเป็น **"Cancel Setup" (รูปไอคอน X)** แทนปุ่มจัดเก็บปกติ
- **แถบเมนูคัดกรองใหม่:** เพิ่มตัวกรองบนหน้า UI ให้ผู้ใช้สามารถเลือกดูเครื่องที่อยู่ในกลุ่ม **"Archived"** และกดกู้คืน (**"Restore"** ด้วยปุ่มลูกศรหมุนกลับสีเขียว) ให้กลับมาทำงานเป็นเครื่อง Active ได้ทันที
- **อัปเดตระบบโควตา:** ปรับปรุงตรรกะการตรวจสอบโควตาระดับ API และ UI เพื่อไม่ให้นับรวมเซิร์ฟเวอร์ที่อยู่ใน Archive เพื่อให้การจำกัดโควตาทำงานได้อย่างสอดคล้องกับการใช้งานจริง

---

## 🏗️ สถานะ Infrastructure ปัจจุบัน

### Docker Services (docker-compose.yml)
| Service | Container | Port | สถานะ |
|:--------|:----------|:----:|:------|
| WAF Engine | `waf-nginx` | 8080 | ✅ พร้อมใช้ |
| DVWA Target | `dvwa` | (internal) | ✅ พร้อมใช้ |
| Caddy SSL | `caddy-ssl-termination` | 80, 443 | ✅ พร้อมใช้ |
| Redis | `waf-redis` | 6379 | ✅ พร้อมใช้ |
| ClickHouse | `waf-clickhouse` | 8123, 9000 | ✅ พร้อมใช้ |

> [!NOTE]
> CDN Stack (SG/JP/TH edge nodes) อยู่ใน `cdn/docker-compose-cdn.yml` แยกต่างหาก — ต้องรันด้วย `run_cdn_stack.sh`

### Backend API (FastAPI — port 8000)
| Router | Prefix | สถานะ |
|:-------|:-------|:------|
| Auth | `/api/auth` | ✅ |
| Rules | `/api/rules` | ✅ |
| Alerts | `/api/alerts` | ✅ |
| CDN | `/api/cdn` | ✅ |
| Origins | `/api/origins` | ✅ |
| Domains | `/api/domains` | ✅ |
| Rate Limiter | `/api/limiter` | ✅ |
| Analytics | `/api/analytics` | ✅ |

### Frontend (React + Vite + TailwindCSS)
Pages ที่มีอยู่: `Dashboard`, `CDN`, `Alerts`, `Logs`, `Origins`, `OriginDetail`, `Rules`, `Login`, `Register`, `Users`

---

## ❌ สิ่งที่ยังเหลืออยู่ (Future Improvements)
1. **Envoy xDS Control Plane (Phase 2):** ตัวรับส่ง Dynamic Config ไปยัง Envoy สำหรับ Proxy (ปัจจุบันทดแทนด้วย Caddy on-demand และ nginx reload)
2. **Redis Shared Rate Limiter (Phase 4):** การใช้ Lua script บน Redis ร่วมกันเพื่อลดทราฟฟิกระดับ Global (ปัจจุบันเป็น per-node rate limiting)
3. **Database Migration (Phase 1):** ย้ายจาก DynamoDB ไปยัง PostgreSQL เพื่อความสมบูรณ์ในการทำ Multi-tenant RLS (Supabase)

---

## 📁 โครงสร้างไฟล์สำคัญ

```
waf_project/
├── docker-compose.yml          ← Core WAF stack (Nginx+Caddy+Redis+ClickHouse)
├── cdn/
│   ├── docker-compose-cdn.yml  ← CDN Edge stack (SG/JP/TH nodes)
│   ├── control-api/            ← CDN Control API (port 8070)
│   ├── stats/                  ← CDN Stats Service (port 9090)
│   └── scripts/
│       ├── test_routing.py     ← CDN routing tests (exit 1 on fail ✅)
│       ├── test_tls_edge.py    ← TLS edge tests (exit 1 on fail ✅)
│       └── test_failover.py    ← Failover tests (exit 1 on fail ✅)
├── dashboard/
│   ├── backend/
│   │   ├── main.py             ← FastAPI app (port 8000)
│   │   ├── api/
│   │   │   ├── cdn.py          ← CDN stats + nodes API ✅
│   │   │   ├── domains.py      ← Domain + DNS verification API ✅
│   │   │   └── analytics.py    ← ClickHouse analytics + AI summary ✅
│   │   └── services/
│   │       ├── waf_tunnel_server.py ← Zero-Trust tunnel server ✅
│   │       ├── clickhouse_service.py ← ClickHouse connector ✅
│   │       └── dns_verification_worker.py ← Background DNS checker ✅
│   └── frontend/src/pages/     ← React pages (10 หน้า)
├── scripts/
│   ├── test_runner_gui.py      ← GUI Test Runner (14 tests, Thai UI) ✅
│   ├── sync_waf_rules.py       ← WAF sync script (Dashboard -> Nodes) ✅
│   ├── waf_tunnel_agent.py     ← Tunnel agent script ✅
│   └── waf_tunnel_server.py    ← Tunnel server script ✅
└── dev_readme.md               ← รวมคำสั่งรันระบบและวิธีใช้สำหรับ Developer 🆕
```
