# 🛡️ WAF + CDN Platform — Implementation Plan (งานที่เหลือ)

> เรียงตาม Priority: ทำได้เลย → เกือบเสร็จ → ต้องออกแบบใหม่

---

## กลุ่มที่ 1 — Frontend UI ที่รอ API อยู่แล้ว

### Step 1: WAF Config Tab ใน OriginDetail
**ไฟล์:** `dashboard/frontend/src/pages/OriginDetail.tsx` (L247)  
**เวลา:** ~2 ชม.

**สิ่งที่ต้องทำ:**
- ตอนนี้แสดงแค่ `"Available in Phase 4"` placeholder
- API `/api/rules/` มีครบแล้ว (GET/POST/PUT/DELETE)
- เพิ่ม UI แสดง WAF rules ที่ใช้งานอยู่ + ปุ่ม Add/Delete rule

**ขั้นตอนโค้ด:**
1. ดึง rules ด้วย `useQuery` จาก `/api/rules/`
2. แสดง table: ID | Variable | Operator | Severity | Message | Actions
3. ปุ่ม "+ Add Rule" เปิด inline form (หรือ modal เล็กๆ)
4. ปุ่ม Delete ต่อ row — เรียก DELETE `/api/rules/{id}`

---

### Step 2: SSL Certs Tab ใน OriginDetail
**ไฟล์:** `dashboard/frontend/src/pages/OriginDetail.tsx` (L255)  
**เวลา:** ~2 ชม.

**สิ่งที่ต้องทำ:**
- ตอนนี้แสดงแค่ `"Available in Phase 3"` placeholder
- Frontend type `SslCert` มีอยู่แล้วใน `types/index.ts`
- Frontend API `getSslStatus()` มีอยู่แล้วใน `api/domains.ts`
- Backend endpoint `/api/origins/{id}/domains/{domainId}/ssl` **ยังไม่มี** → ต้องสร้าง

**ขั้นตอนโค้ด:**
1. [Backend] เพิ่ม endpoint `GET /api/domains/{domain_id}/ssl-status` ใน `api/domains.py`
   - คืนค่า issuer (Let's Encrypt / ZeroSSL), expires_at, status จาก `domain.ssl_status`
2. [Frontend] ใช้ `useQuery` ดึง SSL status ต่อ domain ที่ verified แล้ว
3. แสดง Card: 🔒 ชื่อ domain + สถานะ (active/pending/error) + วันหมดอายุ + badge

---

### Step 3: แก้ปุ่ม "Verify DNS" ใน OriginDetail
**ไฟล์:** `dashboard/frontend/src/pages/OriginDetail.tsx` (L211-L214)  
**เวลา:** ~1 ชม.

**ปัญหา:** ตอนนี้ปุ่ม "Verify DNS" เปิด `DomainSetupWizard` ซึ่งไม่ใช่ — ควรจะเรียก API verify ทันที

**ขั้นตอนโค้ด:**
1. แทนที่ `onClick={() => setIsDomainWizardOpen(true)}` ด้วย function ที่เรียก `verifyDomain()`
2. แสดง loading state ระหว่างตรวจสอบ
3. Toast "✅ Domain verified!" หรือ "❌ DNS record not found"
4. `refetchDomains()` หลังจาก verify สำเร็จ

---

## กลุ่มที่ 2 — Backend ที่ใกล้เสร็จแล้ว

### Step 4: ClickHouse — เพิ่ม `country` field ใน CDN log pipeline
**ไฟล์:** `dashboard/backend/services/cdn_log_forward.py`  
**เวลา:** ~2 ชม.

**สถานะปัจจุบัน:**
- `clickhouse_service.py` มี `init_db()` สร้าง `access_logs` table แล้ว (L36-53)
- `save_log()` รับ `country` field แล้ว — แต่ default เป็น `'TH'` เสมอ (L121)
- `cdn_log_forward.py` normalize log แต่ไม่ได้ส่ง `country` field

**ขั้นตอนโค้ด:**
1. เพิ่ม GeoIP lookup ใน `normalize_cdn_access()`:
   - ใช้ `ip2country` หรือ `geoip2` library (หรือ fallback ดูจาก `region` ของ edge node)
   - SG edge → country fallback `"SG"`, JP → `"JP"`, TH → `"TH"`
2. ส่ง `country` field ใน normalized dict
3. ทดสอบว่า query GeoIP ใน analytics API คืนค่าถูกต้อง

---

### Step 5: WAF Config Sync Script
**ไฟล์ใหม่:** `scripts/sync_waf_rules.py`  
**เวลา:** ~3 ชม.

**สิ่งที่ต้องทำ:**
- ดึง rules จาก `GET /api/rules/` (ผ่าน token)
- แปลงเป็น ModSecurity `.conf` format
- `rsync` หรือ HTTP push ไปยัง edge nodes SG/JP/TH
- เรียก `docker exec nginx -s reload` บน edge แต่ละตัว
- เขียน log ผลลัพธ์ + แสดงสถานะใน UI

**ขั้นตอนโค้ด:**
1. เขียน `sync_waf_rules.py` — ดึง rules → แปลงเป็น conf → push ผ่าน SSH/HTTP
2. เพิ่ม API endpoint `POST /api/rules/sync` ที่ trigger script นี้
3. เพิ่ม type `RuleSyncStatus` (มีอยู่แล้วใน `types/index.ts`) ให้ backend คืนค่าจริง
4. เพิ่มปุ่ม "🔄 Sync to Edge Nodes" ในหน้า Rules.tsx

---

## กลุ่มที่ 3 — งานใหม่ที่ต้องออกแบบ

### Step 6: Quota Management System
**ไฟล์ใหม่:** หลายไฟล์  
**เวลา:** ~4 ชม.

**สิ่งที่ต้องทำ:**
1. [Backend] เพิ่ม field `max_origins`, `max_domains` ใน user record
2. [Backend] ตรวจสอบ quota ใน `POST /api/origins/` และ `POST /api/domains/`
3. [Frontend] แสดง quota bar ใน header หรือ Origins page ("2/5 Origins used")

---

### Step 7: Playwright E2E Tests
**ไฟล์ใหม่:** `dashboard/frontend/tests/`  
**เวลา:** ~4 ชม.

**Test cases:**
1. Register → Login → Redirect to Dashboard
2. Create Origin → Go to OriginDetail → Add Domain
3. DNS Verify flow (mock API)
4. WAF Rules CRUD

---

### Step 8: GitHub Actions CI/CD
**ไฟล์ใหม่:** `.github/workflows/ci.yml`  
**เวลา:** ~2 ชม.

**Jobs:**
1. `lint` — ESLint + Python ruff/flake8
2. `test-backend` — pytest (ถ้ามี unit tests)
3. `test-e2e` — Playwright
4. `build` — npm run build (check no TS errors)

---

## ลำดับการทำงานที่แนะนำ

```
วันนี้:
  Step 3 → แก้ Verify DNS button (เล็กสุด เร็วสุด - 1 ชม.)
  Step 1 → WAF Config Tab (2 ชม.)
  Step 2 → SSL Certs Tab (2 ชม.)

วันพรุ่งนี้:
  Step 4 → ClickHouse country field (2 ชม.)
  Step 5 → WAF Sync Script + API + UI button (3 ชม.)

สัปดาห์หน้า:
  Step 6 → Quota System
  Step 7 → E2E Tests
  Step 8 → CI/CD
```
