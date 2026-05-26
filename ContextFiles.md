## Context Files (อ่านทั้งหมดก่อนเริ่มทำงาน)

- `Skill.md`   → system architecture, tech stack, ports, directory structure
- `Task.md`    → task list, working rules, current status
- `DESIGN.md`  → UI/UX spec, component design, TypeScript types, API contract

## สถานะปัจจุบัน

- Phase 1–3 ✅ เสร็จแล้ว
- Phase 4A: Central Log Collection ✅ เสร็จแล้ว
- Phase 4B: Metrics Dashboard 🔄 กำลังทำ (นี่คืองานที่ต้องทำ)
- Frontend: ยังเป็น HTML/JS เดิม ต้อง migrate ไป React + Vite ก่อน

## งานที่ต้องทำใน session นี้

### Step 1 — อ่านไฟล์ที่มีอยู่ทั้งหมดก่อน (ห้ามข้าม)

อ่านไฟล์เหล่านี้ตามลำดับ:
1. `Skill.md` — อ่านครบทุก section
2. `Task.md` — อ่านครบทุก section
3. `DESIGN.md` — อ่านครบทุก section
4. `dashboard/frontend/` — ดูโครงสร้างทั้งหมดที่มีอยู่
5. `dashboard/frontend/index.html` — อ่านหน้า dashboard เดิม
6. `dashboard/frontend/assets/auth.js` — อ่าน auth logic เดิม
7. `dashboard/frontend/assets/dashboard.js` — อ่าน dashboard logic เดิม
8. `dashboard/frontend/logs.html` + `assets/log.js`
9. `dashboard/frontend/rules.html`
10. `dashboard/frontend/alerts.html`
11. `dashboard/backend/api/cdn.py` — อ่าน CDN API ที่มีอยู่
12. `dashboard/backend/services/dynamodb_service.py`
13. `dashboard/backend/main.py`

รายงานผลการอ่านก่อนเขียนโค้ดใดๆ

---

### Step 2 — Setup React + Vite Project

สร้าง project ใหม่ที่ `dashboard/frontend/` (ทับของเดิม แต่ backup ไฟล์เดิมไว้ที่ `dashboard/frontend_backup/` ก่อน)

ติดตั้ง packages ตาม Skill.md:
react@^18, react-dom@^18
vite@^5, @vitejs/plugin-react
typescript@^5
react-router-dom@^6
tailwindcss@^3, postcss, autoprefixer
@tanstack/react-query@^5
zustand@^4
recharts@^2
axios@^1
lucide-react
react-hot-toast

Config ที่ต้องทำ:
- `vite.config.ts`: proxy `/api` → `http://localhost:8000`
- `tailwind.config.ts`: เพิ่ม colors จาก DESIGN.md section 1.1
- `src/types/index.ts`: TypeScript types ทั้งหมดจาก DESIGN.md section 6

รายงานไฟล์ที่สร้างทั้งหมด แล้วหยุดรอ

---

### Step 3 — สร้าง Core Infrastructure

สร้างตามลำดับนี้ทีละไฟล์:

**3A — Auth Store**
- `src/store/authStore.ts`
- Zustand + persist ลง localStorage
- ตาม DESIGN.md section 7.1

**3B — Axios Instance**
- `src/api/axios.ts`
- Request interceptor: เพิ่ม Authorization header
- Response interceptor: 401 → logout + redirect `/login`
- ตาม DESIGN.md section 8

**3C — API Modules** (สร้างทุกไฟล์)
- `src/api/auth.ts`
- `src/api/logs.ts`
- `src/api/rules.ts`
- `src/api/alerts.ts`
- `src/api/cdn.ts`
- ตาม DESIGN.md section 8 ทุก function signature

**3D — Reusable UI Components** (สร้างทุกชิ้น)
สร้างจาก DESIGN.md section 2:
- `src/components/ui/Card.tsx`
- `src/components/ui/StatCard.tsx`
- `src/components/ui/Badge.tsx` (รวม SeverityBadge + StatusBadge)
- `src/components/ui/Button.tsx`
- `src/components/ui/Modal.tsx`
- `src/components/ui/Table.tsx`
- `src/components/ui/Pagination.tsx`
- `src/components/ui/Drawer.tsx`
- `src/components/ui/EmptyState.tsx`
- `src/components/ui/LoadingSpinner.tsx`
- `src/components/ui/HealthDot.tsx`
- `src/components/ui/SearchInput.tsx`
- `src/components/ui/FilterSelect.tsx`
- `src/components/ui/ConfirmDialog.tsx`

**3E — Layout Components**
- `src/components/layout/Sidebar.tsx` — ตาม DESIGN.md section 3.2
- `src/components/layout/TopBar.tsx` — ตาม DESIGN.md section 3.3

**3F — App Shell**
- `src/main.tsx`
- `src/App.tsx` — Router + Layout + QueryClient + route map ตาม DESIGN.md section 3.4

รายงานไฟล์ที่สร้างทั้งหมด แล้วหยุดรอ

---

### Step 4 — Migrate หน้าที่มีอยู่แล้ว (Port จาก HTML/JS)

**4A — Login Page**
- `src/pages/Login.tsx`
- ตาม DESIGN.md section 4.2
- เชื่อม Google OAuth + email/password form
- Password ใช้ `POST /api/auth/login`

**4B — Register Page**
- `src/pages/Register.tsx`
- ตาม DESIGN.md section 4.3
- Password strength meter

**4C — OAuth Success Page**
- `src/pages/OAuthSuccess.tsx`
- ตาม DESIGN.md section 4.4

**4D — Dashboard Page**
- `src/pages/Dashboard.tsx`
- ตาม DESIGN.md section 5.1 ครบทุก component
- StatCards 3 ใบ + BarChart + DoughnutChart + Filter + Table
- React Query poll ทุก 5 วินาที

**4E — Attack Logs Page**
- `src/pages/Logs.tsx`
- ตาม DESIGN.md section 5.2 ครบทุก component
- Summary bar + Filter panel + Sortable table + Pagination + Detail Drawer
- Export CSV
- Auto-refresh ทุก 8 วินาที

**4F — Custom Rules Page**
- `src/pages/Rules.tsx`
- ตาม DESIGN.md section 5.3
- Table + Add/Edit Modal + Delete confirm
- Role-based: viewer เห็น read-only, admin เห็น actions

**4G — Alerts Page**
- `src/pages/Alerts.tsx`
- ตาม DESIGN.md section 5.4
- Telegram 3 states + pairing flow + polling + countdown timer
- Alerts table

**4H — Users & Roles Page**
- `src/pages/UserRoles.tsx`
- ตาม DESIGN.md section 5.6
- Admin only route guard

รายงานไฟล์ที่สร้างทั้งหมด แล้วหยุดรอ

---

### Step 5 — Phase 4B: CDN Monitor Page (งานหลัก)

**5A — Backend: เพิ่ม/อัปเดต CDN API**

อ่าน `dashboard/backend/api/cdn.py` ก่อน แล้ว implement:
GET /api/cdn/nodes
→ poll health ของทุก node (SG port 8081, JP 8082, TH 8086)
→ return: [{ region, port, status, uptime_pct, cache_hit_ratio, avg_latency_ms }]
GET /api/cdn/stats
→ query DynamoDB cdn_logs table
→ return: [{ region, request_count, cache_hit, cache_miss, cache_bypass, blocked_count, avg_latency }]
GET /api/cdn/stats/{region}
→ drill-down per region (SG/JP/TH)
→ return: CdnStats สำหรับ region นั้น + top 5 blocked URLs
GET /api/cdn/logs?region=ALL&limit=50
→ return: [{ region, ip, url, method, status, cache_status, latency_ms, datetime }]

บอก path ทุกไฟล์ที่แก้ไขและ schema ที่ return

**5B — Frontend: CDN.tsx Page**

สร้าง `src/pages/CDN.tsx` ตาม DESIGN.md section 5.5 ครบทุกส่วน:

1. **Node Status Cards** (3 cards: SG/JP/TH)
   - HealthDot + region name + port
   - status: online/offline/degraded
   - cache hit %, avg latency ms
   - ถ้า offline → border แดง + badge "DOWN"

2. **Bar Chart: Requests per Region**
   - Recharts BarChart
   - X: SG/JP/TH, Y: request count
   - Height 200px

3. **Doughnut Chart: Cache Hit Ratio**
   - Recharts PieChart + innerRadius
   - HIT/MISS/BYPASS
   - Center text: "XX% HIT"
   - Height 200px

4. **Metric Cards** (4 cards)
   - Avg Latency / P95 Latency / Cache Hit Rate / Total Blocked

5. **CDN Logs Table**
   - Columns: Time, Region badge, IP, URL, Status, Cache status, Latency
   - ตาม DESIGN.md section 5.5

6. **Cache Purge Panel** (admin only)
   - URL input + Region select + Purge button
   - แสดง last purge info
   - POST `/api/cdn/purge`

7. React Query poll ทุก 10 วินาที สำหรับ nodes + stats
8. เพิ่ม route `/cdn` ใน App.tsx

**5C — อัปเดต main.py**

ตรวจสอบว่า FastAPI include cdn router แล้วและ serve React dist ถูกต้อง

รายงานไฟล์ที่สร้างทั้งหมด แล้วหยุดรอ

---

## กฎการทำงาน (จาก Task.md — ต้องปฏิบัติทุกข้อ)

1. อ่านไฟล์ทุกไฟล์ที่เกี่ยวข้องก่อนแก้ไขเสมอ
2. อย่าลบหรือ overwrite config ที่ทำงานอยู่แล้ว
3. Implement จริง ไม่ใช่แค่ scaffold หรือ placeholder
4. ทำทีละ Step จนเสร็จก่อนไปต่อ
5. บอก path ของทุกไฟล์ที่สร้าง/แก้ไขชัดเจน
6. เมื่อแต่ละ Step เสร็จ รายงานผล แล้วหยุดรอก่อนไปต่อ
7. บันทึกสถานะลง Task.md เมื่อแต่ละ Step เสร็จ

## เป้าหมายสุดท้ายของ Session นี้

เมื่อเสร็จแล้วระบบต้องทำงานได้ดังนี้:
- `npm run dev` รัน React app ที่ port 5173 ได้
- Login ด้วย email/password และ Google OAuth ได้
- Dashboard, Logs, Rules, Alerts ทำงานได้เหมือนเดิม
- หน้า CDN Monitor แสดง node status, charts, logs ได้
- Cache Purge ใช้งานได้ (admin)
- พร้อมรับ Phase 4C (Latency Tracking) ต่อทันที