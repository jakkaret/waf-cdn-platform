# React + Vite Migration & Phase 4B CDN Metrics Dashboard

## สรุปงาน

Migrate frontend จาก HTML/JS/Bootstrap → React 18 + Vite + TypeScript + TailwindCSS พร้อมสร้างหน้า CDN Monitor ใหม่ (Phase 4B)

## Step 1 — ผลการอ่านไฟล์ ✅

| ไฟล์ | สรุป |
|------|------|
| `Skill.md` | Architecture, ports, tech stack — React 18/Vite/TS/Tailwind/Zustand/React Query/Recharts |
| `Task.md` | Phase 1-3 ✅, Phase 4A ✅, Phase 4B 🔄 กำลังทำ |
| `DESIGN.md` | Full UI/UX spec: color palette, components, layout, pages, types, API contracts (1166 lines) |
| `dashboard/frontend/` | 9 HTML files + 3 JS files (auth.js/dashboard.js/log.js) — ใช้ Bootstrap + Chart.js |
| `dashboard/backend/main.py` | FastAPI, serve HTML pages, includes cdn/auth/rules/alerts routers, startup workers |
| `dashboard/backend/api/cdn.py` | `/api/cdn/nodes`, `/stats`, `/stats/{region}`, `/purge`, `/logs` — มีอยู่แล้ว |
| `dashboard/backend/services/dynamodb_service.py` | DynamoDB CRUD for logs/alerts/rules/users |

### Key Observations
- Frontend ปัจจุบันใช้ HTML + vanilla JS + Bootstrap + Chart.js — ต้อง migrate ทั้งหมด
- Auth logic อยู่ใน `auth.js` ใช้ localStorage key `waf_token` + `waf_user`
- Backend CDN API มี `/nodes`, `/stats`, `/stats/{region}`, `/purge`, `/logs` พร้อมแล้ว
- Backend ยัง serve HTML files ด้วย FileResponse — ต้องปรับ serve React dist แทน
- CDN stats ใช้ mock data เมื่อ cdn-stats service ไม่พร้อม

---

## Step 2 — Setup React + Vite Project

1. **Backup** `dashboard/frontend/` → `dashboard/frontend_backup/`
2. **Init** Vite + React + TypeScript ที่ `dashboard/frontend/`
3. **Install** packages ตาม Skill.md
4. **Config**: `vite.config.ts`, `tailwind.config.ts`, `tsconfig.json`, `postcss.config.js`
5. **Types**: `src/types/index.ts` จาก DESIGN.md section 6

> [!IMPORTANT]
> Backup ไฟล์เดิมก่อน init Vite — จะไม่ลบ backend config ใดๆ

---

## Step 3 — Core Infrastructure

| File | Purpose |
|------|---------|
| `src/store/authStore.ts` | Zustand + persist — token/user/role |
| `src/api/axios.ts` | Axios instance + interceptors |
| `src/api/auth.ts` | Login/register/OAuth/me/users API |
| `src/api/logs.ts` | Get recent logs |
| `src/api/rules.ts` | CRUD rules |
| `src/api/alerts.ts` | Alerts + Telegram connect |
| `src/api/cdn.ts` | CDN nodes/stats/logs/purge |
| `src/components/ui/*` | 15 reusable components (Card, StatCard, Badge, Button, Modal, Table, etc.) |
| `src/components/layout/Sidebar.tsx` | Navigation sidebar ตาม DESIGN.md 3.2 |
| `src/components/layout/TopBar.tsx` | Page title + status bar |
| `src/main.tsx` | React entry |
| `src/App.tsx` | Router + Layout + QueryClient |

---

## Step 4 — Migrate Existing Pages

| Page | File | Key Features |
|------|------|-------------|
| Login | `src/pages/Login.tsx` | Google OAuth + email/password |
| Register | `src/pages/Register.tsx` | Password strength meter |
| OAuth Success | `src/pages/OAuthSuccess.tsx` | Token exchange + redirect |
| Dashboard | `src/pages/Dashboard.tsx` | 3 StatCards + BarChart + DoughnutChart + Table |
| Attack Logs | `src/pages/Logs.tsx` | Summary + Filters + Sort + Pagination + Drawer + CSV export |
| Custom Rules | `src/pages/Rules.tsx` | CRUD modal + role-based |
| Alerts | `src/pages/Alerts.tsx` | Telegram 3-state + pairing + alerts table |
| Users & Roles | `src/pages/UserRoles.tsx` | Admin-only, role management |

---

## Step 5 — Phase 4B: CDN Monitor

### 5A — Backend updates (`dashboard/backend/api/cdn.py`)
- ปรับ `/api/cdn/stats` ให้ return ข้อมูลตาม CdnStats type
- เพิ่ม aggregated cache hit/miss/bypass + blocked count
- `/api/cdn/stats/{region}` เพิ่ม top 5 blocked URLs

### 5B — Frontend: `src/pages/CDN.tsx`
- Node Status Cards (SG/JP/TH) + HealthDot
- Bar Chart: Requests per Region (Recharts)
- Doughnut Chart: Cache Hit Ratio (Recharts PieChart)
- 4 Metric Cards: Avg Latency, P95, Cache Hit Rate, Total Blocked
- CDN Logs Table
- Cache Purge Panel (admin only)
- React Query poll ทุก 10 วินาที

### 5C — Update `main.py`
- ปรับ serve React dist แทน HTML files (production mode)
- คง API routes เดิมทั้งหมด

---

## Verification Plan

### Automated Tests
```bash
cd dashboard/frontend
npm run build   # ตรวจ TypeScript compile + build สำเร็จ
```

### Manual Verification
- `npm run dev` → port 5173 ทำงานได้
- `/login` → login form + Google OAuth button
- `/` → Dashboard with charts + table
- `/logs` → Full log viewer with filters
- `/rules` → Rule management (admin)
- `/alerts` → Telegram connection + alerts table
- `/cdn` → CDN Monitor with charts + node status
- `/users` → User roles (admin only)

---

## Open Questions

> [!IMPORTANT]
> **ขอยืนยันก่อนเริ่ม:**
> 1. ต้องการให้ทำทั้ง 5 Steps ในครั้งนี้ใช่ไหม? (เป็นงานขนาดใหญ่)
> 2. Backend API endpoints ที่มีอยู่ทำงานได้ดีหรือต้องแก้ไขด้วย?
> 3. Tailwind v3 ตาม Skill.md (ไม่ใช่ v4) ถูกต้องใช่ไหม?

---

## Proposed Execution Order

1. ✅ Step 1: อ่านไฟล์ (เสร็จแล้ว)
2. Step 2: Setup React + Vite → รายงาน → หยุดรอ
3. Step 3: Core Infrastructure → รายงาน → หยุดรอ
4. Step 4: Migrate Pages → รายงาน → หยุดรอ
5. Step 5: CDN Monitor (Phase 4B) → รายงาน → หยุดรอ
