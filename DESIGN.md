# 🎨 DESIGN.md — WAF + CDN Dashboard Frontend Design Spec

> **วัตถุประสงค์:** ไฟล์นี้เป็น single source of truth สำหรับ AI ในการสร้าง Frontend  
> อ่านร่วมกับ `Skill.md` (architecture) และ `Task.md` (task list + rules)  
> **อ่านไฟล์นี้ก่อนเขียนโค้ด frontend ทุกครั้ง**

---

## 1. Design System

### 1.1 Color Palette

```ts
// tailwind.config.ts — extend colors
colors: {
  // Base (Dark theme)
  bg: {
    primary:   '#0d1117',   // page background
    surface:   '#161b27',   // card, sidebar background
    surface2:  '#1e2438',   // input, hover state
    border:    'rgba(255,255,255,0.07)',
  },

  // Brand / Accent
  accent: {
    DEFAULT:  '#667eea',   // primary purple-blue
    dark:     '#764ba2',   // gradient end
    light:    '#a5b4fc',   // active nav item
    tg:       '#229ed9',   // Telegram blue
  },

  // Semantic
  success:  '#68d391',   // green — allowed, connected, ok
  warning:  '#f6ad55',   // orange — high severity, warning
  danger:   '#fc8181',   // red — critical, blocked, error
  info:     '#76e4f7',   // cyan — info badge

  // Text
  text: {
    primary:  '#e4e8f0',
    muted:    'rgba(255,255,255,0.4)',
    subtle:   'rgba(255,255,255,0.2)',
  },

  // Severity (WAF rules & logs)
  severity: {
    critical: { bg: '#fee', text: '#c53030' },
    high:     { bg: '#fef5e7', text: '#dd6b20' },
    medium:   { bg: '#fefce8', text: '#d69e2e' },
    low:      { bg: '#e6fffa', text: '#38b2ac' },
  },

  // HTTP Status
  status: {
    '2xx': { bg: '#e6f9f0', text: '#276749' },
    '403': { bg: '#fff4e5', text: '#c05621' },
    '5xx': { bg: '#fff5f5', text: '#c53030' },
  },
}
```

### 1.2 Typography

```ts
fontFamily: {
  sans: ['DM Sans', '-apple-system', 'sans-serif'],
  mono: ['IBM Plex Mono', 'Courier New', 'monospace'],
}

// Font sizes (ใช้ Tailwind defaults + custom)
// text-xs   → 11-12px  (badge, label, timestamp)
// text-sm   → 13-14px  (table cell, body)
// text-base → 15-16px  (card subtitle)
// text-lg   → 18px     (section title)
// text-2xl  → 22-24px  (page title)
// text-4xl  → 32-36px  (stat value)
```

### 1.3 Spacing & Radius

```
Page padding:    30px (content area)
Card padding:    20-25px
Gap between cards: 20px
Border radius:
  - Card:    12-14px  (rounded-xl)
  - Button:  8-10px   (rounded-lg)
  - Badge:   20px     (rounded-full)
  - Input:   8px      (rounded-lg)
  - Tag:     6px      (rounded-md)
```

### 1.4 Shadow & Elevation

```
Card (default):  box-shadow: 0 2px 8px rgba(0,0,0,0.06)
Card (hover):    box-shadow: 0 8px 20px rgba(0,0,0,0.1)
Modal:           box-shadow: 0 20px 60px rgba(0,0,0,0.3)
Sidebar:         border-right: 1px solid rgba(255,255,255,0.06)
```

### 1.5 Gradient

```css
/* Brand gradient — ใช้กับ sidebar, primary button */
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);

/* Sidebar background */
background: linear-gradient(160deg, #1a1f36 0%, #252b47 100%);

/* Card glow (login page) */
background: radial-gradient(circle, rgba(102,126,234,0.15) 0%, transparent 70%);
```

---

## 2. Reusable UI Components

### 2.1 Component Inventory

ทุก component อยู่ใน `src/components/ui/`

| Component | File | Props หลัก |
|-----------|------|-----------|
| `Card` | `Card.tsx` | `children`, `className`, `hover?: boolean` |
| `StatCard` | `StatCard.tsx` | `title`, `value`, `change?`, `icon?`, `color?` |
| `Badge` | `Badge.tsx` | `variant`: `severity` \| `status` \| `role` \| `source`, `children` |
| `SeverityBadge` | `SeverityBadge.tsx` | `level`: `CRITICAL`\|`HIGH`\|`MEDIUM`\|`LOW` |
| `StatusBadge` | `StatusBadge.tsx` | `code`: number (200, 403, 500…) |
| `Button` | `Button.tsx` | `variant`: `primary`\|`secondary`\|`danger`\|`ghost`, `size`, `loading?` |
| `Modal` | `Modal.tsx` | `open`, `onClose`, `title`, `children` |
| `Table` | `Table.tsx` | `columns`, `data`, `onRowClick?`, `loading?` |
| `Pagination` | `Pagination.tsx` | `page`, `totalPages`, `onChange` |
| `Drawer` | `Drawer.tsx` | `open`, `onClose`, `title`, `children` |
| `EmptyState` | `EmptyState.tsx` | `icon?`, `title`, `subtitle?` |
| `LoadingSpinner` | `LoadingSpinner.tsx` | `size?` |
| `HealthDot` | `HealthDot.tsx` | `status`: `ok`\|`warn`\|`down` |
| `SearchInput` | `SearchInput.tsx` | `value`, `onChange`, `placeholder` |
| `FilterSelect` | `FilterSelect.tsx` | `options`, `value`, `onChange`, `label` |
| `CodeBlock` | `CodeBlock.tsx` | `code`, `language?` |
| `ConfirmDialog` | `ConfirmDialog.tsx` | `open`, `message`, `onConfirm`, `onCancel` |

### 2.2 Badge Variants

```tsx
// SeverityBadge
<SeverityBadge level="CRITICAL" />  // แดง
<SeverityBadge level="HIGH" />      // ส้ม
<SeverityBadge level="MEDIUM" />    // เหลือง
<SeverityBadge level="LOW" />       // เขียว-น้ำเงิน

// StatusBadge (HTTP)
<StatusBadge code={200} />   // เขียว "200"
<StatusBadge code={403} />   // ส้ม "403"
<StatusBadge code={500} />   // แดง "500"

// Role badge
<Badge variant="role" value="admin" />   // ทอง
<Badge variant="role" value="viewer" />  // เทา
```

### 2.3 StatCard

```tsx
interface StatCardProps {
  title: string
  value: string | number
  icon?: ReactNode
  iconBg?: string        // tailwind class e.g. 'bg-purple-100'
  change?: {
    value: string        // e.g. "+12%"
    direction: 'up' | 'down' | 'neutral'
  }
  color?: 'default' | 'danger' | 'success' | 'warning'
}

// ตัวอย่างการใช้งาน
<StatCard
  title="Total Events"
  value="1,247"
  icon={<ShieldIcon />}
  iconBg="bg-purple-100"
  change={{ value: "+8%", direction: "up" }}
/>
```

---

## 3. Layout & Navigation

### 3.1 App Shell Structure

```
┌─────────────────────────────────────────────────┐
│  Sidebar (240px fixed)  │  Main Content Area     │
│  ─────────────────────  │  ───────────────────── │
│  [Brand Logo + Name]    │  [TopBar]               │
│                         │  ─────────────────────  │
│  [Nav Section: Main]    │                         │
│  • Dashboard            │  <Page Content>         │
│  • Attack Logs          │                         │
│  • Custom Rules         │                         │
│  • Alerts               │                         │
│  • CDN Monitor          │                         │
│                         │                         │
│  [Nav Section: Admin]   │                         │
│  • Users & Roles        │                         │
│  (admin only)           │                         │
│                         │                         │
│  ─────────────────────  │                         │
│  [User Avatar + Name]   │                         │
│  [Role Badge] [Logout]  │                         │
└─────────────────────────────────────────────────┘
```

### 3.2 Sidebar Spec

```tsx
// src/components/layout/Sidebar.tsx

// ความกว้าง: 240px (fixed, left-0, top-0, bottom-0)
// Background: linear-gradient(160deg, #1a1f36 0%, #252b47 100%)
// Border-right: 1px solid rgba(255,255,255,0.06)

// Nav Items
const navItems = [
  // Main section
  { key: 'dashboard', href: '/',          icon: LayoutGrid,   label: 'Dashboard' },
  { key: 'logs',      href: '/logs',      icon: ScrollText,   label: 'Attack Logs' },
  { key: 'rules',     href: '/rules',     icon: ShieldCog,    label: 'Custom Rules' },
  { key: 'alerts',    href: '/alerts',    icon: Bell,         label: 'Alerts' },
  { key: 'cdn',       href: '/cdn',       icon: Globe,        label: 'CDN Monitor' },

  // Admin section (แสดงเฉพาะ role === 'admin')
  { key: 'users',     href: '/users',     icon: Users,        label: 'Users & Roles' },
]

// Active state: bg-accent/18, color: accent.light, border-left: 2px solid accent.light
// Hover state: bg-white/7, color: white/90
// Inactive: color: white/55
```

### 3.3 TopBar Spec

```tsx
// src/components/layout/TopBar.tsx
// ใช้ position sticky top-0, bg-white, z-index 100
// สำหรับ dark theme ใช้ bg-bg-surface, border-bottom

// ซ้าย: Page Title (ชื่อหน้าปัจจุบัน)
// ขวา: Status Badge (WAF Online) + Notification bell + User avatar
```

### 3.4 Route Map

```tsx
// src/App.tsx
const routes = [
  { path: '/',        element: <Dashboard />,  protected: true  },
  { path: '/logs',    element: <Logs />,       protected: true  },
  { path: '/rules',   element: <Rules />,      protected: true  },
  { path: '/alerts',  element: <Alerts />,     protected: true  },
  { path: '/cdn',     element: <CDN />,        protected: true  },
  { path: '/users',   element: <UserRoles />,  protected: true, adminOnly: true },
  { path: '/login',   element: <Login />,      protected: false },
  { path: '/register',element: <Register />,   protected: false },
  { path: '/oauth-success', element: <OAuthSuccess />, protected: false },
]

// Protected Route wrapper: ถ้าไม่มี token → redirect /login
// Admin Route wrapper: ถ้า role !== 'admin' → redirect /
```

---

## 4. Auth Flow

### 4.1 State (Zustand)

```ts
// src/store/authStore.ts
interface AuthState {
  token: string | null
  user: {
    user_id: string
    email: string
    username: string
    role: 'admin' | 'viewer'
    avatar_url?: string
    auth_provider: 'local' | 'google' | 'telegram'
  } | null
  isAuthenticated: boolean

  // Actions
  setSession: (token: string, user: User) => void
  clearSession: () => void
}

// Persistence: localStorage key 'waf_token' + 'waf_user'
// ล้าง session เมื่อ API ตอบ 401 (axios interceptor)
```

### 4.2 Login Page (`/login`)

**Layout:** Centered card, dark background, grid pattern overlay

**Sections:**
1. Brand logo + title "Sign in"
2. OAuth buttons:
   - "Continue with Google" → `GET /api/auth/google`
   - "Continue with Telegram" → เปิด modal แสดง Telegram widget
3. Divider "or sign in with email"
4. Email + Password form → `POST /api/auth/login`
5. Link: "No account? Create one"

**Error state:** แสดง error card สีแดงใต้ OAuth buttons

**Success:** บันทึก token + user ใน Zustand → redirect `/`

### 4.3 Register Page (`/register`)

**Sections:**
1. Brand logo + "Create account"
2. Notice box: "First account = admin, subsequent = viewer"
3. Form: Display Name, Email, Password (strength meter), Confirm Password
4. Submit → `POST /api/auth/register`
5. Link: "Already have account? Sign in"

**Password Strength Meter:**
- Weak (red) / Fair (orange) / Good (green) / Strong (dark green)
- Criteria: length ≥ 8, uppercase, number, special char

### 4.4 OAuth Success Page (`/oauth-success`)

- แสดง spinner "Completing sign in..."
- อ่าน `?token=` จาก URL params
- เรียก `GET /api/auth/me` ด้วย token
- บันทึก session → redirect `/`

### 4.5 Axios Interceptor

```ts
// src/api/axios.ts
// Request interceptor: เพิ่ม Authorization: Bearer <token> ทุก request
// Response interceptor:
//   - 401 → clearSession() + redirect '/login'
//   - 403 → แสดง toast "Access denied"
//   - 5xx → แสดง toast "Server error"
```

---

## 5. Pages — Detailed Spec

---

### 5.1 Dashboard Page (`/`)

**วัตถุประสงค์:** Overview real-time WAF traffic

**API Calls:**
```ts
// React Query — poll ทุก 5 วินาที
GET /api/logs/recent?limit=25
```

**Layout:**

```
[Page Title: "Live Dashboard"]  [Last updated: 14:30:22]

[StatCard: Total Events] [StatCard: Blocked 403] [StatCard: Allowed]

[Bar Chart: Requests by Status Code]  [Doughnut: Top Rule IDs Triggered]

[Filter Bar: Limit select | Status select]

[Log Table]
```

**StatCards (3 cards):**
| Card | Value | Color |
|------|-------|-------|
| Total Events | `logs.length` | default |
| Blocked (403) | count where status=403 | danger (red) |
| Allowed | total - blocked | success (green) |

**Bar Chart — Requests by Status Code:**
- Library: Recharts `BarChart`
- X-axis: status bucket ("2xx Allow", "403 Block", "5xx Error", "Other")
- Y-axis: count
- Colors: ตาม status bucket (green/orange/red/grey)
- Height: 210px
- Empty state: icon + "No data yet"

**Doughnut Chart — Top Rule IDs:**
- Library: Recharts `PieChart` with `innerRadius`
- Filter: เฉพาะ 403 logs
- Group by: `rule_id` (top 9)
- Legend: ขวา, font-size 11px
- Empty state: "No blocked requests yet"

**Log Table Columns:**
| Column | Data field | Format |
|--------|-----------|--------|
| Time | `datetime` | `toLocaleTimeString()` |
| IP | `ip` | monospace |
| Method | `method` | Badge (GET=green, POST=blue, DELETE=red) |
| URL | `url` | truncate 220px, monospace |
| Status | `status` | StatusBadge |
| Rule ID | `rule_id` | monospace, accent color |
| Severity | `severity` | SeverityBadge |

**Row highlight:** 403 rows → `bg-orange-50`

**Filter Bar:**
- Limit select: 5 / 10 / 20 / 25
- Status select: All / Allow (200) / Blocked (403) / Server Error (5xx)
- Filter เปลี่ยนทันทีโดยไม่ต้องกด Apply (onChange)

---

### 5.2 Attack Logs Page (`/logs`)

**วัตถุประสงค์:** Full log viewer พร้อม filter, sort, export, detail drawer

**API Calls:**
```ts
GET /api/logs/recent?limit=100   // auto-refresh ทุก 8 วินาที
```

**Layout:**

```
[Page Header: "Attack Logs"]  [● Live badge] [Auto-refresh toggle]

[Summary Bar: Total | Blocked | Allowed | 5xx | Suspicious | Unique IPs]

[Filter Panel]
  Search: [____________________]
  Status: [All ▼] Method: [All ▼] Severity: [All ▼] Source: [All ▼]
  Suspicious: [All ▼]  Fetch: [100 rows ▼]  [Apply] [Reset]
  [Active filter tags]

[Table Toolbar: "Showing N of M results" | [Export CSV] [Refresh]]

[Log Table with Sorting]

[Pagination Bar]
```

**Summary Bar (6 cards):**
| Metric | Calculation |
|--------|------------|
| Total | `logs.length` |
| Blocked 403 | `status === '403'` |
| Allowed 2xx | `['200','201','204'].includes(status)` |
| 5xx Errors | `status.startsWith('5')` |
| Suspicious | `is_suspicious_path === true` |
| Unique IPs | `new Set(logs.map(l => l.ip)).size` |

**Filter Panel:**
- Search: full-text search across all fields, Enter to apply
- Status: All / 200 / 403 / 5xx
- Method: All / GET / POST / PUT / PATCH / DELETE
- Severity: All / CRITICAL / HIGH / MEDIUM / LOW / None
- Source: All / nginx / modsecurity
- Suspicious: All / Suspicious only / Normal only
- Fetch limit: 25 / 50 / 100

**Active Filter Tags:** แสดง chip สีม่วงสำหรับ filter ที่เปิดอยู่ กด × เพื่อลบ

**Log Table Columns (sortable ทุก column):**
| Column | Field | Note |
|--------|-------|------|
| Time | `datetime` | sort default desc |
| Source IP | `ip` | monospace, suspicious = ⚠ icon |
| Method | `method` | color badge |
| URL | `url` | truncate 240px |
| Status | `status` | StatusBadge |
| Rule ID | `rule_id` | monospace |
| Severity | `severity` | SeverityBadge |
| Source | `source` | badge: nginx=blue / modsecurity=purple |
| Flags | `is_suspicious_path` | ⚠ หรือ — |

**Row colors:**
- 403 → `bg-orange-50`
- 5xx → `bg-red-50`

**Sort:** click header → toggle asc/desc → sort icon แสดง direction

**Pagination:** 25 rows/page, แสดง page buttons

**Detail Drawer (slide-in จากขวา, 480px):**
- เปิดเมื่อ click row
- แสดงข้อมูลทุก field ของ log นั้น
- Section: Request Info / WAF Info / Raw Data (code block)
- ปุ่มปิด (X) และ click overlay เพื่อปิด

**Export CSV:**
- download ชื่อ `waf-logs-{date}.csv`
- export เฉพาะ filtered rows

---

### 5.3 Custom Rules Page (`/rules`)

**วัตถุประสงค์:** จัดการ ModSecurity custom rules

**API Calls:**
```ts
GET    /api/rules/           // load rules
POST   /api/rules/           // create rule (admin only)
PUT    /api/rules/{rule_id}  // update rule (admin only)
DELETE /api/rules/{rule_id}  // delete rule (admin only)
```

**Layout:**

```
[Page Title: "Custom Rules"]  [+ Add Rule button (admin only)]

[Rules Table]
```

**Rules Table Columns:**
| Column | Field | Note |
|--------|-------|------|
| Rule ID | `id` | monospace |
| Variable | `variable` | e.g. REQUEST_URI |
| Operator | `operator` | monospace, truncate |
| Severity | `severity` | SeverityBadge |
| Message | `message` | - |
| Actions | — | Edit + Delete buttons (admin only) |

**Add/Edit Rule Modal:**
```
Modal title: "Add Rule" / "Edit Rule"
Width: 480px

Fields:
  Rule ID     [text input]  — disabled เมื่อ Edit
  Variable    [select]      — REQUEST_URI / ARGS / REQUEST_HEADERS / REQUEST_BODY
  Operator    [text input]  — e.g. "@rx .*admin.*"
  Severity    [select]      — CRITICAL / HIGH / MEDIUM / LOW
  Message     [textarea]    — description

Buttons: [Save] [Cancel]
```

**Validation (client-side):**
- Rule ID: ตัวเลขเท่านั้น
- Variable: ต้องเลือกจาก allowed list
- Operator: ห้ามว่าง
- Message: ห้ามว่าง

**Role-based visibility:**
- `viewer`: เห็น table อ่านอย่างเดียว ไม่มีปุ่ม Add/Edit/Delete
- `admin`: เห็นและใช้งานทุกอย่างได้

**Delete flow:** ConfirmDialog → "Delete this rule?" → DELETE API

---

### 5.4 Alerts Page (`/alerts`)

**วัตถุประสงค์:** เชื่อมต่อ Telegram Bot + ดู WAF alerts ที่ถูก trigger

**API Calls:**
```ts
GET    /api/alerts/recent?limit=50        // load alerts table
GET    /api/alerts/connect/status         // check Telegram connection
POST   /api/alerts/connect/start          // generate pairing code
GET    /api/alerts/connect/poll?code=XXX  // poll connection status (ทุก 3 วิ)
DELETE /api/alerts/connect                // disconnect Telegram
```

**Layout:**

```
[Page Title: "Alerts"]
[Subtitle: "WAF-triggered alerts forwarded to your Telegram"]

[Telegram Card]

[Alerts Table]
```

**Telegram Card — 3 States:**

**State A: ยังไม่ได้เชื่อมต่อ**
```
[Telegram Icon]  Telegram Alert Bot
                 รับแจ้งเตือนเมื่อ WAF ตรวจพบการโจมตี
                 ● ยังไม่ได้เชื่อมต่อ

                                    [เชื่อมต่อ Telegram]
```

**State B: กำลัง Pair (Code Panel เปิด)**
```
[Telegram Icon]  Telegram Alert Bot
                 ● กำลังรอการยืนยัน...
                                    [ยกเลิก]

--- Code Panel ---
Step 1: รหัสยืนยัน
        [ A3F2C1 ]  [คัดลอก]  หมดอายุใน 4:32

Step 2: ส่งรหัสไปที่ Bot
        [เปิด Telegram Bot]
        หรือส่ง /start A3F2C1 ใน chat

Step 3: รอการยืนยัน
        [spinner] รอรับรหัสจาก Telegram...
```

**State C: เชื่อมต่อแล้ว**
```
[Telegram Icon]  Telegram Alert Bot
                 ● เชื่อมต่อแล้ว (Chat ID: 123456789)
                 [✓ เชื่อมต่อแล้ว]       [ยกเลิกการเชื่อมต่อ]
```

**Pairing Flow (Sequence):**
1. User กด "เชื่อมต่อ Telegram"
2. POST `/api/alerts/connect/start` → ได้ `code`, `bot_username`, `expires_in`
3. แสดง code + link ไป Telegram Bot
4. Frontend poll GET `/api/alerts/connect/poll?code=XXX` ทุก 3 วินาที
5. เมื่อ status = "connected" → อัปเดต UI เป็น State C
6. Countdown timer แสดงอายุ code (5 นาที)
7. ถ้า expire → ยกเลิกอัตโนมัติ กลับ State A

**Alerts Table Columns:**
| Column | Field |
|--------|-------|
| Alert ID | `alert_id` monospace |
| Source IP | `ip` |
| URL | `url` truncate |
| Status | `status` StatusBadge |
| Message | `message` |
| Time | `timestamp` |

**Empty state:** Bell icon + "ยังไม่มี alert — WAF กำลังเฝ้าระวังอยู่ 👀"

---

### 5.5 CDN Monitor Page (`/cdn`)

**วัตถุประสงค์:** ดู status และ metrics ของ CDN edge nodes

**API Calls:**
```ts
// React Query — poll ทุก 10 วินาที
GET /api/cdn/nodes                  // node health status
GET /api/cdn/stats                  // aggregate stats
GET /api/cdn/stats/{region}         // drill-down per region
GET /api/cdn/logs?region=ALL&limit=50  // CDN logs
GET /api/cdn/latency?region=ALL&period=1h  // latency data
POST /api/cdn/purge?url=...&region=ALL     // cache purge (admin only)
GET /api/cdn/rule-sync-status       // rule sync status (Phase 5B)
```

**Layout:**

```
[Page Title: "CDN Monitor"]

[Node Status Cards: SG | JP | TH]

[Stats Row]
[Bar Chart: Requests per Region]  [Doughnut: Cache Hit Ratio]

[Latency Line Chart: Latency over time, per region]

[Metric Cards: Avg Latency | P95 Latency | Cache Hit Rate | Total Blocked]

[Cache Purge Panel (admin only)]

[CDN Logs Table]

[Rule Sync Status Panel (Phase 5B+)]

[Global Block Panel (Phase 5C+)]
```

**Node Status Cards (3 cards: SG / JP / TH):**
```
┌─────────────────────────┐
│ 🟢 SG — Singapore       │
│ Port: 8081              │
│ Status: Online          │
│ Uptime: 99.9%           │
│ Cache: HIT 73%          │
│ Latency: 42ms avg       │
└─────────────────────────┘
```
- HealthDot: green=online, orange=degraded, red=offline
- Data จาก `GET /api/cdn/nodes`
- ถ้า node offline → card border สีแดง + badge "DOWN"

**Bar Chart — Requests per Region:**
- Recharts `BarChart`
- X-axis: SG / JP / TH
- Y-axis: request count
- Color: accent gradient ต่อ region
- Height: 200px

**Doughnut Chart — Cache Hit Ratio:**
- Recharts `PieChart`
- Segments: HIT (green) / MISS (orange) / BYPASS (grey)
- Center text: "73% HIT"
- Height: 200px

**Latency Line Chart:**
- Recharts `LineChart`
- X-axis: time (ช่วง 1 ชั่วโมงล่าสุด)
- Y-axis: latency (ms)
- 3 lines: SG (blue) / JP (purple) / TH (green)
- Data จาก `/api/cdn/latency`
- Height: 220px

**Metric Cards (4 cards):**
| Metric | Source |
|--------|--------|
| Avg Latency | `avg_ms` จาก latency API |
| P95 Latency | `p95_ms` |
| Cache Hit Rate | `hit / total * 100` % |
| Total Blocked | sum ของ `blocked_count` ทุก region |

**Cache Purge Panel (admin only):**
```
[URL input: /path/to/resource]  [Region select: ALL/SG/JP/TH]  [Purge Cache]
Last purge: 2025-01-17 14:30 — /dvwa/images/logo.png (ALL)
```
- POST `/api/cdn/purge?url=...&region=...`
- แสดง success/error toast

**CDN Logs Table:**
| Column | Field |
|--------|-------|
| Time | `datetime` |
| Region | `region` badge |
| IP | `ip` |
| URL | `url` |
| Status | `status` StatusBadge |
| Cache | `cache_status` (HIT/MISS/BYPASS) badge |
| Latency | `latency_ms` ms |

**Rule Sync Status Panel (Phase 5B):**
```
WAF Rule Sync Status
SG [✓ Synced]  JP [✓ Synced]  TH [✗ Failed]
Last sync: 14:30:00
[Force Sync Now]
```

**Global Block Panel (Phase 5C):**
```
Global IP/CIDR Block
[IP/CIDR input]  [Reason input]  [Block]

Blocked List:
IP/CIDR          Reason              Blocked At       [Unblock]
192.168.1.1      SQL Injection scan  2025-01-17       [Unblock]
10.0.0.0/8       Suspicious range    2025-01-16       [Unblock]
```

---

### 5.6 Users & Roles Page (`/users`) — Admin Only

**วัตถุประสงค์:** จัดการ user roles

**API Calls:**
```ts
GET /api/auth/users                        // list users
PUT /api/auth/users/{user_id}/role         // update role
```

**Layout:**

```
[Page Title: "Users & Roles"]

[Users Table]
```

**Users Table Columns:**
| Column | Field |
|--------|-------|
| User | Avatar + Name + Email |
| Provider | badge: local / google / telegram |
| Role | Role badge (admin=gold, viewer=grey) + [Change role select] |
| Joined | `created_at` |
| Last Login | `last_login` |

**Role Change:** dropdown select inline ใน table → confirm dialog → PUT API

**Access Control:** route guard → ถ้าไม่ใช่ admin → redirect `/`

---

## 6. TypeScript Types

```ts
// src/types/index.ts

export interface User {
  user_id: string
  email: string
  username: string
  role: 'admin' | 'viewer'
  avatar_url?: string
  auth_provider: 'local' | 'google' | 'telegram'
  created_at: string
  last_login: string
}

export interface WafLog {
  log_id?: string
  user_id: string
  request_id?: string
  ip: string
  method: string
  url: string
  status: number
  user_agent?: string
  datetime: string
  timestamp: number
  source: 'nginx' | 'modsec' | 'merged'
  rule_id?: string | null
  severity?: string | null
  attack_type?: string | null
  alert: boolean
  is_suspicious_path?: boolean
  has_query?: boolean
  body_bytes_sent?: number
  http_referer?: string
}

export interface WafRule {
  id: string
  variable: 'REQUEST_URI' | 'ARGS' | 'REQUEST_HEADERS' | 'REQUEST_BODY'
  operator: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  message: string
}

export interface WafAlert {
  user_id: string
  alert_id: string
  ip: string
  url: string
  status: string
  message: string
  timestamp: string
}

export interface CdnNode {
  region: 'SG' | 'JP' | 'TH'
  port: number
  status: 'online' | 'offline' | 'degraded'
  uptime_pct?: number
  cache_hit_ratio?: number
  avg_latency_ms?: number
}

export interface CdnStats {
  region: string
  request_count: number
  cache_hit: number
  cache_miss: number
  cache_bypass: number
  blocked_count: number
  avg_latency: number
}

export interface CdnLatency {
  region: string
  avg_ms: number
  p95_ms: number
  p99_ms: number
  datapoints: { time: string; latency_ms: number }[]
}

export interface CdnLog {
  region: string
  ip: string
  url: string
  method: string
  status: number
  cache_status: 'HIT' | 'MISS' | 'BYPASS'
  latency_ms: number
  datetime: string
}

export interface BlockedIP {
  ip_cidr: string
  reason: string
  blocked_at: string
  blocked_by: string
}

export interface RuleSyncStatus {
  node: string
  status: 'synced' | 'failed' | 'pending'
  last_sync: string
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
export type CacheStatus = 'HIT' | 'MISS' | 'BYPASS'
export type NodeRegion = 'SG' | 'JP' | 'TH'
export type UserRole = 'admin' | 'viewer'
```

---

## 7. State Management

### 7.1 Zustand (Global State)

```ts
// src/store/authStore.ts — Auth state เท่านั้น
// persist ลง localStorage

interface AuthStore {
  token: string | null
  user: User | null
  isAuthenticated: boolean
  setSession: (token: string, user: User) => void
  clearSession: () => void
}
```

### 7.2 React Query (Server State)

```ts
// Polling intervals
const POLL_DASHBOARD  = 5_000   // ms — Dashboard logs
const POLL_LOGS       = 8_000   // ms — Attack Logs
const POLL_CDN_NODES  = 10_000  // ms — CDN node health
const POLL_CDN_STATS  = 10_000  // ms — CDN stats
const POLL_ALERTS     = 30_000  // ms — Alerts table

// Query Keys (ใช้ consistent)
const queryKeys = {
  logs:      (limit: number) => ['logs', limit],
  rules:     () => ['rules'],
  alerts:    (limit: number) => ['alerts', limit],
  cdnNodes:  () => ['cdn', 'nodes'],
  cdnStats:  (region?: string) => ['cdn', 'stats', region ?? 'ALL'],
  cdnLogs:   (region: string, limit: number) => ['cdn', 'logs', region, limit],
  cdnLatency:(region: string, period: string) => ['cdn', 'latency', region, period],
  users:     () => ['users'],
}
```

### 7.3 Local State (useState)

ใช้สำหรับ:
- filter values ใน Logs page
- modal open/close
- drawer open/close
- current page (pagination)
- sort key + direction
- selected row

---

## 8. API Module Spec

```ts
// src/api/axios.ts
// Base URL: '' (ใช้ Vite proxy ใน dev, relative path ใน prod)
// Request interceptor: เพิ่ม Authorization header
// Response interceptor: handle 401 → logout, show toast สำหรับ error

// src/api/logs.ts
export const getRecentLogs = (limit: number) =>
  axios.get<{ logs: WafLog[] }>(`/api/logs/recent?limit=${limit}`)

// src/api/rules.ts
export const getRules = () =>
  axios.get<{ rules: WafRule[] }>('/api/rules/')
export const createRule = (rule: Omit<WafRule, 'id'> & { id: string }) =>
  axios.post('/api/rules/', rule)
export const updateRule = (id: string, rule: Omit<WafRule, 'id'>) =>
  axios.put(`/api/rules/${id}`, rule)
export const deleteRule = (id: string) =>
  axios.delete(`/api/rules/${id}`)

// src/api/alerts.ts
export const getRecentAlerts = (limit: number) =>
  axios.get<{ alerts: WafAlert[] }>(`/api/alerts/recent?limit=${limit}`)
export const getConnectStatus = () =>
  axios.get<{ connected: boolean; chat_id: string | null }>('/api/alerts/connect/status')
export const startConnect = () =>
  axios.post<{ code: string; bot_username: string; expires_in: number }>('/api/alerts/connect/start')
export const pollConnect = (code: string) =>
  axios.get<{ status: 'waiting' | 'connected'; chat_id?: string }>(`/api/alerts/connect/poll?code=${code}`)
export const disconnect = () =>
  axios.delete('/api/alerts/connect')

// src/api/cdn.ts
export const getCdnNodes = () =>
  axios.get<{ nodes: CdnNode[] }>('/api/cdn/nodes')
export const getCdnStats = (region = 'ALL') =>
  axios.get<CdnStats[]>(`/api/cdn/stats${region !== 'ALL' ? `/${region}` : ''}`)
export const getCdnLogs = (region = 'ALL', limit = 50) =>
  axios.get<{ logs: CdnLog[] }>(`/api/cdn/logs?region=${region}&limit=${limit}`)
export const getCdnLatency = (region = 'ALL', period = '1h') =>
  axios.get<CdnLatency[]>(`/api/cdn/latency?region=${region}&period=${period}`)
export const purgeCache = (url: string, region = 'ALL') =>
  axios.post(`/api/cdn/purge?url=${encodeURIComponent(url)}&region=${region}`)
export const getRuleSyncStatus = () =>
  axios.get<RuleSyncStatus[]>('/api/cdn/rule-sync-status')

// src/api/security.ts (Phase 5C)
export const getBlockedIPs = () =>
  axios.get<{ items: BlockedIP[] }>('/api/security/block')
export const blockIP = (ip_cidr: string, reason: string) =>
  axios.post('/api/security/block', { ip_cidr, reason })
export const unblockIP = (ip_cidr: string) =>
  axios.delete(`/api/security/block/${encodeURIComponent(ip_cidr)}`)

// src/api/auth.ts
export const getMe = () =>
  axios.get<User>('/api/auth/me')
export const login = (email: string, password: string) =>
  axios.post<{ access_token: string; user: User }>('/api/auth/login', { email, password })
export const register = (email: string, username: string, password: string) =>
  axios.post<{ access_token: string; user: User }>('/api/auth/register', { email, username, password })
export const logout = () =>
  axios.post('/api/auth/logout')
export const listUsers = () =>
  axios.get<{ users: User[] }>('/api/auth/users')
export const updateUserRole = (user_id: string, role: UserRole) =>
  axios.put(`/api/auth/users/${user_id}/role`, { role })
```

---

## 9. Error & Loading States

### 9.1 Loading States

```tsx
// ทุก API call ที่ใช้ React Query ต้องมี loading state

// Table loading: แสดง skeleton rows (3-5 rows)
// Chart loading: แสดง grey placeholder box ขนาดเดียวกับ chart
// StatCard loading: แสดง "—" แทนตัวเลข
// Page loading: แสดง full-page spinner ตรงกลาง
```

### 9.2 Error States

```tsx
// API error → แสดง EmptyState พร้อม retry button
// 401 → redirect login (axios interceptor)
// 403 → toast "ไม่มีสิทธิ์เข้าถึง"
// 404 → EmptyState "ไม่พบข้อมูล"
// 5xx → toast "Server error กรุณาลองใหม่"
```

### 9.3 Empty States

```tsx
// ทุก table/list ต้องมี empty state
// Components: EmptyState icon + title + optional subtitle

// ตัวอย่าง
<EmptyState
  icon={<ShieldIcon />}
  title="ยังไม่มี alert"
  subtitle="WAF กำลังเฝ้าระวังอยู่ 👀"
/>
```

### 9.4 Toast Notifications

```tsx
// ใช้ react-hot-toast หรือ custom toast component
// Success: สีเขียว ด้านบนขวา auto-dismiss 3s
// Error:   สีแดง ด้านบนขวา auto-dismiss 5s
// Warning: สีส้ม

// ตัวอย่าง trigger
toast.success('Rule created successfully')
toast.error('Failed to delete rule')
```

---

## 10. Permission Matrix

| Feature | Admin | Viewer |
|---------|-------|--------|
| ดู Dashboard | ✅ | ✅ |
| ดู Attack Logs | ✅ | ✅ |
| Export CSV Logs | ✅ | ✅ |
| ดู Custom Rules | ✅ | ✅ |
| เพิ่ม/แก้ไข/ลบ Rule | ✅ | ❌ |
| ดู Alerts | ✅ | ✅ |
| เชื่อมต่อ Telegram | ✅ | ✅ |
| ดู CDN Monitor | ✅ | ✅ |
| Purge Cache | ✅ | ❌ |
| Global Block IP | ✅ | ❌ |
| ดู Users & Roles | ✅ | ❌ |
| เปลี่ยน User Role | ✅ | ❌ |
| Force Rule Sync | ✅ | ❌ |

**Implementation:**
- Route guard: `<AdminRoute>` wrapper → redirect `/` ถ้า viewer
- Component level: `{isAdmin && <Button>Add Rule</Button>}`
- API level: FastAPI ตรวจ role ด้วย `require_admin` dependency

---

## 11. Build & Deployment

### Development
```bash
cd dashboard/frontend
npm run dev        # http://localhost:5173
                   # /api/* → proxy → http://localhost:8000
```

### Production Build
```bash
npm run build      # output: dashboard/frontend/dist/
```

### FastAPI Serve (Production)
```python
# dashboard/backend/main.py
app.mount("/", StaticFiles(directory="../frontend/dist", html=True), name="static")
# ต้องอยู่ท้ายสุด หลัง router ทุกตัว
```

### Environment Variables (Frontend)
```env
# .env.production (ที่ dashboard/frontend/)
VITE_API_BASE_URL=http://localhost:8000
```

---

## 12. Page-to-API-to-Phase Mapping

| Page | API Endpoints | Phase ที่เพิ่ม |
|------|--------------|----------------|
| Dashboard | `/api/logs/recent` | มีอยู่แล้ว |
| Attack Logs | `/api/logs/recent` | มีอยู่แล้ว |
| Custom Rules | `/api/rules/*` | มีอยู่แล้ว |
| Alerts | `/api/alerts/*` | มีอยู่แล้ว |
| CDN — Node Cards | `/api/cdn/nodes` | Phase 3A |
| CDN — Stats Charts | `/api/cdn/stats` | Phase 4B |
| CDN — Logs Table | `/api/cdn/logs` | Phase 4A |
| CDN — Latency Chart | `/api/cdn/latency` | Phase 4C |
| CDN — Cache Purge | `/api/cdn/purge` | Phase 1 |
| CDN — Rule Sync | `/api/cdn/rule-sync-status` | Phase 5B |
| CDN — Global Block | `/api/security/block` | Phase 5C |
| Users & Roles | `/api/auth/users` | มีอยู่แล้ว |