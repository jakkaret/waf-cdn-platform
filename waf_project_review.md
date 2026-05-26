# 🛡️ WAF Automated — Project Review

## ภาพรวม (Overview)

โปรเจกต์นี้คือ **Web Application Firewall Management Dashboard** ที่รวม 3 ระบบหลักไว้ด้วยกัน:
- **ModSecurity WAF** (บน Nginx) — กรอง HTTP traffic และ detect attacks
- **Multi-Region CDN** (SG / JP / TH) — Edge nodes พร้อม Cache & Rate Limiting
- **Dashboard** (React + FastAPI) — Real-time monitoring, Rules Management, Telegram Alerts

### Tech Stack

| Layer | Technology |
|-------|-----------|
| WAF | Nginx + OWASP ModSecurity CRS |
| Backend API | FastAPI (Python 3.10+) |
| Frontend | React 18 + Vite + TypeScript + TailwindCSS |
| Database | AWS DynamoDB (Cloud) |
| Auth | JWT (HS256) + Google OAuth + Telegram Widget |
| Alerting | Telegram Bot (Telethon + Bot API) |
| Infra | Docker Compose |

---

## ✅ จุดแข็ง (Strengths)

### 1. Architecture ออกแบบมาดี
- แยก concern ชัดเจน: `api/` (routes) → `services/` (business logic) → DynamoDB
- RBAC ทำ 2 ระดับ (`admin` / `viewer`) ครอบคลุมทุก endpoint ด้วย `Depends(require_admin)`
- Log merging pipeline (Nginx access log + ModSecurity audit log) ผ่าน `request_id` เป็นแนวคิดที่ดีมาก

### 2. Security ในส่วน Auth
- ใช้ **Argon2** สำหรับ hash password (best practice ปัจจุบัน)
- Telegram login ใช้ HMAC-SHA256 verify ตาม official spec
- Token อ่านได้ทั้ง Authorization header และ HttpOnly cookie (dual support)
- Google OAuth redirect ผ่าน server-side callback — token ไม่โดน expose ใน URL โดยตรง

### 3. Log Forward Pipeline
- `tail_file()` ทำแบบ async generator — ไม่ block event loop
- Merge logic รอ access + modsec log ด้วย buffer + timeout fallback สะอาด

### 4. Design System
- มี `DESIGN.md` เป็น single source of truth สำหรับ AI และ developer อื่น
- Color system, typography, spacing เป็น token-based ครบ
- Component inventory วาง spec ไว้ชัดเจน

---

## 🔴 ปัญหาสำคัญ — Security (Critical / High)

### S1. `allow_origins=["*"]` + `allow_credentials=True` — **Critical**

```python
# main.py:29-34
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # ❌ wildcard
    allow_credentials=True,    # ❌ ร่วมกับ wildcard = CORS spec violation + security risk
    allow_methods=["*"],
    allow_headers=["*"],
)
```

CORS spec กำหนดว่า **ห้ามใช้ `*` ร่วมกับ `allow_credentials=True`** browser จะ reject request อยู่แล้ว แต่บาง HTTP client (เช่น curl, Postman) ไม่ enforce ทำให้เปิดช่องโหว่ได้
**แก้:** ระบุ origin ที่อนุญาตจริงๆ (เช่น `["http://localhost:5173", "https://yourdomain.com"]`)

---

### S2. Token ใน URL (OAuth redirect) — **High**

```python
# api/auth.py:149
resp = RedirectResponse(url=f"/oauth-success?token={token}", ...)
```

JWT token ปรากฏใน URL → ถูกบันทึกใน browser history, server access logs, Referrer header
**แก้:** ใช้ HttpOnly cookie อย่างเดียว หรือ redirect ไปหน้า `oauth-success` แล้วให้ frontend เรียก `/api/auth/me` ผ่าน cookie แทน

---

### S3. Role Hardcode สำหรับ Google Domain — **Medium**

```python
# services/auth_service.py:239
role="admin" if email.endswith("@example.com") else "viewer",
```

Domain `@example.com` ถูก hardcode ให้เป็น admin อัตโนมัติ — ควรลบออกหรือทำผ่าน env variable

---

### S4. `subprocess` ไม่มี validation เพิ่มเติม — **Medium**

```python
# services/rule_manager.py:21-23
subprocess.run(["docker", "exec", "waf-nginx", "nginx", "-s", "reload"], check=True)
```

Arguments เป็น list (ปลอดภัยกว่า shell=True) แต่ backend process ต้องมีสิทธิ์รัน `docker exec` ซึ่งเท่ากับ root บนระบบ — ควร review permission model นี้

---

### S5. `_pending` dict เก็บใน memory — **Low/Medium**

```python
# api/alerts.py:12
_pending: dict = {}
```

ถ้า server restart → pairing codes ทั้งหมดหาย และไม่ได้ cleanup อย่างถูกต้อง (update logic ใน connect_start ผิด)

```python
# บรรทัด 58-61 — logic นี้ผิด (ไม่ได้ลบ key เก่า แต่สร้าง dict ใหม่แล้วทิ้ง)
_pending.update({
    k: v for k, v in _pending.items()
    if v.get("user_id") != user_id
})
```
ควรเปลี่ยนเป็น: `_pending = {k: v for ...}` หรือใช้ Redis

---

## 🟡 ปัญหาด้าน Code Quality (Medium)

### Q1. DynamoDB Scan ทุก query — Performance Issue

```python
# services/auth_service.py:78-86
def get_user_by_email(self, email: str):
    resp = self.users_table.scan(FilterExpression=Attr("email").eq(email))
```

**ทุก** user lookup ทำ full table scan — ค่าใช้จ่ายสูงมากเมื่อ data โต
**แก้:** สร้าง GSI (Global Secondary Index) บน `email` field ใน DynamoDB แล้วใช้ `query()` แทน

---

### Q2. CDN logs endpoint fetch 2000 rows แล้ว filter ใน Python

```python
# api/cdn.py:178
all_logs = db.get_logs(limit=2000)
cdn_logs_list = [log for log in all_logs if log.get("source") == "cdn"]
```

ดึง 2000 records มา filter ใน application memory — ควร filter ที่ DynamoDB โดยตรงด้วย `FilterExpression`

---

### Q3. `DynamoDBService` instantiate ซ้ำใน request scope

```python
# api/cdn.py:176
db = DynamoDBService()  # สร้างใหม่ทุก request!
```

บาง endpoint สร้าง `DynamoDBService()` ทุก request แทนที่จะ share instance — ควรใช้ dependency injection หรือ singleton

---

### Q4. Debug print ในโค้ด production

```python
# services/telegram_listener.py:83
print("DEBUG logs:", logs)
# log_forward.py:142, 162, 205, 233
print("🔥 MERGED:", key)
print("ACCESS:", key)
```

ควรเปลี่ยนเป็น `logging` module ที่มี log level control แทน `print()`

---

### Q5. Duplicate comment blocks

```python
# log_forward.py — มี comment block ซ้ำกัน 2 ครั้ง
# PROCESS ACCESS (บรรทัด 191-193 และ 194-213)
# PROCESS MODSEC (บรรทัด 219-221 และ 222-241)
# WORKER (บรรทัด 247-249 และ 250-258)
```

---

### Q6. Frontend UI components ไม่ครบตาม DESIGN.md spec

DESIGN.md ระบุ component เหล่านี้แต่ยังไม่พบในโค้ด:
- `SeverityBadge`, `StatusBadge`, `Table`, `Pagination`, `Drawer`, `Modal`, `EmptyState`, `LoadingSpinner`, `SearchInput`, `FilterSelect`, `CodeBlock`, `ConfirmDialog`

`/src/components/ui/` มีแค่: `Badge`, `Button`, `Card`, `HealthDot`, `StatCard`

---

### Q7. scikit-learn ใน requirements.txt แต่ไม่ได้ใช้

```
# requirements.txt:32
scikit-learn==1.3.2
```

ไม่พบการใช้งานในโค้ด — เพิ่ม dependency โดยไม่จำเป็น (ขนาด ~30MB)

---

### Q8. `dynamodb_service.py` มี debug code ที่รัน module-level

```python
# dynamodb_service.py:149-178
if __name__ == "__main__":
    db = DynamoDBService()
    db.save_alert(...)
    print(db.get_alerts())  # method นี้ไม่มีใน class!
```

`get_alerts()` ถูกเรียกแต่ไม่ได้ define → จะ crash ถ้า run module โดยตรง

---

## 🔵 ข้อเสนอแนะเพิ่มเติม (Recommendations)

### R1. เพิ่ม Rate Limiting สำหรับ Auth endpoints

ยังไม่มี rate limiting บน `/api/auth/login` และ `/api/auth/register` — เสี่ยง brute force
แนะนำ: `slowapi` library สำหรับ FastAPI

### R2. เพิ่ม Input Validation ที่ ModSecurity Rule operator

```python
# rule_manager.py — ไม่มี sanitize operator string
operator: str  # user input โดยตรง → ควร validate รูปแบบ
```

### R3. Telegram Alert Worker ดึง user list ทุก 5 วินาที

```python
# telegram_listener.py:89-91 — scan table ทุก loop
users = db.dynamodb.Table("waf_users").scan(
    FilterExpression=Attr("telegram_chat_id").exists()
).get("Items", [])
```

ควร cache ไว้ชั่วคราว (เช่น 60 วินาที) แล้ว invalidate เมื่อมีการ connect/disconnect

### R4. Frontend ยังไม่มี Error Boundary

ถ้า API down → component crash โดยไม่มี fallback UI

### R5. ไม่มี tests เลย

ควรเพิ่ม pytest สำหรับ services layer และ Vitest สำหรับ React components อย่างน้อย critical path

---

## 📊 สรุป Priority

| Priority | รายการ | Impact |
|----------|--------|--------|
| 🔴 Critical | S1 — CORS wildcard + credentials | Security |
| 🔴 High | S2 — JWT token ใน URL | Security |
| 🟠 Medium | S3 — Hardcoded admin domain | Security |
| 🟠 Medium | Q1 — DynamoDB scan ทุก query | Performance |
| 🟠 Medium | S5 — _pending cleanup bug | Correctness |
| 🟡 Low-Medium | Q2, Q3 — CDN scan + DynamoDB instantiation | Performance |
| 🟡 Low | Q4–Q8 — Code hygiene | Maintainability |
| 🔵 Nice | R1–R5 — Improvements | Quality |

---

## 🏁 สรุป

โปรเจกต์นี้มี **architecture ที่ดีมาก** — log merging pipeline, RBAC, multi-region CDN เป็นสิ่งที่ซับซ้อนและทำออกมาได้ coherent ดี  
ปัญหาหลักที่ต้องแก้ก่อนคือ **CORS config** และ **JWT ใน URL** ซึ่งเป็น security risk ที่แก้ได้ใน 10 นาที  
Frontend ยังต้องสร้าง component library ให้ครบตาม DESIGN.md spec อีกหลายตัว
