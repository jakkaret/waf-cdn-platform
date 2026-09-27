---
title: "บทที่ 11 — การยืนยันตัวตนและการกำหนดสิทธิ์"
chapter: 11
part: "Part III — Backend"
status: VERIFIED
---

# บทที่ 11 — การยืนยันตัวตนและการกำหนดสิทธิ์ (Authentication & Authorization)

## 11.1 การเข้าสู่ระบบ

| วิธี | Endpoint | รายละเอียด | สถานะ |
|---|---|---|---|
| อีเมล + รหัสผ่าน | `POST /api/auth/login` | จำกัด 5 ครั้ง/นาที (slowapi), ตรวจรหัสผ่านแบบ Argon2 (`argon2.PasswordHasher`) | VERIFIED |
| สมัคร | `POST /api/auth/register` | สร้างผู้ใช้ใน `waf_users` | VERIFIED |
| Google OAuth | `GET /api/auth/google` → `/google/callback` → หน้า `/oauth-success` | ผู้ใช้ถูกค้นด้วย `ProviderIndex` | VERIFIED (โค้ด) |
| Telegram | `POST /api/auth/telegram` | ตรวจข้อมูลจาก Telegram ก่อนออก token | VERIFIED (โค้ด) |

## 11.2 Token

- **JWT HS256** สร้างใน `services/auth_service.py::create_access_token` อายุเริ่มต้น **60 นาที** (`JWT_EXPIRE_MINUTES`)
- payload มี `sub` = `user_id`
- ส่งกลับทั้งใน body และ **cookie `access_token`** (`httponly`, `samesite=lax`)
- ฝั่ง backend อ่าน token จาก header `Authorization: Bearer` ก่อน แล้วค่อยดู cookie (`services/rbac.py::_extract_token`)
- `get_current_user` ถอด token แล้ว **อ่านผู้ใช้จาก DynamoDB ทุกครั้ง** ถ้า role ถูกเปลี่ยนหรือผู้ใช้ถูกลบ จะมีผลทันทีกับคำขอถัดไป
- ฝั่ง frontend เก็บ session ใน `localStorage['waf_auth']` (Zustand persist)
- secret ของ JWT อ่านจาก environment (ไม่แสดงในเอกสาร) ความยาวที่พบตอนตรวจยังสั้นกว่าที่ควร → ควร rotate เป็นค่าสุ่มยาว

## 11.3 Role ระดับระบบ

| Role | ความสามารถ | ตรวจด้วย |
|---|---|---|
| `admin` | ทุกอย่าง รวมกฎทั้งระบบ, ผู้ใช้, ML, deception simulate, เห็น log/alert ทุก tenant | `require_admin` |
| `viewer` | ใช้ dashboard ได้ แต่เห็นข้อมูลเฉพาะ origin ที่ตนเป็นเจ้าของหรือได้รับสิทธิ์ | `require_viewer_or_above` |

## 11.4 สิทธิ์ระดับ origin (Team Workspace)

| ความสัมพันธ์ | ฟิลด์ใน `waf_origins` | ทำได้ |
|---|---|---|
| Owner | `admin_user_id` | ทุกอย่าง รวมลบ/กู้ origin, จัดการทีม, สร้าง credential ของ tunnel (`verify_origin_ownership`) |
| Editor | `editor_user_ids` | แก้การตั้งค่า เช่น captcha/OTP (`verify_origin_edit_access`) |
| Viewer | `viewer_user_ids` | อ่านอย่างเดียว (`verify_origin_access`) |

origin ที่สถานะ `archived` หรือ `deleted` ถือว่าไม่มีอยู่ ยกเว้นในการกู้คืน

## 11.5 จุดที่ควรรู้

- endpoint ภายในที่ nginx เรียก (`/api/deception/respond`) ใช้ **shared key** จาก `DECEPTION_INTERNAL_KEY` ไม่มีค่า default ในโค้ด ถ้าไม่ได้ตั้ง endpoint จะปฏิเสธทุกคำขอ (fail closed)
- การเรียก backend พอร์ต 8000 ตรงยังต้องผ่าน auth ของแต่ละ endpoint เหมือนเดิม แต่ไม่ผ่าน WAF

## แหล่งอ้างอิง (Evidence)
- `services/auth_service.py` (บรรทัด 18–75), `services/rbac.py` (10–140), `api/auth.py` (44–210), `api/deception.py`
