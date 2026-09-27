---
title: "บทที่ 35 — ผู้ใช้และสิทธิ์"
chapter: 35
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 35 — การจัดการผู้ใช้และสิทธิ์ (User & Permission Management)

## 35.1 หน้า Access Control (`/users`, admin เท่านั้น)

- แสดงผู้ใช้ทั้งหมดจาก `waf_users`
- เปลี่ยน role ระหว่าง `admin` / `viewer` (`authApi.updateRole`)
- ลบผู้ใช้ (`authApi.deleteUser`)

## 35.2 สิทธิ์ต่อ origin

จัดการในแท็บ Team ของ Origin Detail: owner เพิ่ม **viewer** (อ่านอย่างเดียว) หรือ **editor** (แก้การตั้งค่า shield ฯลฯ) — รายละเอียดสิทธิ์ในบทที่ 11

## 35.3 ตารางสรุปสิทธิ์

| การกระทำ | admin | viewer (owner ของ origin) | editor | viewer ของ origin |
|---|---|---|---|---|
| ดู log/alert ของ origin | ✓ (ทุก origin) | ✓ | ✓ | ✓ |
| แก้ captcha/OTP ของ origin | ✓ | ✓ | ✓ | – |
| ลบ/กู้ origin, จัดการทีม, สร้าง tunnel | ✓ | ✓ | – | – |
| สร้าง/แก้กฎ WAF (ทั้งระบบ) | ✓ | – | – | – |
| อนุมัติกฎ ML / threshold | ✓ | – | – | – |
| จัดการผู้ใช้ | ✓ | – | – | – |

## แหล่งอ้างอิง (Evidence)
- `pages/Users.tsx`, `services/rbac.py`, `api/auth.py`, `api/origins.py`
