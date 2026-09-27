---
title: "บทที่ 29 — การเข้าสู่ระบบ"
chapter: 29
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 29 — การเข้าสู่ระบบ (Login)

## 29.1 ขั้นตอน

1. ผู้ใช้กรอกอีเมล/รหัสผ่านที่ `/login` → `POST /api/auth/login`
2. backend ตรวจรหัสผ่าน (Argon2) จำกัด 5 ครั้ง/นาที ส่ง JWT กลับทั้งใน body และ cookie `access_token` (HttpOnly)
3. frontend เก็บ `{token, user, isAuthenticated}` ใน `localStorage['waf_auth']` ผ่าน Zustand persist
4. ทุกคำขอ axios ใส่ `Authorization: Bearer <token>` และส่ง cookie (`withCredentials`)
5. ถ้า API ตอบ **401** interceptor ล้าง session และพาไป `/login`
6. token อายุ 60 นาที (ค่าเริ่มต้น) ไม่พบกลไก refresh token → ต้อง login ใหม่เมื่อหมดอายุ

## 29.2 Google OAuth

ปุ่ม Google → `GET /api/auth/google` → Google → `/api/auth/google/callback` → redirect ไป `/oauth-success` ซึ่งอ่าน session แล้วเข้า dashboard

## 29.3 สมัครสมาชิก

`/register` → `POST /api/auth/register` (จำกัด 10 ครั้ง/นาที)

- ผู้ใช้ **คนแรก** ของระบบได้ role `admin` อัตโนมัติ
- ผู้ใช้คนถัดไปได้ `viewer` เสมอ แม้ร้องขอ `admin`
- ผู้ใช้ Google OAuth ได้ `admin` เมื่ออีเมลอยู่ในโดเมน `ADMIN_EMAIL_DOMAIN` (ถ้าตั้งไว้) นอกนั้นได้ `viewer`
- admin เปลี่ยน role ได้ที่ `/users`

## แหล่งอ้างอิง (Evidence)
- `pages/Login.tsx`, `pages/Register.tsx`, `pages/OAuthSuccess.tsx`, `api/axios.ts`, `store/authStore.ts`, `api/auth.py`
