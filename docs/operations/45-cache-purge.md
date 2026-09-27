---
title: "บทที่ 45 — การล้าง Cache (Purge)"
chapter: 45
part: "Part VIII — Operations"
status: PARTIAL
---

# บทที่ 45 — การล้าง Cache (Purge)

## 45.1 สถานะ

API `POST /api/cdn/purge` มีอยู่ แต่ **ยังไม่ถึง edge** (บทที่ 24): ไม่ได้ตั้ง `CDN_PURGE_API_URL` และ edge ไม่มี endpoint purge

## 45.2 วิธีที่ใช้ได้ตอนนี้

1. รอ TTL (10 นาที dynamic / 1 ชั่วโมง static)
2. ล้างทั้งหมดบน edge ด้วยมือ (มีผลทันที ทุกโดเมนบน edge นั้น) — **ยังไม่ได้ทดสอบบน production**
   ```bash
   docker exec cdn-edge-node sh -c 'rm -rf /var/cache/nginx/edge/*'
   ```
   nginx จะเติม cache ใหม่เองจากคำขอถัดไป

## 45.3 งานที่ต้องทำให้ purge สมบูรณ์ (PLANNED)

เพิ่ม endpoint purge ที่ edge (เช่น `proxy_cache_purge` หรือ service เล็กที่ลบไฟล์ตาม key) และตั้ง `CDN_PURGE_API_URL` ให้ backend ส่งไปทุก edge

## แหล่งอ้างอิง (Evidence)
- `api/cdn.py:30, 337–360`, `.env` (ไม่มี `CDN_PURGE_API_URL`)
