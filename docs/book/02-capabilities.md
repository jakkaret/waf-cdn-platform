---
title: "บทที่ 02 — ความสามารถของระบบ"
chapter: 2
part: "Part I — Introduction"
status: PARTIAL
---

# บทที่ 02 — ความสามารถของระบบ

บทนี้สรุปความสามารถที่ **มีอยู่จริง** พร้อมสถานะ แยกของที่ทำงานแล้วออกจากของที่เป็นเพียงหน้าแนวคิด (concept preview) ในหน้าเว็บ

## 2.1 ตารางสรุป

| ความสามารถ | รายละเอียดสั้น | บทที่อธิบาย | สถานะ |
|---|---|---|---|
| WAF | ModSecurity + OWASP CRS 3.3.10, Paranoia Level 1, anomaly threshold 10, ทำงานทั้งที่ edge และ Main | 19–21 | VERIFIED |
| Custom WAF rule | สร้าง/แก้/ลบกฎ ModSecurity จาก dashboard ด้วย action BLOCK / CHALLENGE / DECEIVE และ sync ไป edge ทุก 5 วินาที | 32, 43 | VERIFIED |
| Challenge | หน้า captcha และ OTP shield ผ่าน control-api (`/cdn-cgi/challenge`, `/cdn-cgi/otp-*`) | Flow C | VERIFIED (โค้ด), OTP ทางอีเมลต้องตั้ง SMTP |
| Deception | กฎ DECEIVE คืน `/etc/passwd` หรือ JSON ฐานข้อมูลปลอม origin ไม่ถูกเรียก | 17, Flow D | VERIFIED |
| CDN / Cache | nginx proxy cache บน edge, cache key รวม host, TTL 10 นาที (dynamic) / 1 ชั่วโมง (static) | 22–24 | VERIFIED |
| TLS อัตโนมัติ | Caddy on-demand TLS อนุญาตเฉพาะโดเมนที่ยืนยัน DNS แล้ว | 26 | VERIFIED |
| Origin tunnel | FRP (`frps`) และ CloudWAF tunnel ของระบบเอง ให้ origin ต่อขาออก | 25 | VERIFIED |
| Dashboard | ภาพรวม, log, origin, กฎ, IP list, rate limit, ML, alert, CDN, tunnel, ผู้ใช้, ตั้งค่า | 27–35 | VERIFIED |
| Logging | log ทุกคำขอเข้า ClickHouse (`access_logs`) ทั้งจาก Main และ edge | 14 | VERIFIED |
| Alerting | alert ลง DynamoDB `waf_alerts_v2` แยกตาม origin + Telegram + สรุปด้วย Gemini | 15 | VERIFIED |
| ML | Random Forest (ONNX) + Isolation Forest, `/predict`, `/generate-rule`, rule รออนุมัติ, threshold proposals | 16 | PARTIAL |
| Multi-tenancy | ข้อมูล log/alert/origin แยกตามเจ้าของ, สิทธิ์ owner/editor/viewer ต่อ origin | 12 | VERIFIED |
| Authentication | อีเมล/รหัสผ่าน (Argon2) + Google OAuth, JWT | 11 | VERIFIED |
| IP access list / rate limit | กฎ IP และ rate limit ต่อ path (SQLite + nginx `auth_request`) | 43 | VERIFIED (โค้ด) |
| BOLA guard | นโยบายกัน Broken Object Level Authorization สำหรับ API | 32 | PARTIAL (มี API และหน้าเว็บ, ยังไม่ได้ตรวจการบังคับใช้ที่ nginx) |
| Threat intel ข้ามลูกค้า | บันทึกรูปแบบการโจมตีแบบไม่ระบุตัวตน (opt-in) | 15 | VERIFIED (โค้ด) |
| Public status page | `/status` แสดงสถานะ edge | 30 | VERIFIED |
| GeoDNS | เลือก edge ตามประเทศของผู้ใช้ | 22 | PARTIAL — ไม่ได้อยู่ในเส้นทาง DNS สาธารณะ |

## 2.2 หน้าแนวคิด (Concepts preview)

เมนู **Concepts (preview)** ในหน้า dashboard (เฉพาะ admin) มี 13 หน้า เช่น AI Rule Composer, Quantum-safe TLS, Supply-chain monitor หน้าเหล่านี้เป็น **ต้นแบบหน้าจอ** แสดงแนวคิดในอนาคต **ไม่ได้เชื่อมกับการทำงานจริงทั้งหมด** จึงนับเป็น `PLANNED` ยกเว้นหัวข้อที่มีบทอธิบายการทำงานจริงแยกไว้ (เช่น Deception)

## 2.3 สิ่งที่ระบบ **ไม่มี** (ณ วันที่ตรวจ)

- การกระจาย edge แบบ anycast หรือมากกว่า 2 โหนด
- ระบบสำรองของเครื่อง Main (HA / failover)
- การบล็อกอัตโนมัติจากผล ML โดยไม่ผ่านการอนุมัติ

## แหล่งอ้างอิง (Evidence)
- `dashboard/frontend/src/App.tsx`, `components/layout/Sidebar.tsx`
- `dashboard/backend/main.py`, `api/*.py`, `services/*.py`
- `cdn/control-api/main.py`, `modsecurity/custom-rules/custom-deceive.conf`
- ผลทดสอบจริงใน `_evidence/runtime-2026-09-27.md`
