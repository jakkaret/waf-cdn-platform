---
title: "บทที่ 30 — หน้า Dashboard"
chapter: 30
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 30 — หน้า Dashboard (Security Operations Center)

หน้า `/` แบ่งเป็น 2 แท็บ ข้อมูลกรองตาม origin ที่เลือกใน `OriginSelector` (viewer เลือกได้เฉพาะ origin ของตัวเอง) และรีเฟรชอัตโนมัติทุก 5–15 วินาที

## 30.1 แท็บ Security

| ส่วน | ข้อมูล | แหล่ง |
|---|---|---|
| การ์ดสรุป | คำขอทั้งหมด, Threats Mitigated, อัตราการบล็อก ฯลฯ | `/api/analytics/...` (ClickHouse) |
| Traffic & Threat Timeline | กราฟ area/bar สลับได้ | ClickHouse |
| Detected Threat Types | ประเภทการโจมตีจาก `attack_type` | ClickHouse |
| Top Suspicious Sources | IP ที่ถูกบล็อกมากสุด | ClickHouse |
| Geographic Distribution | ประเทศจาก DB-IP (มีเครดิต DB-IP และคำเตือนว่าเป็นค่าประมาณ) | `country` ใน `access_logs` |

## 30.2 แท็บ Infrastructure

สถานะ edge node และบริการ (health) — ใช้ข้อมูลจาก `/api/cdn/*` และระบบ public status

## 30.3 หน้า Public Status (`/status`)

ไม่ต้อง login แสดงสถานะ edge ปัจจุบันและประวัติ (worker เก็บทุก 5 นาที)

## แหล่งอ้างอิง (Evidence)
- `pages/Dashboard.tsx`, `pages/StatusPage.tsx`, `api/analytics.py`, `api/public_status.py`
