---
title: "บทที่ 32 — การจัดการกฎ"
chapter: 32
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 32 — การจัดการกฎ (Rule Management)

## 32.1 หน้า WAF Rules (`/rules`)

| ความสามารถ | รายละเอียด | ผู้ใช้ |
|---|---|---|
| ดูรายการ | อ่านไฟล์ `custom-*.conf`/`ml-*.conf` ผ่าน `GET /api/rules/` แสดง ID, variable, operator, severity, **action** | admin, viewer |
| กรอง | ตาม variable และ severity | ทุกคน |
| สร้าง / แก้ไข | Drawer ฟอร์ม: Rule ID, Target Variable (`REQUEST_URI`, `ARGS`, `REQUEST_HEADERS`, `REQUEST_BODY`), Severity, Operator (`@rx ...`), Message, **Rule Action**, **Deception Template** | admin (backend บังคับ) |
| ลบ | `DELETE /api/rules/{id}` | admin |
| Sync | `POST /api/rules/sync` | admin |
| Blast radius | `POST /api/rules/blast-radius` ประเมินผลกระทบกับ traffic จริงก่อนใช้กฎ | admin |

**Action**
| ค่า | ผลใน ModSecurity | หมายเหตุ |
|---|---|---|
| BLOCK | `phase:2,deny,status:403` | ค่าเริ่มต้น |
| CHALLENGE | `phase:2,deny,status:401,tag:'action:challenge'` | ส่งไป captcha/OTP |
| DECEIVE | `phase:1,deny,status:418,tag:'action:deceive'` | template: Auto, Fake /etc/passwd, Fake SQL JSON; ใช้กับ `REQUEST_BODY` ไม่ได้ |

การบันทึกกฎรัน `nginx -t` ก่อน reload ถ้าไม่ผ่านจะคืนกฎเดิม ข้อความ/operator ที่มีขึ้นบรรทัดใหม่ถูกปฏิเสธ

> ไม่มีปุ่มเปิด/ปิด (enable/disable) กฎแยก — ปิดกฎด้วยการลบ

## 32.2 หน้าอื่นที่เกี่ยวกับกฎ

| หน้า | หน้าที่ | สถานะ |
|---|---|---|
| API Security (BOLA) `/bola` | จัดการนโยบาย BOLA (`/api/rules/bola/policies`) | PARTIAL |
| IP Access List `/ip-rules` | allow/deny IP (SQLite) | VERIFIED (โค้ด) |
| Rate Limiting `/rate-limits` | กฎจำกัดอัตราต่อ path | VERIFIED (โค้ด) |
| ML Anomaly Rules `/ml-rules` | อนุมัติ/ปฏิเสธ/ลบกฎที่ ML เสนอ, สแกน CVE | VERIFIED |
| Tuning Proposals `/threshold-proposals` | สร้าง/อนุมัติ/ปฏิเสธ/rollback ข้อเสนอ threshold | VERIFIED |

## แหล่งอ้างอิง (Evidence)
- `pages/Rules.tsx`, `pages/BolaRules.tsx`, `pages/IPRules.tsx`, `pages/RateLimiting.tsx`, `pages/MLRules.tsx`, `pages/ThresholdProposals.tsx`, `services/rule_manager.py`
