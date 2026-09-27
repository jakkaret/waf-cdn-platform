---
title: "บทที่ 12 — สถาปัตยกรรมหลายผู้เช่า (Multi-tenant)"
chapter: 12
part: "Part III — Backend"
status: VERIFIED
---

# บทที่ 12 — สถาปัตยกรรมหลายผู้เช่า (Multi-tenant Architecture)

```text
User (waf_users)
  ↓ role: admin | viewer
Origin (waf_origins)  ← owner = admin_user_id, ทีม = viewer_user_ids / editor_user_ids
  ↓ origin_id
Domain (waf_domains)  ← domain_name (Host header ที่ลูกค้าใช้)
  ↓
Logs (ClickHouse access_logs.host) · Alerts (waf_alerts_v2 partition = origin_id)
```

## 12.1 หลักการ

ทุกข้อมูลที่ผู้ใช้เห็นถูกกรองจาก "origin ที่ผู้ใช้มีสิทธิ์" เสมอ Admin เห็นทั้งหมด ส่วน viewer เห็นเฉพาะของตัวเอง ระบบเลือกแบบ **fail closed**: ถ้าหาขอบเขตไม่ได้จะคืน "ไม่มีข้อมูล" แทน "ข้อมูลทั้งหมด"

## 12.2 การแยก Log (ClickHouse)

`services/tenant_service.py`

1. `get_user_origins_and_domains(user_id)` รวม origin ที่ active ของผู้ใช้ แล้วดึงโดเมนจาก `waf_domains` (GSI `origin_id-index`) ผลลัพธ์ถูก cache และล้างด้วย `invalidate_tenant_cache`
2. `build_tenant_origin_filter(origin, user_domains, is_admin)` สร้าง `WHERE`:
   - admin + ไม่ระบุ origin → ไม่กรอง
   - viewer ที่ไม่มีโดเมน → `1=0` (ไม่เห็นอะไรเลย)
   - viewer ปกติ → `(host = 'a.com' OR host = 'b.com' ...)`
3. `build_domain_pattern_sql(domain)` จับคู่ด้วย `host = '<domain>'` แบบตรงตัว และสำหรับแถวเก่าที่ `host = ''` (ก่อนมีคอลัมน์ host) ใช้การเดาจาก URL keyword ซึ่งจะหมดไปเองตาม TTL 30 วัน

## 12.3 การแยก Alert (DynamoDB)

- ตาราง `waf_alerts_v2` ใช้ **partition key = `origin_id`**, sort key = `alert_id`
- ตอนสร้าง alert (`services/telegram_listener.py`) ระบบหา origin จาก Host ผ่าน GSI `domain_name-index` ถ้าหาไม่เจอ (ยิง IP ตรง, โดเมนที่ไม่ได้ลงทะเบียน) จะเก็บใน partition พิเศษ **`unattributed`** ซึ่งเฉพาะ admin เห็น
- ตาราง `waf_alerts` เดิม (key `user_id` ที่เป็นค่าคงที่) เลิกใช้แล้ว → DEPRECATED

## 12.4 การแยกทรัพยากรอื่น

| ทรัพยากร | วิธีแยก |
|---|---|
| Origin / Domain | `admin_user_id-index`, ตรวจ `verify_origin_*` ทุก endpoint ที่มี `{origin_id}` |
| Tunnel | token ต่อ origin (hash เก็บใน origin) |
| Custom WAF rule | **ใช้ร่วมกันทั้งระบบ** — ไฟล์ใน `modsecurity/custom-rules` มีผลกับทุกโดเมน สร้าง/แก้ได้เฉพาะ admin |
| Captcha / OTP shield | ตั้งค่าต่อ origin |
| Threat intel | เก็บเฉพาะรูปแบบ (pattern) แบบไม่ระบุตัวตน และต้อง opt-in |

## 12.5 ข้อจำกัดที่พบ

| ข้อจำกัด | ผลกระทบ | สถานะ |
|---|---|---|
| (แก้แล้ว 2026-09-28) เดิมเมื่อ viewer ระบุ `origin` เอง ระบบตรวจสิทธิ์ด้วยการเทียบ substring สองทาง และข้ามการตรวจเมื่อผู้ใช้ไม่มีโดเมน | ปัจจุบันใช้ `tenant_service.is_origin_owned` เทียบตรงตัว (ไม่สนตัวพิมพ์, ตัดจุดท้าย) และไม่มีโดเมน = ไม่มีสิทธิ์ ใช้ทั้ง `build_tenant_origin_filter` และ `api/logs.py` | แก้แล้ว (KNOWN_ISSUES #7) |
| (แก้แล้ว 2026-09-28) Telegram เคยส่ง alert ถึงผู้ใช้ทุกคนที่ผูก chat id | ปัจจุบันส่งเฉพาะ admin + ทีมของ origin | แก้แล้ว (KNOWN_ISSUES #8) |
| Main บันทึก IP ของ edge เป็น client IP สำหรับ traffic ที่มาทาง edge | ข้อมูล IP ใน log ของ tenant ไม่ใช่ IP จริง | ทราบแล้ว |
| กฎ WAF ใช้ร่วมกันทั้งระบบ | tenant กำหนดกฎเฉพาะของตัวเองไม่ได้ | ข้อจำกัดของการออกแบบ |

## แหล่งอ้างอิง (Evidence)
- `services/tenant_service.py` (14–166), `services/telegram_listener.py`, `services/dynamodb_service.py:207`
- `scripts/migrate_alerts_to_origin_key.py`, `services/rbac.py`
