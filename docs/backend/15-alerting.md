---
title: "บทที่ 15 — ระบบแจ้งเตือน (Alerting)"
chapter: 15
part: "Part III — Backend"
status: VERIFIED
---

# บทที่ 15 — ระบบแจ้งเตือน (Alerting)

## 15.1 เงื่อนไขการเกิด alert

`services/log_forward.py` เรียก `dispatch_telegram_alert(event)` เมื่อ
- `status` เป็น **403** (ถูกบล็อก) หรือ **429** (เกิน rate limit) หรือ
- `severity` เป็น **CRITICAL** หรือ **HIGH**

log จาก edge ผ่าน `api/cdn.py` (ingest) ก็ส่งคำขอที่ถูกบล็อกเข้าเส้นทางเดียวกัน ทุกครั้งเรียกแบบ fire-and-forget (`asyncio.create_task`) จึงไม่หน่วง response ของ WAF

## 15.2 ขั้นตอนใน `services/telegram_listener.py::dispatch_telegram_alert`

| ลำดับ | ขั้นตอน | หมายเหตุ |
|---|---|---|
| 1 | ขอคำอธิบายภาษาคนจาก Gemini (`gemini_service.explain_attack`) | ถ้าใช้ quota หมด จะได้ข้อความสำรอง |
| 2 | หา `origin_id` จาก Host ผ่าน `waf_domains` (`domain_name-index`) | ไม่พบ → `unattributed` |
| 3 | `put_item` ลง `waf_alerts_v2` (`origin_id`, `alert_id`, ip, url, rule_id, attack_type, severity, edge_node, ai_summary …) | เรียกผ่าน `asyncio.to_thread` ไม่บล็อก event loop |
| 4 | บันทึกรูปแบบลง threat intel (ถ้า Host มีค่า) | opt-in, ไม่ระบุตัวตน |
| 5 | ส่งข้อความ HTML ผ่าน Telegram Bot API ถึงผู้ใช้ทุกคนที่มี `telegram_chat_id` | ต้องตั้ง bot token; รายชื่อผู้ใช้ cache 60 วินาที |

## 15.3 การแสดงผล

- หน้า **Alert Center** (`/alerts`) อ่านจาก `/api/alerts` ซึ่งกรองตาม origin ของผู้ใช้ (admin เห็น `unattributed`)
- **Notification feed** ใน header อ่านจาก `/api/ai/notifications/feed`

## 15.4 ข้อจำกัด

- Telegram ส่งถึง **ผู้ใช้ทุกคนที่ผูก chat id** ไม่ได้กรองตาม tenant ของ alert — ควรตรวจสอบก่อนเปิดให้ลูกค้าหลายรายใช้ Telegram (UNKNOWN ว่าตั้งใจหรือไม่)
- Gemini free tier มี quota รายวัน (พบข้อความ quota exceeded ใน journal)

## แหล่งอ้างอิง (Evidence)
- `services/log_forward.py:298–322`, `services/telegram_listener.py` (53–186), `api/alerts.py`, `api/ai_summary.py`
- `journalctl -u waf-dashboard` (Gemini quota)
