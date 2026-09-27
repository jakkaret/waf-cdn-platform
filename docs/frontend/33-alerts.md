---
title: "บทที่ 33 — Alert Center"
chapter: 33
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 33 — Alert Center

| ส่วน | รายละเอียด |
|---|---|
| รายการ alert | จาก `/api/alerts` (DynamoDB `waf_alerts_v2` กรองตาม origin ของผู้ใช้) รีเฟรชทุก 8 วินาที |
| ตัวกรอง | severity, สถานะการส่ง (Dispatched/…), ช่วงวันที่ (preset หรือเลือกวัน), ไปหน้าที่ต้องการ |
| รายละเอียด | Drawer แสดง IP, URL, rule, ประเภท, severity, edge, คำอธิบายจาก AI พร้อมปุ่มคัดลอก |
| Telegram | แสดงสถานะการเชื่อมต่อ Telegram ของผู้ใช้ และวิธีผูกบัญชี |
| Notification Center | กระดิ่งที่แถบบน อ่าน feed ล่าสุด |

ขั้นตอนของผู้ดูแล: ดู alert ใหม่ → เปิดรายละเอียด → ไปดู log ที่เกี่ยวข้องในหน้า Traffic Logs → ถ้าเป็นการโจมตีจริงที่ผ่านมาได้ ให้สร้างกฎ/บล็อก IP; ถ้าเป็น false positive ให้พิจารณา threshold หรือกฎยกเว้น

## แหล่งอ้างอิง (Evidence)
- `pages/Alerts.tsx`, `components/NotificationCenter.tsx`, `api/alerts.py`, `api/ai_summary.py`
