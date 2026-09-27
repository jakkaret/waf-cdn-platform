---
title: "บทที่ 31 — Security Logs"
chapter: 31
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 31 — หน้า Traffic Logs

## 31.1 การค้นหาและกรอง

| ตัวกรอง | ที่มาของตัวเลือก |
|---|---|
| Status code, Severity, Method | `GET /api/logs/filters` (ค่าที่มีจริงใน ClickHouse) |
| คำค้น | ข้อความใน URL/IP |
| Origin | `OriginSelector` (tenant filter ที่ backend) |

ตารางแบ่งหน้า (first/prev/next/last มี `aria-label`) รีเฟรชทุก 6 วินาที

## 31.2 ดูรายละเอียด (Drawer)

คลิกแถวหรือปุ่ม "Inspect" เปิด Drawer ด้านขวาโดยตารางยังมองเห็นอยู่ แสดง IP, เวลา, method, URL, status, severity, rule ที่ทำงาน และมีปุ่ม
- **AI Explain Log** → `GET /api/logs/explain/{log_id}` (อธิบายด้วย AI)
- **PII Mask Preview** → `POST /api/logs/mask-preview` (แสดง payload ที่ปิดข้อมูลส่วนบุคคล)

Drawer รองรับคีย์บอร์ด (Escape ปิด, Tab วนในแผง, คืน focus ให้ปุ่มเดิม)

## แหล่งอ้างอิง (Evidence)
- `pages/Logs.tsx`, `api/logs.ts`, `components/ui/Drawer.tsx`, `useDialog.ts`, `dashboard/backend/api/logs.py`
