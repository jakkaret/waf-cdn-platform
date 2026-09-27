---
title: "บทที่ 34 — การจัดการเว็บไซต์และผู้เช่า"
chapter: 34
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 34 — การจัดการเว็บไซต์และผู้เช่า (Site / Tenant Management)

## 34.1 Origin Servers (`/origins`)

รายการ origin ที่ผู้ใช้มีสิทธิ์ สถานะ, จำนวน slot ที่ใช้, ตัวกรองสถานะ, ปุ่มเพิ่ม origin (wizard ตั้งค่าโดเมน + คำแนะนำ DNS) และ archive

## 34.2 Origin Detail (`/origins/:id`)

| แท็บ | สิ่งที่ทำได้ |
|---|---|
| Pool Overview | ภาพรวม origin |
| Domains & DNS | เพิ่มโดเมน, ดูสถานะยืนยัน DNS, คำแนะนำ CNAME/TXT |
| WAF Policies | นโยบาย WAF ที่เกี่ยวกับ origin |
| SSL Certificates | สถานะใบรับรอง (`ssl_cert_monitor`) |
| Bot & Login Shield | เปิด/ตั้งค่า captcha และ OTP shield ต่อ origin |
| Team & Audit Log | เพิ่ม viewer/editor, ดู audit log |
| Incident Postmortem | สรุปเหตุการณ์ที่สร้างด้วย AI |

## 34.3 Zero Trust Tunnels (`/tunnels`)

สร้าง credential และคำสั่งติดตั้ง agent (FRP หรือ CloudWAF tunnel) ต่อ origin ดูสถานะการเชื่อมต่อ — การสร้าง credential ทำได้เฉพาะ owner

## 34.4 CDN Edge Nodes (`/cdn`)

สถานะ edge, log ของ CDN, กราฟ cache hit/บล็อก และปุ่ม purge (ดูข้อจำกัดในบทที่ 24)

## แหล่งอ้างอิง (Evidence)
- `pages/Origins.tsx`, `pages/OriginDetail.tsx`, `pages/Tunnels.tsx`, `pages/CDN.tsx`, `components/DomainSetupWizard.tsx`
