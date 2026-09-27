---
title: "บทที่ 01 — ภาพรวมโครงการ"
chapter: 1
part: "Part I — Introduction"
status: VERIFIED
---

# บทที่ 01 — ภาพรวมโครงการ

## 1.1 ที่มาของโครงการ

WAF + CDN Security Platform เป็นระบบป้องกันเว็บไซต์แบบ "บริการกลาง" (multi-tenant) ที่ให้เจ้าของเว็บหลายรายนำเว็บของตนมาไว้หลังระบบเดียว แนวคิดคล้ายบริการเชิงพาณิชย์อย่าง Cloudflare คือเปลี่ยน DNS ของเว็บให้ชี้มาที่โหนดขอบ (edge) ของระบบ แล้วระบบจะคัดกรองคำขอ (request) ที่เป็นอันตรายก่อนส่งต่อไปยังเครื่องต้นทาง (origin) ของลูกค้า

ระบบที่รันอยู่จริงประกอบด้วยเครื่องเสมือน (VM) 3 เครื่อง ได้แก่ เครื่องหลัก (Main) ที่ Hetzner และ edge 2 เครื่องที่ไทยกับ Azure (ดูบทที่ 05)

## 1.2 วัตถุประสงค์

| วัตถุประสงค์ | วิธีที่ระบบทำ | สถานะ |
|---|---|---|
| กันการโจมตีเว็บทั่วไป (OWASP Top 10) | ModSecurity + OWASP CRS 3.3.10 ทั้งที่ edge และ Main | VERIFIED |
| ให้เจ้าของเว็บจัดการกฎและดูเหตุการณ์ของตัวเอง | Dashboard (React) + API (FastAPI) แยกข้อมูลตาม tenant | VERIFIED |
| ลดภาระ origin และเพิ่มความเร็ว | proxy cache บน edge | VERIFIED |
| ไม่ต้องเปิดพอร์ตของ origin สู่อินเทอร์เน็ต | tunnel ขาออกจาก origin (FRP / CloudWAF tunnel) | VERIFIED |
| แจ้งเตือนทันที | บันทึก alert ลง DynamoDB + ส่ง Telegram พร้อมคำอธิบายจาก Gemini | VERIFIED |
| ตรวจจับสิ่งที่กฎไม่รู้จัก | โมเดล ML (Random Forest / Isolation Forest) และระบบเสนอกฎ | PARTIAL |
| หลอกผู้โจมตี | Deception layer คืนข้อมูลปลอม (synthetic) | VERIFIED |

## 1.3 ปัญหาที่ระบบแก้

1. **เว็บขนาดเล็กไม่มี WAF** — การตั้ง ModSecurity เองต้องใช้ความรู้สูง ระบบนี้ให้บริการแบบตั้งครั้งเดียวที่ DNS
2. **origin ถูกยิงตรง** — เมื่อใช้ tunnel ขาออก origin ไม่ต้องมี IP สาธารณะ จึงเลี่ยง WAF ไม่ได้
3. **มองไม่เห็นการโจมตี** — log ทุกคำขอถูกเก็บใน ClickHouse และแสดงบน dashboard ตาม tenant
4. **กฎคงที่ตามไม่ทัน** — ML ช่วยเสนอกฎใหม่ให้ผู้ดูแลอนุมัติ (human-in-the-loop)

## 1.4 ผู้ใช้ที่คาดหวัง

| กลุ่มผู้ใช้ | สิ่งที่ทำ | Role ในระบบ |
|---|---|---|
| ผู้ดูแลระบบ (platform admin) | จัดการกฎทั้งระบบ, ผู้ใช้, ML, edge | `admin` |
| เจ้าของเว็บ (tenant) | เพิ่ม origin/โดเมน, ดู log/alert ของตัวเอง, สร้าง tunnel | `viewer` + owner ของ origin |
| ผู้ร่วมทีมของเจ้าของเว็บ | ดูหรือแก้ไข origin ที่ได้รับสิทธิ์ | `viewer_user_ids` / `editor_user_ids` ของ origin |

## 1.5 ขอบเขตระบบ (Scope)

**อยู่ในขอบเขต:** การคัดกรอง HTTP/HTTPS, TLS อัตโนมัติ, cache, dashboard, log, alert, ML ช่วยเสนอกฎ, deception, tunnel

**นอกขอบเขต / ไม่พบหลักฐาน:** การป้องกัน DDoS ระดับเครือข่าย (L3/L4), anycast, edge มากกว่า 2 จุด, high availability ของเครื่อง Main

## 1.6 ข้อจำกัดหลัก

- เครื่อง Main รวม WAF หลัก, backend และฐานข้อมูลไว้ที่เดียว หากล่มจะกระทบทั้งระบบ
- ภาค ML ยังเป็นระบบช่วยตัดสินใจ ไม่ได้บล็อกเองโดยอัตโนมัติ (ดูบทที่ 16)
- ข้อจำกัดด้านความปลอดภัยที่ทราบแล้วสรุปไว้ใน [SYSTEM_FACTS §7](../SYSTEM_FACTS.md)

## แหล่งอ้างอิง (Evidence)
- `docs/SYSTEM_FACTS.md`, `docs/_evidence/runtime-2026-09-27.md`
- `docker-compose.yml`, `cdn/edge/`, `dashboard/backend/main.py`
