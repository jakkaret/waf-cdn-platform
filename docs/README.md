---
title: "คู่มือระบบ WAF + CDN Security Platform"
status: VERIFIED
---

# คู่มือระบบ WAF + CDN Security Platform

เอกสารชุดนี้อธิบาย **ระบบที่กำลังรันจริง** (ตรวจเมื่อ 2026-09-27/28, commit `c033758`) ทุกข้อความสำคัญมีสถานะ `VERIFIED` / `PARTIAL` / `PLANNED` / `UNKNOWN` / `DEPRECATED` และอ้างอิงหลักฐานได้

## เริ่มอ่านที่ไหน

| ถ้าคุณเป็น | อ่าน |
|---|---|
| ผู้บริหาร/ผู้ตรวจโครงการ | [บทที่ 01](book/01-overview.md), [บทที่ 02](book/02-capabilities.md), [Implementation Status](IMPLEMENTATION_STATUS.md) |
| ผู้ดูแลระบบ | [Part II](infrastructure/04-infrastructure-overview.md), [Part VIII Operations](operations/36-prerequisites.md), [Troubleshooting](operations/50-troubleshooting.md) |
| นักพัฒนา | [Part III Backend](backend/08-backend-overview.md), [API Reference](reference/api-reference.md), [Part VI Frontend](frontend/27-react-architecture.md) |
| ผู้ดูแลความปลอดภัย | [Part IV WAF](waf/18-nginx.md), [Deception](backend/17-deception-layer.md), [Part VII Flows](workflows/end-to-end.md) |

## โครงสร้าง

| ส่วน | ไดเรกทอรี |
|---|---|
| ข้อเท็จจริงหลัก | [SYSTEM_FACTS.md](SYSTEM_FACTS.md) |
| Part I Introduction | `book/` |
| Part II Infrastructure | `infrastructure/` |
| Part III Backend | `backend/` |
| Part IV WAF | `waf/` |
| Part V CDN | `cdn/` |
| Part VI Frontend | `frontend/` |
| Part VII Data Flows | `workflows/` |
| Part VIII Operations | `operations/` |
| Part IX Testing | `testing/` |
| Reference | `reference/` (API, Database, Glossary) |
| Diagrams (Mermaid source) | `diagrams/` |
| สถานะ / หลักฐาน / QA | [IMPLEMENTATION_STATUS](IMPLEMENTATION_STATUS.md), [TRACEABILITY](DOCUMENTATION_TRACEABILITY.md), [QA REPORT](DOCUMENTATION_QA_REPORT.md) |
| เว็บเอกสาร | `site/` (VitePress) |
| คู่มือ DOCX/PDF | `dist/` |

## การสร้างใหม่ (Rebuild)

Markdown ใน `docs/` คือต้นฉบับเดียว เว็บ DOCX และ PDF สร้างจากไฟล์ชุดนี้ด้วยสคริปต์ใน `docs/site/` ดู `docs/site/README.md`

เอกสารเก่าในโฟลเดอร์นี้ (`ARCHITECTURE.md`, `OPERATIONS.md`, `UX_AUDIT.md` ฯลฯ) เป็นบันทึกก่อนหน้า อาจล้าสมัย ให้ยึดเอกสารชุดนี้
