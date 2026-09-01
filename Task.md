---
name: WAF & CDN Project Tasks and Rules
description: Task list, active roadmap, and AI behavior rules for the WAF & CDN project
---

# 📋 Task.md — Task List & Development Rules

> **วัตถุประสงค์:** เอกสารนี้คือแหล่งอ้างอิงสถานะงาน (Task List) และกฎการเขียนโค้ด (Rules) เพื่อควบคุมคุณภาพและกระบวนการทำงานของ AI

## 🚀 1. สถานะโปรเจค (Project Status Overview)

*   **Phase 1 (Core Platform):** 100% — มี WAF Config Sync, Quota Management, Archive & Restore ครบถ้วน (เหลือแค่แผน Database Migration ไป PostgreSQL)
*   **Phase 2 (Zero-Trust Network):** 85% — ทดสอบ Tunnel Python ได้สำเร็จ (รอขยับไปใช้ Envoy xDS Control Plane เพื่อ Production Readiness)
*   **Phase 3 (Domain & SSL):** 100% — DNS Verification (Background worker) และ Caddy SSL อัตโนมัติทำงานสมบูรณ์ มีหน้า UI ดูสถานะ Certs
*   **Phase 4 (Analytics & Protection):** 100% — ClickHouse Analytics, Alert Telegram สมบูรณ์ (เหลือการปรับ Rate Limiter ให้เป็น Shared Redis)
*   **Phase 5 (QA & CI/CD):** 95% — มี E2E Tests ด้วย Playwright และ GitHub Actions 

## 🎯 2. สิ่งที่ต้องทำต่อไป (To-Do / Action Items)

- [ ] **Envoy xDS Control Plane (Phase 2):** สร้างระบบส่ง Dynamic Config ไปยัง Envoy Proxy (แทนที่ Caddy/Nginx reload ปัจจุบันในระบบ Tunnel)
- [ ] **Distributed Rate Limiting Engine (Phase 4):** เขียน Lua Script สำหรับ Redis เพื่อแชร์ค่า limit_req zone ของ Nginx ข้ามไปยังทุก Edge Node พร้อมกัน (Global Rate Limiting)
- [ ] **Database Migration (Phase 1):** ย้ายฐานข้อมูลจาก AWS DynamoDB LocalMock ไปใช้ PostgreSQL (Supabase) และปรับใช้ RLS (Row-Level Security)
- [ ] **ML Rules Accuracy Resolution:** ชี้แจงหรือรวมผลลัพธ์ของ Model Performance (Accuracy 93.40% ใน README vs 80.47% ใน metadata.json) ให้ตรงกัน

## ⚖️ 3. กฎและข้อตกลงในการพัฒนา (Development Rules)

### 💻 Code Standards (Frontend)
1.  **Strict TypeScript:** ไม่อนุญาตให้ใช้ `any` ในโค้ดใหม่ ให้ใช้ Type Interface จาก `src/types/index.ts` หรือสร้างใหม่ให้ตรงกับ Backend
2.  **State Management:** ใช้ `Zustand` สำหรับ Auth / Theme state และ `TanStack React Query` สำหรับ Data fetching และ Server state เสมอ
3.  **UI & Styling:** อิง Design System สีส้ม (`orange-500`), ฟอนต์ `font-mono` สำหรับข้อมูลเทคนิค, ใช้ TailwindCSS ห้ามเขียน Inline CSS
4.  **Error Handling:** ทุก API request ต้องมีการดักจับ Error และโชว์ผ่าน `react-hot-toast` รวมถึงแสดง Loading UI (Skeleton หรือ Spinner) ขณะโหลดข้อมูล

### ⚙️ Code Standards (Backend & System)
1.  **FastAPI Standards:** ใช้ Pydantic schemas ในการ Validate ข้อมูลเข้า/ออกเสมอ
2.  **Role Enforcement:** ตรวจสอบ Role (Admin/Viewer) ผ่าน FastAPI Dependency ทุกครั้งก่อนอนุญาตให้เรียกใช้ฟังก์ชันทำลายล้าง/เปลี่ยนแปลง
3.  **Evidence-Based Claims:** หากเกี่ยวข้องกับตัวเลข Performance ของ ML หรือสถิติ WAF ห้ามสมมติตัวเลขเอง ให้ดึงจาก Artifacts หรือ Dashboard ข้อมูลจริงเท่านั้น
4.  **No Cat command:** ไม่ใช้คำสั่ง Bash `cat` > file เพื่อแก้ไขหรือสร้างไฟล์ ให้ใช้ Tool ของ Agent เขียนตรงแทน
5.  **Preserve Comments:** ห้ามลบ Docstring, Comment หรือ Type hinting เดิมที่มีอยู่ในไฟล์ นอกเหนือจากที่ระบุให้ลบ

## 4. Workflows ประจำวันสำหรับ Developer
เมื่อทำการพัฒนาและเทส สามารถดูคำสั่งได้จาก `dev_readme.md`:
*   รัน Backend: `uvicorn main:app --port 8000 --reload`
*   รัน Frontend: `npm run dev` (port 5173)
*   รัน Tests: `npm run test:e2e` สำหรับ Playwright และ `python3 scripts/test_runner_gui.py` สำหรับ Integration
