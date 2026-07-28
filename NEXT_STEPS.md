# 🛡️ แผนการพัฒนา WAF+CDN Platform v2.0 (Roadmap & Action Items)

เอกสารนี้รวบรวมรายการสิ่งที่ต้องทำ (To-Do / Action Items) ในแต่ละระยะ (Phase) ของโครงการ **WAF+CDN Platform v2.0** เพื่อให้ทีมพัฒนาเห็นภาพรวมและเข้าใจสิ่งที่ต้องเขียนโค้ดเพิ่มเติม (Custom Build) ในแต่ละส่วนอย่างชัดเจน

---

## 📅 ภาพรวมการดำเนินงาน (Timeline Overview)

| Phase | หัวข้อระบบ | ระยะเวลา | จุดเน้นสำคัญ (Custom Build Focus) |
| :--- | :--- | :---: | :--- |
| **Phase 1** | Core Platform | 7-10 วัน | Sync Configuration, RLS Database, Business Logic (Quota/Auth), UI Component Assembly |
| **Phase 2** | Zero-Trust Network | 6-8 วัน | Envoy Control Plane (xDS), Tunnel Agent Token Validation Wrapper |
| **Phase 3** | Domain & SSL Automation | 6-8 วัน | DNS CNAME/TXT Token Matching Engine, Caddy SSL Termination Layer |
| **Phase 4** | Analytics & Advanced Protection | 5-7 วัน | Redis Sliding Window Rate Limiter (Lua), ClickHouse Analytics API |
| **Phase 5** | QA & Production Readiness | 4-6 วัน | E2E Playwright Setup & GitHub Actions CI/CD Integration |

---

## 📋 รายละเอียดสิ่งที่ต้องทำและประเด็นทางเทคนิค (Technical Checklist)

### 🛠️ Phase 1: Core Platform (พัฒนาระบบแกนกลาง)
**ระยะเวลา:** 7-10 วัน

#### 1. Core WAF Engine (Edge Nodes) ⏱️ 2 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** `Nginx + ModSecurity` (จาก `docker-compose.yml`)
* **เทคโนโลยีแนะนำ (Recommended):** `Nginx + ModSecurity` (ใช้ของเดิม เนื่องจากเสถียร รวดเร็ว และเป็นมาตรฐาน)
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] เขียนสคริปต์ Sync Configuration ระหว่าง Edge Nodes (SG/JP/TH) เพื่อให้กฎ WAF อัปเดตตรงกันเสมอเมื่อมีการเปลี่ยนแปลงบน Dashboard

#### 2. Database & Multi-tenant Schema ⏱️ 2 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** `AWS DynamoDB / MongoDB` (NoSQL)
* **เทคโนโลยีแนะนำ (Recommended):** `PostgreSQL` (Supabase / Relational DB) — ช่วยให้การ Query และ Join ข้อมูลที่ซับซ้อน (User -> Origins -> Domains -> Access Logs) ทำได้ง่ายขึ้นและประหยัดกว่า
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] ออกแบบ Database Schema และสร้างตารางที่จำเป็นสำหรับ Multi-tenant
  - [ ] เขียนกฎ Row-Level Security (RLS) เพื่อแยกสิทธิ์การมองเห็นข้อมูล (Tenant Isolation) บังคับให้ลูกค้าแต่ละรายเข้าถึงได้เฉพาะข้อมูลโดเมนของตนเองเท่านั้น

#### 3. Backend API Foundation ⏱️ 2 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** `FastAPI` (Python)
* **เทคโนโลยีแนะนำ (Recommended):** `FastAPI` (Python) หรือ `Go` — รองรับ I/O ได้ดีและสร้าง API Swagger Docs ให้อัตโนมัติ
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] สร้าง API endpoints หลักสำหรับการติดต่อระหว่าง Dashboard และ Backend
  - [ ] พัฒนา Business Logic สำหรับตรวจสอบสิทธิ์เข้าใช้งาน (Authentication / Authorisation)
  - [ ] เขียนระบบจัดการโควต้า (Quota Management) ในการเพิ่ม Origin และ Domain ของแต่ละ Tenant

#### 4. Dashboard Base UI & Design System ⏱️ 3 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** `HTML/CSS` ธรรมดา (Vanilla JS)
* **เทคโนโลยีแนะนำ (Recommended):** `React + TailwindCSS + Radix UI` — เหมาะกับการจัดการ State หน้าเว็บที่ซับซ้อน เช่น Onboarding Wizard หลายขั้นตอน และช่วยให้เขียน Reusable Components ได้ง่ายขึ้น
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] วางโครงสร้าง Layout และระบบ Design System สำหรับ Frontend
  - [ ] สร้างและประกอบ UI Components ย่อยให้ออกมาเป็น Flow การทำงานจริง (เช่น หน้าจัดรายการ, หน้าการตั้งค่า)
  - [ ] เขียนโค้ดเชื่อมต่อ UI เข้ากับ Backend API เพื่อดึงและอัปเดตข้อมูลแบบไดนามิก

---

### 🔌 Phase 2: Zero-Trust Network (ระบบเชื่อมต่อกับลูกค้า)
**ระยะเวลา:** 6-8 วัน

#### 1. Tunnel Connection Manager (ฝั่ง WAF) ⏱️ 2 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** ยังไม่มี (ขึ้นอยู่กับ Firewall ปลายทาง)
* **เทคโนโลยีแนะนำ (Recommended):** `Envoy Proxy` หรือ `HAProxy` — บริหารจัดการ Persistent HTTP/2 mTLS Connection จำนวนมากได้เสถียรและมีประสิทธิภาพสูง
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] เขียนระบบ Control Plane แบบ Real-time (ผ่าน Envoy xDS API) เพื่อส่ง Config อัปเดตไปยัง Envoy เมื่อลูกค้าทำการเพิ่มหรือลบโดเมนบน Dashboard

#### 2. WAF Tunnel Agent (ฝั่งลูกค้า) ⏱️ 3 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** ลูกค้าตั้งค่า UFW Firewall และ Nginx ด้วยตัวเอง
* **เทคโนโลยีแนะนำ (Recommended):** `Chisel` หรือ `Cloudflared` (Fork มาปรับแต่งเพิ่มเติม) — เพื่อให้ลูกค้าสร้าง Outbound mTLS Tunnel วิ่งมาที่ Edge Node ของเราโดยไม่ต้องเปิดพอร์ตขาเข้า (Zero-Trust)
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] พัฒนา Agent Wrapper (โปรแกรมครอบทับตัว Tunnel)
  - [ ] เขียนระบบดึงค่า `WAF_TOKEN` จากระบบ/ไฟล์คอนฟิกของลูกค้า แล้วส่ง API ไปตรวจสอบสิทธิ์กับระบบหลังบ้านก่อนเริ่มทำการเชื่อมต่อ Tunnel

---

### 🌐 Phase 3: Domain & SSL Automation (ระบบอัตโนมัติ)
**ระยะเวลา:** 6-8 วัน

#### 1. DNS Verification Service ⏱️ 2 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** ยังไม่มี
* **เทคโนโลยีแนะนำ (Recommended):** `Celery` (Python) + `Redis Queue` — สำหรับตรวจสอบ DNS ในแบบ Background Job ป้องกัน HTTP Request หลักค้างหรือ Timeout
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] พัฒนา Background Worker เพื่อเช็คค่า DNS Record
  - [ ] เขียนตรรกะเปรียบเทียบค่า CNAME หรือ TXT Record ที่สืบค้นได้ ว่าตรงกับ DNS Token ที่ระบบสร้างขึ้นให้สำหรับลูกค้ารายนั้นๆ หรือไม่

#### 2. Auto-provisioning SSL ⏱️ 3 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** ใช้ Bash Script วนลูปเรียก Certbot แล้วเซฟลงโฟลเดอร์
* **เทคโนโลยีแนะนำ (Recommended):** `Caddy Web Server` — ทำหน้าที่เป็น SSL Termination Layer นอกสุด จัดการการขอและต่ออายุใบรับรอง (Auto-HTTPS / Let's Encrypt) ได้อย่างปลอดภัยและทำงานอัตโนมัติ 100%
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] ติดตั้งและกำหนดค่า Caddy เป็น Edge SSL Termination Layer เพื่อรับทราฟฟิก HTTPS
  - [ ] เขียนระบบคุยต่อกับ Nginx WAF Engine ภายในผ่าน HTTP (หลังจาก Caddy ถอดรหัส SSL แล้ว)

---

### 🚦 Phase 4: Analytics & Advanced Protection (ระบบวิเคราะห์ความปลอดภัยขั้นสูง)
**ระยะเวลา:** 5-7 วัน

#### 1. Distributed Rate Limiting Engine ⏱️ 2 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** `Nginx limit_req zone` (ทำงานแยกกันตามแต่ละ Edge Node ไม่แชร์สถานะ)
* **เทคโนโลยีแนะนำ (Recommended):** `Redis + Lua Scripting` — ช่วยซิงก์สถานะจำนวน request ของแต่ละ IP ข้ามไปยังทุก Edge Node พร้อมกันได้ เพื่อการจำกัดอัตราการยิงแบบ Real-time
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] เขียน Rate Limiting Algorithm (เช่น Sliding Window) ด้วย Lua Script บน Redis
  - [ ] เขียนตัวเชื่อมโยงเพื่อส่งสัญญาณ (Flag) ไปให้ Nginx ปฏิเสธ Request ที่ยิงเกินกำหนดด้วยรหัส `429 Retry-After` ทันที

#### 2. Real-time Analytics & Access Logs ⏱️ 3 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** บันทึกลง text file (.log) หรือ AWS CloudWatch
* **เทคโนโลยีแนะนำ (Recommended):** `ClickHouse` (Time-series / Columnar DB) — เหมาะสมมากกับการจัดเก็บและ Query ข้อมูล Log ปริมาณมหาศาลได้อย่างรวดเร็วและใช้ทรัพยากรน้อยกว่า
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] พัฒนา Data Pipeline สำหรับดึง/ส่ง Access Logs จาก Edge Nodes เข้าสู่ ClickHouse
  - [ ] พัฒนา API Endpoint เพื่อคิวรีสถิติและข้อมูลการโจมตีในรูปของ JSON ส่งออกไปแสดงผลที่ Dashboard แบบเรียลไทม์ โดยไม่ส่งผลกระทบต่อประสิทธิภาพการทำงานของ Database หลัก

---

### 🤖 Phase 5: QA & Production Readiness (การทดสอบและเตรียมความพร้อม)
**ระยะเวลา:** 4-6 วัน

#### 1. Automated E2E Testing ⏱️ 2 วัน
* **สิ่งที่ใช้อยู่ปัจจุบัน (Current):** ตรวจสอบด้วยตัวเอง (Manual Testing)
* **เทคโนโลยีแนะนำ (Recommended):** `Playwright` — สำหรับทำ E2E UI Testing เลียนแบบพฤติกรรมผู้ใช้งานจริงตั้งแต่ต้นจนจบ
* **📋 สิ่งที่ต้องเขียนโค้ดเพิ่มเอง (Custom Build Tasks):**
  - [ ] เขียนสคริปต์การทดสอบ (Test Suites) ครอบคลุม Flow สำคัญ เช่น สมัครสมาชิก, ตั้งค่า Onboarding, และการเชื่อมโดเมน
  - [ ] เชื่อมต่อ Playwright เข้ากับ CI/CD (เช่น GitHub Actions) เพื่อให้รันการทดสอบโดยอัตโนมัติทุกครั้งเมื่อมีการ Push หรือ Merge โค้ดใหม่
