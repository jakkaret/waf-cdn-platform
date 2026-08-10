# 🛡️ WAF Automated - Web Application Firewall & CDN Management System

ระบบ Dashboard แบบ Single Page Application (React + Vite) สำหรับจัดการและติดตามการทำงานของ Web Application Firewall (WAF) ที่ใช้ ModSecurity, จัดการ Multi-Region CDN Architecture และระบบตรวจจับภัยคุกคามด้วย Machine Learning (Random Forest + Isolation Forest)

---

## ✨ Features
- **Real-time WAF Monitoring:** ติดตามเหตุการณ์การโจมตี (Attack Logs) และการบล็อก (403 Forbidden) แบบเรียลไทม์
- **CDN Global Monitor:** ตรวจสอบ Health Status และ Cache Hit/Miss/Bypass ของ CDN Edge Nodes ในแต่ละภูมิภาค (SG, JP, TH)
- **Custom Rules Management:** จัดการ ModSecurity Rules แบบกราฟิกผ่าน Dashboard
- **Telegram Alerts:** ผูกบัญชีกับ Telegram Bot เพื่อรับการแจ้งเตือนทันทีเมื่อเกิดเหตุการณ์ร้ายแรง
- **🤖 AI/ML Anomaly Detection:** ตรวจจับพฤติกรรมผิดแปลกและการโจมตีเว็บ (SQLi, XSS, Path Traversal, RCE) ด้วย Machine Learning **Accuracy 93.40% (ROC-AUC 0.9895)**
- **⚙️ Auto ModSecurity SecRule Generator:** ระบบสกัด Signature และสร้างกฎ ModSecurity `SecRule` บันทึกลงระบบ WAF อัตโนมัติใน 1 คลิก
- **Modern UI/UX:** หน้าจอ Dashboard ออกแบบด้วย TailwindCSS & Cyber Obsidian Theme (Glassmorphism) สวยงาม รวดเร็ว

---

## 🚀 การติดตั้งและรันระบบ

### 📋 Prerequisites
ก่อนเริ่มต้น กรุณาตรวจสอบว่าคุณได้ติดตั้งโปรแกรมต่อไปนี้:
- **Docker & Docker Compose** (สำหรับรัน WAF, โหนด CDN, และ Mock Services)
- **Python 3.10+** (สำหรับ FastAPI Backend & ML Pipeline)
- **Node.js 20+ & npm** (สำหรับ React Frontend)

---

### 1️⃣ เริ่มต้น Infrastructure (WAF & CDN Nodes)
ระบบจำเป็นต้องมี Container ต่างๆ ทำงานอยู่ (เช่น Nginx WAF, DynamoDB-local, Node Edges)

```bash
# สตาร์ทโปรเจกต์ทั้งหมดผ่าน Docker Compose
cd waf_project
docker-compose up -d

# หรือในกรณีที่มี CDN stack แยก
docker-compose -f cdn/docker-compose-cdn.yml up -d
```

ตรวจสอบสถานะว่า container รันสำเร็จ:
```bash
docker-compose ps
```

---

### 2️⃣ ติดตั้งและเริ่มต้น React Frontend
Frontend ถูกพัฒนาด้วย React 18 และ Vite หากมีการแก้ไขโค้ดฝั่ง UI ต้องสั่ง Build ก่อน เพื่อให้ Backend นำไฟล์ไป serve ได้

```bash
cd dashboard/frontend

# ติดตั้ง dependencies
npm install

# รันโหมด Development (Hot Reloading รันที่พอร์ต 5173)
npm run dev

# ** หรือ Build เพื่อใช้งานจริง ** (จำเป็นต้องทำก่อนรัน Backend ในโหมด Production)
npm run build
```
*(หมายเหตุ: หากคุณรัน `npm run dev` Vite จะทำการ Proxy API requests ไปยัง `http://localhost:8000` ให้อัตโนมัติ)*

---

### 3️⃣ เริ่มต้น FastAPI Backend Main Dashboard
Backend ทำหน้าที่เป็น API Server และเสิร์ฟไฟล์ React Frontend ที่ถูก build แล้ว (SPA)

```bash
cd dashboard/backend

# สร้างและเข้าสู่ Virtual Environment
python3 -m venv .venv
source .venv/bin/activate

# ติดตั้ง Python Dependencies
pip install -r requirements.txt

# สตาร์ท Backend API Server (พอร์ต 8000)
python main.py
```

---

### 4️⃣ เริ่มต้น Machine Learning & Auto Rule Generator Service 🧠

บริการ ML (Random Forest + Isolation Forest) สำหรับทำนายผล Anomaly Score และ Auto Generate WAF SecRule:

```bash
# เปิดใช้งาน Virtual Environment หลักของโปรเจกต์
cd /home/chirachot/seminar/waf_project
source .venv/bin/activate

# 1. คำสั่งเทรนโมเดลใหม่ (Multi-Dataset High-Accuracy):
python ml/train_model.py

# 2. คำสั่งรัน ML API & Interactive Web Dashboard (พอร์ต 5000):
python ml/ml_api.py

# 3. คำสั่งทดสอบทำนายผลผ่าน CLI:
python ml/evaluate_model.py

# 4. คำสั่งรัน Real-time Log Stream Analyzer (Worker):
python ml/async_log_analyzer.py
```

*(หมายเหตุ: หากรันจาก Windows PowerShell สามารถรันคำสั่ง: `wsl env PYTHONPATH=/home/chirachot/seminar/waf_project /home/chirachot/seminar/waf_project/.venv/bin/python ml/ml_api.py`)*

---

## 📖 การใช้งานระบบ

เมื่อเปิดบริการเรียลไทม์แล้ว คุณสามารถเข้าถึงบริการต่างๆ ได้ตาม URL ด้านล่างนี้:

| Service | URL | คำอธิบาย |
|---------|-----|----------|
| **Dashboard (Main UI)** | http://localhost:8000 | เข้าสู่หน้าจอหลักของ WAF & CDN Dashboard |
| **🤖 ML Dashboard & Auto Rule Generator** | **http://localhost:5000** | **หน้าจอ WAF ML Anomaly Predictor & Auto SecRule Generator** |
| **Frontend Dev Server** | http://localhost:5173 | สำหรับนักพัฒนา (ต้องรัน `npm run dev`) |
| **API Docs (Main Backend)** | http://localhost:8000/docs | FastAPI Swagger UI สำหรับทดสอบ Main REST API |
| **API Docs (ML Service)** | http://localhost:5000/docs | FastAPI Swagger UI สำหรับ ML Predict & Auto Rule API |
| **WAF Proxy** | http://localhost:8080 | ทางเข้าหลักของ ModSecurity WAF |
| **DVWA (Test Target)** | http://localhost:8080 | Vulnerable Web App สำหรับใช้ทดสอบยิง Request |

---

## 🔐 ข้อมูลสำหรับการล็อกอินเบื้องต้น
หากคุณใช้งานระบบยืนยันตัวตน หรือ DynamoDB ในโหมดจำลอง (Local):
คุณสามารถสมัครบัญชีใหม่ผ่านหน้าเว็บ `http://localhost:8000/register` หรือใช้ Google OAuth

---

## 📄 เอกสารคู่มือและรายงานการทดสอบ ML
- 📘 **[ml_summary_and_guide.md](file:///home/chirachot/seminar/waf_project/ml_summary_and_guide.md):** รายงานการฝึกโมเดล Accuracy 93.40% และคู่มือ Auto Rule Generator
- 📙 **[ml_integration_guide.md](file:///home/chirachot/seminar/waf_project/ml_integration_guide.md):** คู่มือสถาปัตยกรรม 3 แนวทางการนำ ML ไปต่อยอดใน Production
