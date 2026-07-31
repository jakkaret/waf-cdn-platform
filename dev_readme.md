# 🛠️ WAF + CDN Platform — Developer Run Guide (คู่มือนักพัฒนา)

ไฟล์นี้รวบรวมคำสั่งที่ใช้ในการติดตั้ง เริ่มต้นระบบ จัดการ และทดสอบการทำงานของระบบ WAF + CDN Platform v2.0 ทั้งหมดในที่เดียว

---

## 🏗️ 1. เริ่มต้น Infrastructure (Core Stack)

ใช้ Docker Compose ในการเริ่มต้น Core Service ทั้งหมด (Nginx WAF, Caddy, Redis, ClickHouse, DynamoDB Local, และ target app: DVWA)

```bash
# รัน Core Stack ในเบื้องหลัง (Background)
docker compose up -d

# ตรวจสอบสถานะการทำงานของ Containers
docker compose ps

# หยุดการทำงานและลบ Containers ทั้งหมด
docker compose down
```

---

## 🌐 2. เริ่มต้น CDN Edge Stack (SG/JP/TH Nodes)

CDN nodes ทั้ง 3 ภูมิภาคถูกแยกอยู่ใน stack ต่างหาก สามารถเลือกเปิดทีละส่วนหรือใช้สคริปต์ช่วยจัดการ:

```bash
# ใช้ Bash Script เมนูจัดการ CDN ทั้งหมด (รัน Origin, รัน CDN Stack, Test routing)
./run_cdn_stack.sh

# หรือ สตาร์ทแบบ manual ผ่าน Docker Compose
docker compose -f cdn/docker-compose-cdn.yml up -d --build
```

### การเช็คสถานะ Health ของ Edge แต่ละโหนด:
```bash
# Singapore Node
curl -s http://localhost:8081/healthz

# Japan Node
curl -s http://localhost:8082/healthz

# Thailand Node
curl -s http://localhost:8086/healthz
```

---

## 🐍 3. เริ่มต้น Backend API Server (FastAPI)

จัดการ Database, Authentication, Logging, และ APIs ทั้งหมด

```bash
cd dashboard/backend

# 1. ติดตั้ง virtual environment
python3 -m venv .venv
source .venv/bin/activate  # (Windows: .venv\Scripts\activate)

# 2. ติดตั้ง dependencies
pip install -r requirements.txt

# 3. รัน backend API server (Uvicorn)
python main.py
# หรือ รันในโหมด reload สำหรับพัฒนา
uvicorn main:app --port 8000 --reload
```

### Background Workers (สำหรับ Log & DNS):
ในสภาพแวดล้อม Production หรือทดสอบฟีเจอร์เต็มรูปแบบ ต้องรัน workers เพิ่มเติม:
```bash
# รันตัวดึง CDN Edge logs เข้า ClickHouse (Ingest pipeline)
python3 -c "import asyncio; from services.cdn_log_forward import cdn_log_forward_worker; asyncio.run(cdn_log_forward_worker())"

# รันตัวตรวจสอบ DNS Verification สำหรับ Custom Domains
python3 -c "import asyncio; from services.dns_verification_worker import dns_verification_worker; asyncio.run(dns_verification_worker())"
```

---

## ⚛️ 4. เริ่มต้น React Frontend Dashboard (Vite)

หน้าจอสำหรับจัดการโฮสต์ โดเมน และแสดงสถิติ

```bash
cd dashboard/frontend

# 1. ติดตั้ง dependencies
npm install

# 2. รันหน้าจอยุคพัฒนา (Development server - hot reloading ที่ port 5173)
npm run dev

# 3. ตรวจสอบ Type error / Build สำหรับ Production
npm run build

# 4. ทดลองรันตัว preview ของ Build ล่าสุด (Production preview)
npm run preview
```

---

## 🔒 5. การรัน Zero-Trust WAF Tunnel

ระบบเชื่อมต่อ WAF Agent จากเครื่อง Origin ภายในบ้านเข้าหา WAF Edge Server โดยตรงโดยไม่ต้องเปิด Public IP

```bash
# 1. รัน Server (รอรับการเชื่อมต่อจาก Client/Agent)
python3 scripts/waf_tunnel_server.py

# 2. รัน Agent/Client บนฝั่งเครื่องต้นทาง (Origin)
python3 scripts/waf_tunnel_agent.py --token <WAF_TOKEN> --local-port 80
```

---

## 🔄 6. การ Sync กฎ WAF ไปยัง CDN Edge Nodes

ดึง Rules ล่าสุดจาก Dashboard API แล้วแปลงเป็น ModSecurity `.conf` อัปโหลดไป Edge Nodes และสั่ง Nginx Reload อัตโนมัติ

```bash
# 1. รันผ่าน python script โดยตรง (ต้องแนบ JWT auth token)
python3 scripts/sync_waf_rules.py --token <JWT_TOKEN>

# 2. รันแบบ Dry-run เพื่อตรวจสอบความถูกต้องของ configuration ก่อนอัปเดตจริง
python3 scripts/sync_waf_rules.py --token <JWT_TOKEN> --dry-run
```
*(หมายเหตุ: สามารถกดปุ่ม **"🔄 Sync to Edge Nodes"** ในหน้า Custom Rules บน Dashboard ได้เช่นกัน)*

---

## 🧪 7. การทดสอบระบบ (Testing & Verification)

### 🖥️ การรัน GUI Test Runner (มีแบบทดสอบ 14 รูปแบบในตัว)
ตัวทดสอบที่ครอบคลุมถึง Cache, Purge, DNS, TLS, WAF, Failover, Rate-limit
```bash
# รัน GUI สำหรับทดสอบ (มีเมนูแปลไทย)
python3 scripts/test_runner_gui.py
```

### 🎭 การรัน E2E Tests ด้วย Playwright (Frontend & Auth Flows)
ทดสอบ UI ตั้งแต่การ Register -> Login -> การเพิ่มและจัดการ Origin -> ตรวจสอบโควตา
```bash
cd dashboard/frontend

# รัน E2E test ในเบื้องหลัง (Headless mode)
npm run test:e2e

# รันพร้อมหน้าต่าง Browser จริง (Headed mode)
npm run test:e2e:headed

# รันด้วยระบบโต้ตอบของ Playwright (UI Mode)
npm run test:e2e:ui
```
