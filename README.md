# 🛡️ WAF Automated - Web Application Firewall Management System

ระบบ Dashboard สำหรับจัดการและติดตามการทำงานของ Web Application Firewall (WAF) ที่ใช้ ModSecurity + ML

---


🚀 การติดตั้ง

1️⃣ Clone Repository

```bash
git clone <repository-url>
cd waf_project
```

2️⃣ ติดตั้ง Python Dependencies

```bash
cd dashboard/backend
pip3 install -r requirements.txt
```

ลง FastAPI และ Uni:

```bash
cd dashboard/backend
python3 -m pip install fastapi uvicorn
หรือ 
sudo apt update
sudo apt install python3-fastapi python3-uvicorn
```

3️⃣ เริ่มต้น WAF Container

```bash
cd waf_project
docker-compose up -d
```

ตรวจสอบสถานะ:

```bash
docker-compose ps
```

4️⃣ เริ่มต้น Dashboard

```bash
cd dashboard/backend
python3 main.py
หรือ
uvicorn main:app -​-reload 
```

---

## 📖 การใช้งาน

### เข้าใช้งานระบบ

| Service | URL | คำอธิบาย |
|---------|-----|----------|
| **Dashboard** | http://localhost:8000 | หน้าแรก Overview |
| **API Docs** | http://localhost:8000/docs | Swagger UI |
| **WAF** | http://localhost:8080 | ModSecurity WAF (Reverse Proxy) |
| **DVWA** | http://localhost:8080 | Vulnerable Web App (ทดสอบ) |

---
