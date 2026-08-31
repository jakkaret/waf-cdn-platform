# 🛡️ WAF & CDN Management System - Complete Cloud Deployment Guide
> **คู่มือการติดตั้งและตั้งค่าระบบ Web Application Firewall (WAF) & CDN Management System บนระบบคลาวด์ฉบับสมบูรณ์**

---

## 📑 สารบัญ (Table of Contents)
1. [ภาพรวมสถาปัตยกรรมระบบ (Architecture Overview)](#1-ภาพรวมสถาปัตยกรรมระบบ)
2. [วิเคราะห์และแก้ไขปัญหาพอร์ต 8000 & 8080 (Troubleshooting Diagnosis)](#2-วิเคราะห์และแก้ไขปัญหาพอร์ต-8000--8080)
3. [คู่มือการติดตั้งทีละขั้นตอน (Step-by-Step Deployment Commands)](#3-คู่มือการติดตั้งทีละขั้นตอน)
4. [การตั้งค่า SSL และ Domain Name (Caddy SSL Automation)](#4-การตั้งค่า-ssl-และ-domain-name)
5. [การรักษาความปลอดภัยและการตั้งค่า Firewall (Security & Ports)](#5-การรักษาความปลอดภัยและการตั้งค่า-firewall)
6. [คำสั่งเช็กความถูกต้องและผลลัพธ์ที่ควรได้ (Health Check Suite)](#6-คำสั่งเช็กความถูกต้องและผลลัพธ์ที่ควรได้)

---

## 1. ภาพรวมสถาปัตยกรรมระบบ

ระบบ **WAF & CDN Management System** ประกอบไปด้วยส่วนประกอบหลัก (Microservices) ที่ทำงานร่วมกัน:

```
                          ┌─────────────────────────────────────────┐
                          │    Internet Users / Attack Vectors      │
                          └───────────────────┬─────────────────────┘
                                              │
                                              ▼
                          ┌─────────────────────────────────────────┐
                          │   Caddy Reverse Proxy (SSL/HTTPS 443)   │
                          └───────────────────┬─────────────────────┘
                                              │
                                              ▼
                          ┌─────────────────────────────────────────┐
                          │   Nginx + ModSecurity WAF (Port 8080)   │
                          │   - OWASP Core Rule Set Inspection      │
                          │   - Rate Limit Check via Port 8000      │
                          └─────────┬───────────────────┬───────────┘
                                    │                   │
                                    ▼                   ▼
                  ┌───────────────────┐       ┌───────────────────┐
                  │ Web App Target    │       │ ClickHouse Log DB │
                  │ (DVWA / Backend)  │       │ (Port 8123/9000)  │
                  └───────────────────┘       └─────────┬─────────┘
                                                        │
                                                        ▼
                                              ┌───────────────────┐
                                              │ FastAPI Backend   │
                                              │ (Port 8000 Python)│
                                              └───────────────────┘
```

---

## 2. วิเคราะห์และแก้ไขปัญหาพอร์ต 8000 & 8080

### ❓ ทำไมถึงเจอ `Failed to connect to localhost port 8000`?
- **สาเหตุ:** ตัว **FastAPI Backend (`main.py`)** ยังไม่ได้ถูกสั่งรันบน VPS (ใน `docker-compose.yml` มีเฉพาะ WAF, Caddy, Redis, ClickHouse, DVWA)

### ❓ ทำไมพอร์ต 8080 ถึงเจอ `HTTP/1.1 500 Internal Server Error`?
- **สาเหตุ:** Nginx WAF (พอร์ต 8080) มีคอนฟิกเช็ก Rate Limit ไปที่ `http://host.docker.internal:8000/api/limiter/check` ทุกครั้งที่มี Request พอพอร์ต 8000 ยังไม่ถูกเปิด Nginx จึงเชื่อมต่อไม่ได้และตีกลับเป็น **500 Internal Server Error**

### 🛠️ วิธีแก้ไข:
ต้องสั่งรัน FastAPI Backend บนพอร์ต 8000 ด้วยคำสั่ง:
```bash
cd /root/waf_project/dashboard/backend
pip install -r requirements.txt
nohup python3 main.py > backend.log 2>&1 &
```

---

## 3. คู่มือการติดตั้งทีละขั้นตอน

### Step 1: เตรียม VPS Server (Ubuntu 22.04 LTS / 24.04 LTS)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw python3-pip

# ติดตั้ง Docker & Docker Compose
sh get-docker.sh
systemctl enable --now docker
```

### Step 2: Clone โค้ด & สร้าง `.env`
```bash
git clone https://github.com/jakkaret/waf_project.git
cd waf_project
git checkout Backend

cat << 'EOF' > .env
PROJECT_NAME="WAF CDN System"
ENVIRONMENT="production"
AWS_REGION="ap-southeast-1"
AWS_ACCESS_KEY_ID="dummy"
AWS_SECRET_ACCESS_KEY="dummy"
CLICKHOUSE_HOST="clickhouse"
CLICKHOUSE_PORT="8123"
CLICKHOUSE_USER="default"
CLICKHOUSE_PASSWORD="***REDACTED***"
REDIS_HOST="redis"
REDIS_PORT="6379"
TELEGRAM_BOT_TOKEN="***REDACTED***"
TELEGRAM_CHAT_ID="your_telegram_chat_id"
EOF
```

### Step 3: Build React Frontend
```bash
cd dashboard/frontend
npm install
npm run build
cd ../..
```

### Step 4: สตาร์ท Docker Stack & FastAPI Backend
```bash
# 1. สตาร์ท Docker Containers
docker compose up -d

# 2. ติดตั้งและรัน FastAPI Backend (พอร์ต 8000)
cd dashboard/backend
pip install -r requirements.txt
nohup python3 main.py > backend.log 2>&1 &
cd ../..
```

---

## 4. การตั้งค่า SSL และ Domain Name

แก้ไขไฟล์ `nginx/Caddyfile`:
```caddyfile
waf.yourdomain.com {
    reverse_proxy backend:8000
}
```
จากนั้นรีโหลด Caddy:
```bash
docker compose restart caddy
```

---

## 5. การรักษาความปลอดภัยและการตั้งค่า Firewall

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8000/tcp
sudo ufw --force enable
```

---

## 6. คำสั่งเช็กความถูกต้องและผลลัพธ์ที่ควรได้

### 1. เช็ก Backend API (Port 8000):
```bash
curl -I http://localhost:8000/docs
# ผลลัพธ์ที่ถูกต้อง: HTTP/1.1 200 OK
```

### 2. เช็ก WAF Proxy (Port 8080):
```bash
curl -I http://localhost:8080/
# ผลลัพธ์ที่ถูกต้อง: HTTP/1.1 302 Found (หรือ 200 OK)
```

---
*จัดทำโดย WAF & CDN Automated System Team*
