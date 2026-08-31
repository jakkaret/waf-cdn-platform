# 🛡️ CloudWAF — Intelligent WAF & CDN Platform

**Multi-tenant Web Application Firewall + CDN Platform** พร้อมเลเยอร์ตรวจจับภัยคุกคามด้วย Machine Learning และ AI Copilot สำหรับวิเคราะห์เหตุการณ์ความปลอดภัยแบบเรียลไทม์

โปรเจกต์จบสาขา Cybersecurity มหาวิทยาลัยขอนแก่น

> **สถานะโปรเจกต์:** Advanced Prototype / Demo — ระบบผ่านการทดสอบใช้งานจริงในระดับหนึ่งแล้ว (ไม่ใช่ production hardening เต็มรูปแบบ) รายละเอียดสถานะแต่ละฟีเจอร์อยู่ในหัวข้อ [Roadmap & ข้อจำกัดที่ทราบ](#-roadmap--ข้อจำกัดที่ทราบ) ด้านล่าง — เขียนไว้ตรงไปตรงมาโดยเจตนา

---

## 📑 สารบัญ

- [ภาพรวมโปรเจกต์](#-ภาพรวมโปรเจกต์)
- [สถาปัตยกรรมระบบ](#-สถาปัตยกรรมระบบ)
- [ฟีเจอร์หลัก](#-ฟีเจอร์หลัก)
- [Tech Stack](#-tech-stack)
- [ผลการทดสอบโมเดล ML](#-ผลการทดสอบโมเดล-ml)
- [การติดตั้งและรันระบบ](#-การติดตั้งและรันระบบ)
- [การใช้งานระบบ](#-การใช้งานระบบ)
- [Testing](#-testing)
- [Roadmap & ข้อจำกัดที่ทราบ](#-roadmap--ข้อจำกัดที่ทราบ)
- [เอกสารเพิ่มเติม](#-เอกสารเพิ่มเติม)

---

## 📖 ภาพรวมโปรเจกต์

ระบบนี้จำลองแพลตฟอร์ม WAF + CDN เชิงพาณิชย์ (แนวทางเดียวกับ Cloudflare) ให้ผู้ใช้แต่ละคนเพิ่มเว็บไซต์ของตัวเองเข้ามาให้ระบบป้องกันได้ — ประกอบด้วย 4 เลเยอร์หลัก:

1. **เลเยอร์ป้องกัน (Prevention)** — ModSecurity v3 + OWASP CRS ตรวจจับและบล็อกการโจมตีมาตรฐาน (SQLi, XSS, RCE, LFI ฯลฯ) แบบ signature-based พร้อม security module เสริมที่เขียนเอง (BOLA/IDOR guard, payload normalizer ต้าน evasion, ReDoS-safe regex engine)
2. **เลเยอร์ตรวจจับ (Detection)** — โมเดล Machine Learning (Random Forest + Isolation Forest) ให้คะแนนความผิดปกติของ request แบบ real-time พร้อมระบบอธิบายเหตุผลเชิง feature-attribution เป็นภาษาไทย
3. **เลเยอร์วิเคราะห์ (Analysis)** — AI Copilot (Gemini) ตอบคำถามเชิงความปลอดภัยโดยอ้างอิงข้อมูล telemetry สดจาก ClickHouse สรุปเหตุการณ์และรายงานภาพรวมเป็นภาษาไทย
4. **เลเยอร์บริหารจัดการ (Management)** — Dashboard แบบ multi-tenant ครบวงจร: สมัคร/ล็อกอิน, เพิ่ม origin server ของตัวเอง, จัดการ custom rule, ดู analytics, ตั้งค่า rate-limit, รับแจ้งเตือนผ่าน Telegram

ระบบมาพร้อมชุดเว็บแอปช่องโหว่ตั้งใจ (**DVWA, OWASP Juice Shop, vAmPI, bWAPP**) สำหรับสาธิตและพิสูจน์ว่า WAF ทำงานได้จริงกับการโจมตีจริง ไม่ใช่แค่ทฤษฎี

### เหตุผลเชิงออกแบบที่สำคัญ

- **ML ไม่ block เองอัตโนมัติ** — ระบบใช้ ML เพื่อ *เสนอ* กฎใหม่ (human-in-the-loop) เท่านั้น การบล็อกอัตโนมัติทำผ่าน Rule Engine (signature-based) ที่ผ่านการพิสูจน์ความแม่นยำแล้ว เหตุผลคือ recall ของโมเดลปัจจุบันยังไม่สูงพอสำหรับการตัดสินใจอัตโนมัติเต็มรูปแบบ (ดูตัวเลขจริงในหัวข้อ [ผลการทดสอบโมเดล ML](#-ผลการทดสอบโมเดล-ml))
- **Self-hosted private tunnel** — ผู้ใช้ที่มีเว็บเซิร์ฟเวอร์อยู่หลัง NAT/private network (ไม่มี public IP) สามารถต่อเข้ากับระบบได้โดยไม่ต้องเปิดพอร์ตขาเข้าเลย ผ่าน tunnel protocol ที่พัฒนาเอง (TLS + per-origin credential, hostname-based routing)
- **Fail-safe design** — ถ้า ML service ล่ม ระบบยังบล็อกด้วย Rule Engine ได้ตามปกติ ไม่กระทบการป้องกันหลัก

---

## 🏗️ สถาปัตยกรรมระบบ

ระบบรันจริงบนโครงสร้างพื้นฐาน 3 เครื่อง:

```
                          ┌─────────────────────────────────────┐
                          │            อินเทอร์เน็ตทั่วไป             │
                          └───────────────┬───────────────────────┘
                                          │ HTTPS
              ┌───────────────────────────┼───────────────────────────┐
              │                           │                           │
              ▼                           ▼                           │
   ┌─────────────────────┐    ┌─────────────────────────────┐        │
   │   Edge Node          │    │   Main Node                 │        │
   │   (CDN + WAF ชั้นนอก)   │    │   (WAF instance หลัก +       │        │
   │                      │    │    Control Plane ทั้งหมด)      │        │
   │  Caddy (SSL) ──►     │    │                              │        │
   │  ModSecurity CRS     │    │  Caddy (SSL) ──►             │        │
   │                      │    │  ModSecurity CRS (waf-nginx) │        │
   │  poll rule ทุก 5s ◄──┼────┼──control-api                 │        │
   │  log-forwarder ──────┼────┼─► ClickHouse                 │        │
   │                      │    │                              │        │
   │                      │    │  Dashboard Backend (FastAPI) │        │
   │                      │    │  + ML API (Random Forest +   │        │
   │                      │    │    Isolation Forest)         │        │
   │                      │    │                              │        │
   │                      │    │  ClickHouse / DynamoDB /      │        │
   │                      │    │   Redis                      │        │
   │                      │    │                              │        │
   │                      │    │  Tunnel Server (FRP + self-  │        │
   │                      │    │   hosted private tunnel)     │        │
   └──────────────────────┘    └──────────────┼────────────────┘        │
                                               │ Outbound tunnel          │
                                               │ (origin ไม่เปิดพอร์ตเข้า) │
                                               ▼                        │
                          ┌──────────────────────────────────┐          │
                          │   Web Origin (Private Network)    │          │
                          │                                    │          │
                          │  nginx ──┬─ DVWA + MariaDB          │          │
                          │          ├─ OWASP Juice Shop         │          │
                          │          ├─ vAmPI (vulnerable API)    │          │
                          │          └─ bWAPP                     │          │
                          │                                    │          │
                          │  Private Tunnel Agent               │◄─────────┘
                          └────────────────────────────────────┘
```

**เหตุผลของสถาปัตยกรรม 3 เครื่อง:** Edge Node และ Main Node มี public IP ทำหน้าที่เป็นด่านหน้า (Main Node ทำหน้าที่คู่คือทั้ง WAF instance หลักและ control plane) ส่วน Web Origin คือเครื่องที่เก็บเว็บแอปเป้าหมายไว้ อยู่หลัง private network จึงต้องมีกลไก tunnel เชื่อมออกมา — จำลองสถานการณ์จริงที่ลูกค้า WAF ส่วนใหญ่ไม่มี public IP ของตัวเอง

### ตัวอย่าง Request Lifecycle

1. ผู้ใช้สมัครบัญชี → เพิ่ม origin server ของตัวเอง → เพิ่มโดเมน → ตั้งค่า DNS → กด Verify → Caddy ออก TLS certificate อัตโนมัติ
2. ผู้โจมตีส่ง `GET /login?id=1' OR '1'='1` เข้าโดเมนนั้น
3. Request มาถึง Edge/Main → Caddy terminate TLS → ModSecurity CRS ตรวจพบ pattern SQLi → **บล็อกทันที ตอบ 403** ก่อนถึง origin จริง
4. บันทึกเหตุการณ์ลง ClickHouse (`access_logs`) และ DynamoDB (`waf_alerts`) พร้อมกัน
5. ระบบ explainability แปล rule ที่ trigger เป็นคำอธิบายภาษาไทยทันที ส่งแจ้งเตือนเข้า Telegram ของแอดมิน
6. แอดมินเปิด Dashboard เห็นกราฟ attack แบบ real-time เปิด AI Copilot ถาม "วันนี้โดนอะไรบ้าง" ได้คำตอบอ้างอิงตัวเลขจริงจาก ClickHouse

---

## ✨ ฟีเจอร์หลัก

| หมวด | รายละเอียด |
|---|---|
| **Real-time WAF Monitoring** | ติดตามเหตุการณ์การโจมตีและการบล็อกแบบเรียลไทม์ |
| **Custom Rules Management** | จัดการ ModSecurity Rules แบบกราฟิกผ่าน Dashboard พร้อม Blast Radius Simulator ทดสอบ false-positive ก่อน deploy |
| **🤖 ML Anomaly Detection** | ตรวจจับพฤติกรรมผิดปกติด้วย Random Forest + Isolation Forest พร้อม **feature-attribution แบบ per-request** (อธิบายว่าทำไม request นี้ถึงถูกตัดสินแบบนี้ ไม่ใช่แค่คะแนนดิบ) |
| **AI Copilot** | ผูกกับ Gemini API ตอบคำถามเชิงความปลอดภัยพร้อมข้อมูลจริงจาก ClickHouse สรุปเหตุการณ์เป็นภาษาไทย |
| **Self-hosted Private Tunnel** | เชื่อมต่อ origin server ที่อยู่หลัง NAT เข้าระบบโดยไม่ต้องเปิดพอร์ต — พัฒนาเอง ไม่พึ่งบริการภายนอก |
| **Multi-tenant Dashboard** | สมัคร/ล็อกอิน 3 ช่องทาง (Email, Google OAuth, Telegram), จัดการ origin/โดเมนของตัวเอง, ตั้งค่า rate-limit, ดู analytics แยกตาม tenant |
| **Telegram Alerts** | แจ้งเตือนทันทีเมื่อเกิดเหตุการณ์ร้ายแรงผ่าน Telegram Bot |
| **CDN Monitoring** | ตรวจสอบ Health Status และ Cache Hit/Miss ของ Edge Node |
| **Modern UI/UX** | React 18 + TailwindCSS ธีม Glassmorphism |

---

## 🧩 Tech Stack

| ชั้น | เทคโนโลยี |
|---|---|
| **WAF Engine** | ModSecurity v3 + OWASP CRS v3.3.10, nginx, Caddy (SSL termination อัตโนมัติ) |
| **Security เสริม (เขียนเอง)** | BOLA/IDOR guard (JWT + path canonicalization), payload normalizer ต้าน evasion, ReDoS-safe regex engine (process-isolated, RE2 fast-path) |
| **Backend** | Python 3.11, FastAPI 0.104, Uvicorn |
| **Frontend** | React 18.3 + TypeScript 5.6, Vite 5.4, TailwindCSS 3.4, TanStack Query 5.62, Zustand 4.5 |
| **Machine Learning** | scikit-learn (Random Forest + Isolation Forest ensemble), joblib |
| **AI** | Google Gemini API |
| **ข้อมูล** | ClickHouse (log/analytics), DynamoDB บน AWS จริง (config/entity), Redis (rate-limit) |
| **Tunnel** | FRP + Private Tunnel Protocol ที่พัฒนาเอง (TLS, per-origin credential, hostname-based vhost routing, zero inbound port บน origin) |
| **Container** | Docker + Docker Compose |
| **CI** | GitHub Actions — lint (backend/frontend), build frontend, test backend, test ML pipeline |
| **Auth** | JWT (HS256) + Argon2 password hash, Google OAuth 2.0, Telegram Login Widget |

---

## 📊 ผลการทดสอบโมเดล ML

ตัวเลขด้านล่างวัดจาก held-out test set จริง (`ml/models/eval_results.json`) — ไม่ใช่ train accuracy และไม่ใช่ตัวเลขคาดการณ์

```
Dataset:        Multi-Source Web Attack (CSIC 2010 + Augmented Security Payloads)
Train / Test:   45,079 / 15,027 samples (75% / 25% split)

Accuracy:       80.47%
ROC-AUC:        0.8847

                Precision   Recall    F1
Benign (0)      72.08%      98.97%    83.41%
Attack (1)      98.39%      62.26%    76.26%

Confusion Matrix (Test Set):
                Predicted: Normal   Predicted: Attack
Actual: Normal        7,377                77
Actual: Attack        2,858             4,715
```

**อ่านผลอย่างไร**: โมเดลนี้ตั้งใจออกแบบให้ **precision สูง (98.39%)** เพื่อลด false positive ซึ่งเป็นจุดที่ WAF เชิงพาณิชย์ส่วนใหญ่มีปัญหา — แลกกับ recall ที่ยังไม่สูง (62.26%) ซึ่งเป็นเหตุผลที่ระบบใช้ ML เป็น **ชั้นเสริม** ทำงานคู่กับ Rule Engine (signature-based) ที่จับ known attack ได้อยู่แล้ว ไม่ใช่ให้ ML ตัดสินใจบล็อกเดี่ยว ๆ

---

## 🚀 การติดตั้งและรันระบบ

### Prerequisites

- **Docker & Docker Compose**
- **Python 3.11+**
- **Node.js 20+ & npm**

### 1️⃣ Infrastructure (WAF & CDN)

```bash
git clone <repository-url>
cd waf_project
docker compose up -d

# CDN stack แยกต่างหาก (ถ้าต้องการ)
docker compose -f cdn/docker-compose-cdn.yml up -d

docker compose ps   # ตรวจสอบสถานะ container
```

### 2️⃣ Frontend (React + Vite)

```bash
cd dashboard/frontend
npm install

npm run dev      # Dev server พร้อม hot reload (พอร์ต 5173, proxy API ไป :8000 อัตโนมัติ)
npm run build    # Build สำหรับ production (จำเป็นก่อนรัน Backend โหมดจริง)
```

### 3️⃣ Backend (FastAPI Dashboard)

```bash
cd dashboard/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python main.py   # พอร์ต 8000
```

### 4️⃣ ML Service & Auto Rule Generator

```bash
# จาก root ของโปรเจกต์ ใช้ venv เดียวกับ backend
source dashboard/backend/.venv/bin/activate

python ml/train_model.py        # เทรนโมเดลใหม่ (ถ้าต้องการ)
python ml/ml_api.py             # ML API + Interactive Dashboard (พอร์ต 5000)
python ml/async_log_analyzer.py # Real-time log stream analyzer (worker)
```

---

## 📖 การใช้งานระบบ

| Service | URL (local) | คำอธิบาย |
|---|---|---|
| **Dashboard (Main UI)** | `http://localhost:8000` | หน้าจอหลักของ WAF & CDN Dashboard |
| **ML Dashboard & Auto Rule Generator** | `http://localhost:5000` | WAF ML Anomaly Predictor & Auto SecRule Generator |
| **Frontend Dev Server** | `http://localhost:5173` | สำหรับนักพัฒนา (`npm run dev`) |
| **API Docs (Main Backend)** | `http://localhost:8000/docs` | FastAPI Swagger UI |
| **API Docs (ML Service)** | `http://localhost:5000/docs` | FastAPI Swagger UI |
| **WAF Proxy** | `http://localhost:8080` | ทางเข้าหลักของ ModSecurity WAF |

สมัครบัญชีใหม่ผ่านหน้าเว็บ `/register` หรือใช้ Google OAuth

---

## ✅ Testing

โปรเจกต์มีชุดทดสอบอัตโนมัติหลายระดับ ทั้งหมดรันผ่าน CI (`.github/workflows/ci.yml`):

| ชุดทดสอบ | จำนวน | ครอบคลุม |
|---|---|---|
| Backend unit/integration (`pytest`) | 61 tests | Auth, RBAC, tenant isolation, rule CRUD, domain validation, ML attribution explanation, ClickHouse/SecRule injection regression |
| ML pipeline (`pytest`) | 18 tests | Feature attribution correctness (`bias + Σcontribution == predict_proba`, exact), accuracy-target computation |
| Smoke test (`scripts/smoke_test.sh`) | 22 invariants + 6 security gates | End-to-end health check บนระบบ deploy จริง |
| Tunnel test (`tunnel/test_tunnel.sh`) | 28 tests | Private tunnel protocol: auth, routing, failure modes |

```bash
# Backend + ML
cd dashboard/backend && .venv/bin/python -m pytest ../../ml/tests/ tests/ -v

# Smoke test (ต้อง deploy แล้ว)
bash scripts/smoke_test.sh
```

---

## 🗺️ Roadmap & ข้อจำกัดที่ทราบ

เขียนไว้ตรงไปตรงมา — โปรเจกต์นี้เป็น capstone ที่มีเวลาจำกัด บางฟีเจอร์เขียนโค้ดเสร็จแล้วแต่ยังไม่ deploy จริง บางส่วนตั้งใจเลื่อนไว้หลังสอบจบ

**กำลังพัฒนา:**
- Self-tuning anomaly threshold — ระบบเสนอปรับความไวการบล็อกเองตามข้อมูล traffic จริง โดยต้องมี human approve เสมอ (ป้องกัน data poisoning)
- CDN multi-region (GeoDNS) — โค้ดเขียนเสร็จและผ่านการทดสอบบนเครื่อง dev แล้ว แต่ยังไม่เคย deploy จริงข้ามหลายภูมิภาค

**ตั้งใจเลื่อนไว้ (post-thesis):**
- ปรับจูน ML accuracy เพิ่มเติม (เช่น เพิ่ม feature, ขยาย dataset)
- Production hardening เต็มรูปแบบ — secrets management, mTLS ระหว่าง service, authentication บน ClickHouse/Redis

**Privacy / PDPA:** ระบบเก็บ request log ดิบลง ClickHouse โดยยังไม่มี PII masking ตอน ingest (มีโมดูล `pii_masker.py` เขียนไว้แล้วแต่ยังใช้แค่จุดพรีวิว) และยังไม่มี retention policy — เหมาะสำหรับ lab/demo traffic เท่านั้นในสถานะปัจจุบัน data residency ทำได้จริง (host ในไทยทั้งหมด ยกเว้น Gemini API call)

---

## 📄 เอกสารเพิ่มเติม

- [`CLOUDFLARE_COMPARISON_PLAN.md`](CLOUDFLARE_COMPARISON_PLAN.md) — เปรียบเทียบฟีเจอร์กับ Cloudflare WAF/CDN
- ผลการทดสอบโมเดลแบบละเอียด (ROC curve, score distribution, confusion matrix) — `ml/models/eval_results.json` และหน้า ML Dashboard (`/` บนพอร์ต 5000 เมื่อรันระบบ)

---

<p align="center">พัฒนาเพื่อโปรเจกต์จบการศึกษา สาขาวิศวกรรมความมั่นคงปลอดภัยไซเบอร์ มหาวิทยาลัยขอนแก่น</p>
