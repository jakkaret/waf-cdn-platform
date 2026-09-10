# 🛡️ แผนพัฒนา WAF Gen 3 & มาตรฐานการควบคุมขอบเขตงาน (Living Roadmap)

> **เอกสารอ้างอิงหลัก:** [18 · WAF Generation Assessment (Docs)](https://jakkaret.github.io/Docs-for-WAF-project/18-waf-generation-assessment.html)  
> **วิสัยทัศน์:** ยกระดับจาก Gen 1 (Signature) + Gen 2 (Bot Shield) สู่ **WAF Gen 3 (Next-Gen ML-Driven WAF)** โดยรักษาความแม่นยำสูง ไม่ส่งผลกระทบต่อทราฟฟิกปกติ และไม่แตะต้องโค้ด Origin  
> **สถานะปัจจุบัน:** 🟡 In Progress (เฟส 1: เริ่มต้นยกระดับ ML Inference & Pipeline)  
> **อัปเดตล่าสุด:** 10 กันยายน 2026  

---

## 📌 กฎเหล็กและข้อกำหนดการอัปเดตเอกสาร (Mandatory Rules)

1. **Single Source of Truth:** เอกสารนี้ใช้เป็นแกนกลางในการติดตามสถานะงาน (Process Tracker) หากงานใดทำเสร็จแล้ว **ต้องเข้ามาเปลี่ยนเครื่องหมาย `[ ]` เป็น `[x]` และเพิ่มบันทึกใน [ตารางประวัติการทำงาน](#-ตารางบันทึกประวัติความคืบหน้า-change-log) ทันทีเสมอ**
2. **ห้ามแก้ไขไฟล์ที่ไม่เกี่ยวข้องเด็ดขาด (Strict Scope Boundary):** การทำงานในแต่ละข้อต้องแก้ไขเฉพาะไฟล์ที่ระบุใน [ขอบเขตไฟล์ที่อนุญาต](#-ขอบเขตไฟล์และระบบ-file--system-boundaries) เท่านั้น ห้าม Refactor ไฟล์อื่นนอกขอบเขตโดยพลการ
3. **Zero-Touch Origin Principle:** ห้ามแตะต้อง แก้ไข หรือเพิ่มโค้ดใดๆ บนแอปพลิเคชันต้นทางของลูกค้า (Origin Server) ทุกอย่างต้องทำงานที่ Edge Proxy / WAF Layer เท่านั้น
4. **Zero Customer Disruption:** การป้องกันระดับ Gen 3 ต้องไม่ทำให้ทราฟฟิกผู้ใช้ทั่วไปพัง ห้ามสกัดกั้นหน้าเนื้อหาทั่วไป และห้ามทำให้ฟอร์ม POST หลุด

---

## 🎯 สรุปช่องว่างสู่ WAF Gen 3 (Gap Analysis)

อ้างอิงจากเกณฑ์ในเอกสาร `18-waf-generation-assessment.html`:

| มิติการประเมิน | สถานะเดิมในเอกสาร | สถานะปัจจุบัน (10 ก.ย. 2026) | เป้าหมายสู่ Gen 3 ที่แท้จริง |
| :--- | :---: | :---: | :--- |
| **Gen 1: Signature WAF** | ✅ 100% | ✅ 100% | ModSecurity + OWASP CRS ทำงานตรวจจับ Known Attacks |
| **Gen 2: Bot & Session Risk** | ❌ 0% | 🟡 **50% (เพิ่งทำเสร็จ)** | มี Native PoW Challenge & Pre-Login Gate แล้ว (Commit `a3edfab`/`abff403`) รอเพิ่ม Session Risk Scoring |
| **Gen 3: Real-Time Auto-Block** | ❌ 0% | ❌ 0% (Human-in-the-loop) | ML ตัดสินใจ Inline Real-Time (Latency < 10ms) สั่ง Block หรือ Adaptive Challenge ได้เอง |
| **Gen 3: Model Accuracy & Recall** | ❌ Recall 62.26% | ❌ Recall 62.26% (FN=2,858) | ปรับปรุง Features และจูนโมเดลให้ **Attack Recall สู่ 85% – 90%+** โดยใช้ข้อมูลจริง ห้ามเมค/ห้ามคูณซ้ำ/ห้าม Overfit พร้อมควบคุม Benign Recall >= 98.5% |
| **Gen 3: Closed-Loop Retraining** | ❌ ไม่มี | ❌ ไม่มี | มี Pipeline ดึง Log จริงจาก ClickHouse มา Re-train / Fine-tune ต่อเนื่องอัตโนมัติ |
| **Gen 3: Explainability** | ✅ 100% | ✅ 100% | มี Feature Attribution (SHAP) ภาษาไทยราย Request พร้อมใช้งาน |

---

## 🗺️ แผนการดำเนินการ 4 ขั้นตอน (Phased Roadmap)

```mermaid
flowchart TD
    subgraph Phase 1: Real-Time Inline Decision
        P1_1[แปลง Model เป็น Fast Inference / ONNX] --> P1_2[สร้าง Nginx/Sidecar Decision Hook]
        P1_2 --> P1_3[Adaptive Enforcement: Score สูงส่ง PoW / สูงวิกฤตสั่ง Block]
    end

    subgraph Phase 2: Model Performance & Tuning
        P2_1[เพิ่ม Feature Extraction: Path Entropy / Token Ratios] --> P2_2[Benchmark Dataset คลีนแล้ว ปราศจาก Leakage]
        P2_2 --> P2_3[ดัน Attack Recall สู่ 85%-90%+ ปราศจาก Overfitting]
    end

    subgraph Phase 3: Closed-Loop Retraining
        P3_1[ดึง Real Traffic & Labels จาก ClickHouse] --> P3_2[Automated Retraining Script]
        P3_2 --> P3_3[Safety Evaluation Benchmark ก่อน Auto-Promote]
    end

    subgraph Phase 4: Session Tracking & Fingerprinting
        P4_1[JA3/JA4 TLS Fingerprinting] --> P4_2[Redis Session-based Risk Accumulator]
    end

    Phase 1 --> Phase 2 --> Phase 3 --> Phase 4
```

---

## 📋 รายการงานที่ต้องทำ (To-Do & Checklist)

### เฟส 1: Real-time Inline Decision & Adaptive Enforcement
- [x] **1.1 Low-Latency Inference Engine:** RF/ONNX inline fast path validated; Isolation Forest remains async-only analytics.
  - Parity: 9 cases, label mismatch 0, max probability diff 0.000037 with tolerance 0.001.
  - Benchmark: 30 samples, ONNX avg 0.059ms, p95 0.098ms; ML API /predict-fast is enabled.
  - Scope: Nginx hook and enforcement are not enabled yet.
- [ ] **1.2 Edge Proxy Decision Hook:** เชื่อม Nginx Proxy เข้ากับ Decision Service ผ่าน `auth_request` หรือ Subrequest โดยทำงานเฉพาะ Dynamic / Non-Static paths
- [ ] **1.3 Adaptive Action Policy:**
  - `Score >= 0.95` (อันตรายสูงมาก): สั่ง Block 403 ทันที
  - `0.70 <= Score < 0.95` (ต้องสงสัย): ส่งเข้า Native Proof-of-Work Challenge (แก้ผ่านจึงให้ผ่าน)
  - `Score < 0.70` (ปกติ): ปล่อยผ่านสู่ Origin ทันที

### เฟส 2: ยกระดับความแม่นยำของโมเดล (ดัน Attack Recall สู่ 85% – 90%+ อย่างโปร่งใส)
> [!IMPORTANT]
> **มาตรฐานความโปร่งใสทางข้อมูลและโมเดล (Scientific Data Integrity & Anti-Overfitting Protocol)**  
> 1. **ห้ามเมคตัวเลขเด็ดขาด (No Fabricated Metrics):** ตัวเลข Recall, Precision, Accuracy ทุกตัวต้องเกิดจากการรันโค้ดประเมินจริงผ่านสคริปต์ `ml/evaluate_model.py` บนชุดข้อมูลจริงเท่านั้น ห้ามเขียนเคลมลอยๆ
> 2. **ห้ามคูณซ้ำข้อมูลหรือทำ Data Leakage (No Row Duplication / Multiplication):** ห้ามนำแถวเดิมมาคูณซ้ำ (เช่น `df * 500`) เพื่อปั่นตัวเลข ต้องทำ **Deduplication ผ่าน SHA-256 Hashes 100%** ก่อนการแบ่ง Train/Test Split เพื่อไม่ให้มีข้อมูลเหมือนกันหลุดข้ามไปมาระหว่างชุดฝึกและชุดทดสอบ
> 3. **ห้าม Overfitting จากการท่องจำ (Generalization over Memorization):** โมเดลต้องผ่านการทดสอบกับ Unseen Payloads และ Attack Mutations ใหม่ๆ ที่ไม่เคยเห็นใน Train Set โดยวัดผลผ่าน Stratified Cross-Validation
> 4. **ควบคุม False Positive Rate (Zero Customer Disruption):** การดัน Recall สู่ 85%–90% ต้องไม่แลกมาด้วยการบล็อกคนปกติ — **Benign Recall ต้องคงไว้ที่ >= 98.5% (False Alarm < 1.5%)** เสมอ

- [ ] **2.1 Extended Feature Engineering (แก้ปัญหา FN 2,858 แถวเดิม):**
  - **Shannon Entropy Analysis:** คำนวณความสับสนของ URL Path และ Query Payload เพื่อจับ Shellcode, Base64, Hex และ Obfuscated Payload
  - **Structural Anomaly & Delimiter Ratios:** ตรวจจับวงเล็บ, Quotes, Backticks และอักขระคั่นโครงสร้างที่ผิดปกติ
  - **SQL/Script Mutation Patterns:** เพิ่มการจับ Comment Evasion (`/**/`, `-- -`), Inline Function Calls (`CHAR()`, `SLEEP()`), และ JSON-based Injection
- [ ] **2.2 Cost-Sensitive Learning & Threshold Calibration:**
  - ปรับ Class Weights (ให้ Penalty กับ False Negative มากขึ้น) เพื่อบีบให้โมเดลไม่มองข้ามการโจมตี
  - คำนวณหา Optimal Decision Threshold (จากเดิมที่ Cut-off 0.5 แบบแข็งตัว) เพื่อดัน Recall จาก 62.26% ขึ้นสู่ **85% – 90%**
- [ ] **2.3 Model Architecture Exploration (LightGBM / XGBoost Ensemble):**
  - เปรียบเทียบประสิทธิภาพระหว่าง Random Forest เดิม กับ LightGBM / XGBoost เพื่อค้นหาโมเดลที่จับ Non-linear Boundaries ของ Payload สมัยใหม่ได้ดีกว่า
- [ ] **2.4 Rigorous Holdout & Cross-Validation Benchmark:**
  - รันการทดสอบ 5-Fold Stratified Cross-Validation บนชุดข้อมูล Unseen Holdout ที่คลีนแล้ว
  - บันทึกผลลัพธ์ Confusion Matrix (TP, FP, TN, FN) พร้อม Classification Report ลงในไฟล์ Metadata เพื่อใช้เป็นหลักฐานยืนยันความโปร่งใส

### เฟส 3: ระบบเทรนต่อเนื่องอัตโนมัติ (Closed-Loop Retraining)
- [ ] **3.1 Data Feed จาก ClickHouse:** เขียน Worker ดึงคำขอที่โดนบล็อก, คำขอที่ผ่าน Challenge และคำขอปกติ มาจัดเตรียมเป็นชุดข้อมูลใหม่
- [ ] **3.2 Automated Retraining Job:** สร้าง Script หรือ Systemd Timer รายสัปดาห์สำหรับรัน Retraining Pipeline แบบอัตโนมัติ
- [ ] **3.3 Model Validation Gate:** ก่อนจะนำโมเดลใหม่ขึ้น Production ต้องรัน Automated Test Benchmark หาก Recall ตกต่ำกว่าเกณฑ์จะไม่อัปเดตโมเดล

### เฟส 4: Behavioral Session Tracking & TLS Fingerprinting (Gen 2 Extension)
- [ ] **4.1 TLS Fingerprinting (JA3 / JA4):** บันทึก Signature ของ SSL Handshake เพื่อตรวจจับสคริปต์อัตโนมัติ (เช่น curl, python-requests, Go-http) แม้ว่าจะปลอมแปลง User-Agent
- [ ] **4.2 Cumulative Session Risk:** เก็บแต้มความเสี่ยงสะสมราย IP ใน Redis (เช่น สแกน 404 บ่อย, ยิงถี่ผิดปกติ) เมื่อแต้มสะสมถึงเกณฑ์ให้บังคับ Challenge

---

## 🚫 ขอบเขตไฟล์และระบบ (File & System Boundaries)

### 🟢 ไฟล์และโฟลเดอร์ที่อนุญาตให้แก้ไข (Allowed Target Scopes)
งานทั้งหมดเพื่อ Gen 3 จะต้องทำอยู่ภายในขอบเขตโฟลเดอร์เหล่านี้เท่านั้น:
* `ml/` (โมเดล, สคริปต์เทรน, inference pipeline, evaluation scripts)
* `cdn/control-api/` (Challenge engine, inline policy logic, rate limiter integration)
* `nginx/includes/` และ `nginx/templates/` (เฉพาะ configuration ที่เกี่ยวกับ reverse proxy hook และ captcha integration)
* `dashboard/backend/api/` (API endpoint สำหรับดึงค่าสถานะ ML และความแม่นยำ)
* `dashboard/frontend/src/` (เฉพาะหน้า UI ที่เกี่ยวกับ ML Settings, Shield และ Analytics)
* `scripts/` (Automated worker, retraining scripts, vulnerability scanners)

### 🔴 ไฟล์และระบบที่ **ห้ามแตะต้องเด็ดขาด** (Protected - DO NOT TOUCH)
* ❌ **ห้ามแตะโฟลเดอร์แอปของลูกค้า/Origin ใดๆ**
* ❌ `dashboard/backend/data/` (ห้ามลบหรือเขียนทับ database `.db` โดยไม่มีสคริปต์ migration)
* ❌ `tunnel/` และ Core Zero-Trust Tunnel Agent ที่ทำงานเสถียรแล้ว
* ❌ Caddy Auto-HTTPS & SSL Certificate Provisioning Core
* ❌ ห้ามลบ Docstrings, Comments หรือ Type definitions ที่มีอยู่เดิมในไฟล์

---

## 📝 ตารางบันทึกประวัติความคืบหน้า (Change Log)

> 💡 **คำแนะนำ:** ทุกครั้งที่มีการ Commit โค้ดที่เกี่ยวกับ Roadmap นี้ ให้เพิ่มแถวใหม่ในตารางนี้ทันที

| วันที่ | Task ID / หัวข้อ | Commit ID | ผู้ดำเนินการ | รายละเอียดการเปลี่ยนแปลง |
| :--- | :---: | :---: | :---: | :--- |
| **09/09/2026** | Gen 2: Challenge Engine | `a3edfab` | ryu-chirachot | สร้าง Native Bot Challenge (PoW) & Pre-Login Gate สำเร็จ |
| **09/09/2026** | Gen 2: Dashboard UI | `abff403` | ryu-chirachot | เพิ่มแท็บ Bot & Login Shield บน Origin Detail และ Redesign Auth |
| **10/09/2026** | Gen 3: Roadmap Initialization | - | Pair Programming | จัดทำเอกสาร Roadmap และกำหนด Scope ป้องกันไฟล์นอกขอบเขต |
| **10/09/2026** | Gen 3: 1.1 RF/ONNX Fast Path | - | Pair Programming | Added ONNX export, inference, validation, benchmark and ML API /predict-fast; verified legacy /predict remains operational. |

---

## 🔍 คำสั่งสำหรับตรวจสอบความสมบูรณ์ของระบบ (Verification Commands)

เมื่อแก้ไขโค้ดแต่ละส่วน ให้รันคำสั่งเหล่านี้เพื่อตรวจสอบว่าระบบไม่พัง:

```bash
# 1. ตรวจสอบสถานะ Service ทั้งหมด
docker compose ps

# 2. ตรวจสอบ Linting & Type Check ฝั่ง Dashboard Frontend
cd dashboard/frontend && npm run build

# 3. รัน Unit Tests ฝั่ง ML และ Form Logic
npm run test -- captchaForm.test.ts
pytest tests/

# 4. ทดสอบความเร็วในการ Infer ของ ML (Latency Check)
python3 ml/benchmark_latency.py
```
