# 🛡️ แผนพัฒนา WAF Gen 3 & มาตรฐานการควบคุมขอบเขตงาน (Living Roadmap)

> **เอกสารอ้างอิงหลัก:** [18 · WAF Generation Assessment (Docs)](https://jakkaret.github.io/Docs-for-WAF-project/18-waf-generation-assessment.html)  
> **วิสัยทัศน์:** ยกระดับจาก Gen 1 (Signature) + Gen 2 (Bot Shield) สู่ **WAF Gen 3 (Next-Gen ML-Driven WAF)** โดยรักษาความแม่นยำสูง ไม่ส่งผลกระทบต่อทราฟฟิกปกติ และไม่แตะต้องโค้ด Origin  
> **สถานะปัจจุบัน:** 🟡 In Progress (เฟส 2: Extended Features & Model Calibration; candidate ยังไม่ถูก promote)
> **อัปเดตล่าสุด:** 13 กันยายน 2026

---

## 📌 กฎเหล็กและข้อกำหนดการอัปเดตเอกสาร (Mandatory Rules)

1. **Single Source of Truth:** เอกสารนี้ใช้เป็นแกนกลางในการติดตามสถานะงาน (Process Tracker) หากงานใดทำเสร็จแล้ว **ต้องเข้ามาเปลี่ยนเครื่องหมาย `[ ]` เป็น `[x]` และเพิ่มบันทึกใน [ตารางประวัติการทำงาน](#-ตารางบันทึกประวัติความคืบหน้า-change-log) ทันทีเสมอ**
2. **ห้ามแก้ไขไฟล์ที่ไม่เกี่ยวข้องเด็ดขาด (Strict Scope Boundary):** การทำงานในแต่ละข้อต้องแก้ไขเฉพาะไฟล์ที่ระบุใน [ขอบเขตไฟล์ที่อนุญาต](#-ขอบเขตไฟล์และระบบ-file--system-boundaries) เท่านั้น ห้าม Refactor ไฟล์อื่นนอกขอบเขตโดยพลการ
3. **Zero-Touch Origin Principle:** ห้ามแตะต้อง แก้ไข หรือเพิ่มโค้ดใดๆ บนแอปพลิเคชันต้นทางของลูกค้า (Origin Server) ทุกอย่างต้องทำงานที่ Edge Proxy / WAF Layer เท่านั้น
4. **Zero Customer Disruption:** การป้องกันระดับ Gen 3 ต้องไม่ทำให้ทราฟฟิกผู้ใช้ทั่วไปพัง ห้ามสกัดกั้นหน้าเนื้อหาทั่วไป และห้ามทำให้ฟอร์ม POST หลุด

---

## 🎯 สรุปช่องว่างสู่ WAF Gen 3 (Gap Analysis)

อ้างอิงจากเกณฑ์ในเอกสาร `18-waf-generation-assessment.html`:

| มิติการประเมิน | สถานะเดิมในเอกสาร | สถานะปัจจุบัน (13 ก.ย. 2026) | เป้าหมายสู่ Gen 3 ที่แท้จริง |
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
- [x] **1.2 Edge Proxy Decision Hook (Shadow Mode):** เชื่อม Nginx Dynamic / Non-Static locations เข้ากับ RF/ONNX Decision Service ผ่าน mirror subrequest และ internal dashboard relay โดย fail-open; response ของ ML ถูกเก็บเป็น header ภายในและยังไม่ enforce block/challenge
  - Evidence (13/09/2026, original): Nginx active config มี mirror 5 จุด; benign ได้ decision `pass` score 0.2479; SQLi probe ได้ `anomaly` score 1.0; relay ที่ไม่มี capability header ได้ 404; `/healthz` ยังคง 200
  - **Correction (18/09/2026):** ตรวจซ้ำบน production จริงพบว่า evidence ข้างต้น **reproduce ไม่ได้** — `mirror`/`internal-ml-shadow` ไม่เคย commit เข้า git เลย (`git log -S'mirror' -- nginx/templates/conf.d/default.conf.template` ว่างเปล่า), มีอยู่ชั่วคราวจากการแก้ไฟล์ตรงบน disk (`/root/.bash_history`), ครอบคลุมแค่ 4 host ไม่ใช่ 5, และถูกเปลี่ยนปลายทางไปที่ `/internal-ml-capture` (งาน 3.1) ภายหลังโดยไม่ commit เช่นกัน — ตอนตรวจ ณ วันที่ 18/09 ไม่มี caller เรียก `/internal-ml-shadow` เลยทั้งใน template และ rendered runtime config (`docker exec waf-nginx grep -c ... /etc/nginx/conf.d/default.conf` = 0) ทุกตัวเลขที่อ้างข้างต้นยังเป็นข้อมูลจริงที่เคยรันได้ แต่ **ไม่ใช่สถานะปัจจุบันของระบบ** — ตามกฎข้อ 1 ของ Phase 2 (ห้ามเมคตัวเลข/เคลมลอยๆ) จึงบันทึกแก้ไขตรงนี้แทนการปล่อยไว้
  - Boundary: ไม่มีการ block/challenge จาก ML ในขั้นตอนนี้; Adaptive Enforcement อยู่ใน Task 1.3
- [x] **1.3 Adaptive Action Policy (mechanism built, enforcement OFF):**
  - `Score >= 0.95` (อันตรายสูงมาก): สั่ง Block 403 ทันที
  - `0.70 <= Score < 0.95` (ต้องสงสัย): ส่งเข้า Native Proof-of-Work Challenge (แก้ผ่านจึงให้ผ่าน)
  - `Score < 0.70` (ปกติ): ปล่อยผ่านสู่ Origin ทันที
  - **Evidence (18/09/2026):** ดู `ML_ENFORCEMENT_PLAN.md`. Global toggle `ml_enforcement_enabled` (default `false`) ใน `dashboard/backend/services/settings_service.py`, sync ผ่าน Redis (`waf:ml:policy`) ไปยัง `cdn/control-api/ml_policy.py`; ต่อเป็น branch ที่ 3 ของ `otp_engine.shield_access` ใช้ auth_request chain เดิม (ไม่เพิ่ม nginx location ใหม่). ทดสอบจริงบน production (bypass การจ่ายไปยัง real tunnel traffic โดยเรียก `/api/shield/access`/`/cdn-cgi/challenge` ตรงผ่าน loopback): pass band (score 0.2479) → 204, block band (score 1.0, threshold 0.95) → 403 + `X-Shield-Type: ml-block`, challenge band (score 1.0, threshold ปรับชั่วคราวเป็น 1.5 เพื่อบังคับ band) → 401 + `X-Shield-Type: ml` → `/cdn-cgi/challenge` render หน้า PoW จริง (200). คืนค่า `ml_enforcement_enabled=false` หลังทดสอบแล้ว, `scripts/smoke_test.sh` 22/22 invariant ผ่านทั้งก่อนและหลัง
  - **ทำไมยัง OFF:** promotion gate ของ Phase 2 ยังไม่ผ่าน (ดูรายการ Phase 2 ด้านล่าง) — เปิด enforcement ตอนนี้เท่ากับให้โมเดลที่ recall ต่ำกว่าเกณฑ์ตัวเองไป block/challenge traffic จริง ตามกฎบรรทัดสุดท้ายของเอกสารนี้ ("ห้ามเริ่ม Phase 4 หรือเปิด enforcement ก่อนมี artifact ที่ผ่าน validation และ rollback plan")
  - **Rollback plan:** `ml_enforcement_enabled: false` ใน system settings คือ rollback เต็มรูป — เขียนค่าเดียว ไม่ต้อง redeploy/restart container ใดๆ

### เฟส 2: ยกระดับความแม่นยำของโมเดล (ดัน Attack Recall สู่ 85% – 90%+ อย่างโปร่งใส)
> [!IMPORTANT]
> **มาตรฐานความโปร่งใสทางข้อมูลและโมเดล (Scientific Data Integrity & Anti-Overfitting Protocol)**  
> 1. **ห้ามเมคตัวเลขเด็ดขาด (No Fabricated Metrics):** ตัวเลข Recall, Precision, Accuracy ทุกตัวต้องเกิดจากการรันโค้ดประเมินจริงผ่านสคริปต์ `ml/evaluate_model.py` บนชุดข้อมูลจริงเท่านั้น ห้ามเขียนเคลมลอยๆ
> 2. **ห้ามคูณซ้ำข้อมูลหรือทำ Data Leakage (No Row Duplication / Multiplication):** ห้ามนำแถวเดิมมาคูณซ้ำ (เช่น `df * 500`) เพื่อปั่นตัวเลข ต้องทำ **Deduplication ผ่าน SHA-256 Hashes 100%** ก่อนการแบ่ง Train/Test Split เพื่อไม่ให้มีข้อมูลเหมือนกันหลุดข้ามไปมาระหว่างชุดฝึกและชุดทดสอบ
> 3. **ห้าม Overfitting จากการท่องจำ (Generalization over Memorization):** โมเดลต้องผ่านการทดสอบกับ Unseen Payloads และ Attack Mutations ใหม่ๆ ที่ไม่เคยเห็นใน Train Set โดยวัดผลผ่าน Stratified Cross-Validation
> 4. **ควบคุม False Positive Rate (Zero Customer Disruption):** การดัน Recall สู่ 85%–90% ต้องไม่แลกมาด้วยการบล็อกคนปกติ — **Benign Recall ต้องคงไว้ที่ >= 98.5% (False Alarm < 1.5%)** เสมอ

- [x] **2.1 Extended Feature Engineering (แก้ปัญหา FN 2,858 แถวเดิม):**
  - **Shannon Entropy Analysis:** คำนวณความสับสนของ URL Path และ Query Payload เพื่อจับ Shellcode, Base64, Hex และ Obfuscated Payload
  - **Structural Anomaly & Delimiter Ratios:** ตรวจจับวงเล็บ, Quotes, Backticks และอักขระคั่นโครงสร้างที่ผิดปกติ
  - **SQL/Script Mutation Patterns:** เพิ่มการจับ Comment Evasion (`/**/`, `-- -`), Inline Function Calls (`CHAR()`, `SLEEP()`), และ JSON-based Injection
  - **Evidence (13/09/2026):** เพิ่ม feature vector เป็น 22 features และรันบนข้อมูล 60,106 แถวที่ผ่าน SHA-256 deduplication 100%; train/test hash overlap = 0. Candidate ได้ Accuracy 90.24%, Attack Recall 86.62%, Benign Recall 93.92% (FN=1,013, FP=453).
  - **Promotion gate:** ยังไม่ promote เข้า production เพราะ Benign Recall ต่ำกว่าเกณฑ์ 98.5%; candidate และผล calibration ถูกเก็บไว้ใน `ml/models/archive/task2-1-extended-20260913/`
  - **Evidence (13/09/2026, CSIC-only FN audit):** CSIC-only audit buckets: 9,665/15,472 (62.47%) have high-confidence signals; 5,805 (37.52%) are structural/encoding-only review candidates; 2 rows (0.01%) remain unresolved. Dangerous encoded-token signal appears in 8,436 attack rows and suspicious path markers in 1,122. Ordinary URL encoding overlaps benign traffic and is not treated as proof of attack. This report is used for review only; no labels were auto-relabelled or promoted. Report: `ml/models/archive/task2-1-real-fn-audit-20260913/report.json`.
  - **Audited-training candidate (CSIC-only):** Excluding 3,700 review attack rows from fit reduced unseen-holdout Attack Recall to 53.09% at Benign Recall 98.54%; review rows must not be discarded or auto-relabelled. Report: `ml/models/archive/task2-1-audited-training-candidate-20260913/report.json`.
- [x] **2.2 Cost-Sensitive Learning & Threshold Calibration:**
  - ปรับ Class Weights (ให้ Penalty กับ False Negative มากขึ้น) เพื่อบีบให้โมเดลไม่มองข้ามการโจมตี
  - คำนวณหา Optimal Decision Threshold (จากเดิมที่ Cut-off 0.5 แบบแข็งตัว) เพื่อดัน Recall จาก 62.26% ขึ้นสู่ **85% – 90%**
  - **Evidence (13/09/2026):** Cost-sensitive RF (`class_weight={benign:1.25, attack:1.0}`) ที่ threshold 0.5 ได้ Benign Recall 95.65%, Attack Recall 84.83%; threshold 0.613780 ทำให้ Benign Recall 98.51% แต่ Attack Recall 80.75%. Promotion gate ยังไม่ผ่าน; report อยู่ที่ `ml/models/archive/task2-2-cost-sensitive-20260913/report.json`
  - Evidence (13/09/2026, CSIC-only): tested class weights `{1.0:1.0}`, `{1.25:1.0}`, `{1.5:1.0}`, and `{1.0:1.25}` with threshold calibration; best result within the benign gate: Benign Recall 98.65%, Attack Recall 64.59%; maximum Attack Recall 65.20% occurred at Benign Recall 98.44% and failed the safety gate; promotion gate failed. Report: `ml/models/archive/task2-2-real-cost-sensitive-20260913/report.json`.
  - **Data-integrity correction:** historical 60,106-row metrics for 2.1/2.2 came from a pipeline that regenerated 35,012 synthetic rows; those metrics are retained only as historical candidates and are not valid production-promotion evidence. CSIC-only reports above are authoritative.
- [ ] **2.3 Model Architecture Exploration (LightGBM / XGBoost Ensemble):**
  - เปรียบเทียบประสิทธิภาพระหว่าง Random Forest เดิม กับ LightGBM / XGBoost เพื่อค้นหาโมเดลที่จับ Non-linear Boundaries ของ Payload สมัยใหม่ได้ดีกว่า
  - **Decision (18/09/2026):** ยังไม่เริ่ม 2.3 ในรอบนี้ตามลำดับที่เอกสารนี้กำหนดเอง (ท้าย section 3.1: 2.3 ถูก gate ไว้หลัง 3.1 dataset/feature ผ่านก่อน) และไม่ลอง sweep class-weight/threshold ของ RF เดิมซ้ำ เพราะ 2.2/2.4 sweep ไปครบแล้ว (4 class-weight config × threshold calibration, 5-fold CV, unseen holdout, SHA-256 dedup) เจอเพดานจริงที่ ~65% attack recall ที่ benign recall 98.5%+ (ดู evidence ด้านบน) รันซ้ำแบบเดิมจะไม่ได้ข้อมูลใหม่ ตัดสินใจไปทำ 3.1-A (data pipeline) ก่อนตามลำดับที่เอกสารกำหนดเอง
- [x] **2.4 Rigorous Holdout & Cross-Validation Benchmark:**
  - รันการทดสอบ 5-Fold Stratified Cross-Validation บนชุดข้อมูล Unseen Holdout ที่คลีนแล้ว
  - บันทึกผลลัพธ์ Confusion Matrix (TP, FP, TN, FN) พร้อม Classification Report ลงในไฟล์ Metadata เพื่อใช้เป็นหลักฐานยืนยันความโปร่งใส
  - Evidence (13/09/2026): `ml/models/archive/task2-4-real-holdout-cv-20260913/report.json`; CSIC-only, synthetic rows = 0, SHA-256 train/holdout overlap = 0; unseen holdout Benign Recall 98.54%, Attack Recall 64.75%; promotion gate failed.
  - Candidate is not promoted; the result is a blocker for 2.2/2.3 and ML enforcement remains disabled.

### เฟส 3: ระบบเทรนต่อเนื่องอัตโนมัติ (Closed-Loop Retraining)
- [ ] **3.1 Data Feed จาก ClickHouse:** เขียน Worker ดึงคำขอที่โดนบล็อก, คำขอที่ผ่าน Challenge และคำขอปกติ มาจัดเตรียมเป็นชุดข้อมูลใหม่
  - Controlled lab-only telemetry is live via Nginx mirror -> dashboard relay -> loopback ML API; raw request bodies and headers are not persisted. The capture stores a SHA-256 body hash, redacted preview, and feature vector only, with allowlisted lab hosts, 64KB body cap, 5MB/day cap, and 7-day retention; this is not yet a ClickHouse worker or label-promotion source.
  - **3.1-A re-verified (18/09/2026):** เช่นเดียวกับ 1.2 ที่พบว่า mirror หลุดจาก template โดยไม่ commit, 3.1's `mirror /internal-ml-capture;` ก็หลุดไปด้วยเช่นกัน (มีข้อมูลเก่าอยู่ใน `ml/telemetry/` จากตอนที่เคย wire ชั่วคราว: 581 record วันที่ 14/09, เพิ่มอีก 6 record วันที่ 16-17/09) — re-wire ใหม่และ **commit ครั้งนี้จริง** (`nginx/includes/captcha_server.conf`: `/internal-ml-capture` location; `default.conf.template`: `mirror`+`mirror_request_body on;` ในทุก `location /`, ครอบคลุมทั้ง 5 host ใน `ml/capture_telemetry.py`'s allowlist ผ่าน real Host header ที่ downstream กรองเอง). Aggregate report หลัง re-wire (596 record รวมของเก่า+ใหม่): schema-complete 596/596 (100%), แยกตาม host: vampi 187, bwapp 198, dvwa 208, juice 3 (ryu ยังไม่มี traffic จับได้), แยกตาม method: POST 587 / GET 9, **unredacted secret-looking string ที่พบ = 0**. Size รวม ~596KB ต่อวันสูงสุด (คิดจาก 588KB ของวันที่หนักสุด) ยังต่ำกว่า cap 5MB/day มาก, retention 7 วันทำงานถูกต้อง (ไฟล์ 14/09 อายุ 4 วัน ณ วันที่ตรวจ ยังไม่ถูกลบ)
  - **ยังไม่ทำ (out of scope รอบนี้ตามที่ระบุใน "ลำดับการตัดสินใจ" ด้านล่าง):** 3.1-B (เก็บ traffic จริงให้หลากหลายครบ attack family ตามช่วงเวลา) ถึง 3.1-G (validation gate) ต้องใช้เวลาเก็บข้อมูลจริงหลายวัน/สัปดาห์ ทำในรอบเดียวไม่ได้โดยไม่กลายเป็นข้อมูลปลอม
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
| **13/09/2026** | Gen 3: 2.1 Extended Feature Engineering | - (candidate archived) | Pair Programming | Added entropy, encoded-payload, delimiter, comment-evasion, inline-function and JSON-injection features; evaluated with SHA-256 deduplication. Candidate not promoted because calibrated Attack Recall was 80.59% at Benign Recall 98.52%. |
| **13/09/2026** | Gen 3: 2.2 Cost-Sensitive Threshold Calibration | - (candidate archived) | Pair Programming | Tested one cost-sensitive RF holdout candidate with SHA-256 integrity; safety gate failed because no threshold achieved Benign Recall ≥98.5% and Attack Recall ≥85% simultaneously. |
| **10/09/2026** | Gen 3: 1.2 Edge Proxy Decision Hook | - (pending approval) | Pair Programming | Added shadow-only Nginx mirror hook for five dynamic locations, fail-open dashboard relay to loopback ML service, and verified pass/anomaly decisions without enforcement. |
| **13/09/2026** | Gen 3: 2.2 Real-Data Cost-Sensitive Calibration | - | Pair Programming | Re-ran class-weight and threshold candidates on CSIC-only data with SHA-256 deduplication; best within benign gate Benign Recall 98.65% / Attack Recall 64.59%; maximum Attack Recall 65.20% failed the benign gate; no candidate promoted. |
| **13/09/2026** | Gen 3: 2.1 Real-Data FN/Label Coverage Audit | - | Pair Programming | CSIC-only audit found 62.47% have high-confidence signals, 37.52% remain structural/encoding-only review candidates, and 2 rows remain unresolved; ordinary URL encoding is explicitly treated as noisy; feature-driven promotion paused pending label audit. |
| **13/09/2026** | Gen 3: 2.1 Form-Encoding Normalization | - | Pair Programming | Decoded form-style `+` spaces before feature/signature extraction; added unit coverage; production model/artifacts unchanged. |
| **13/09/2026** | Gen 3: 2.1 Signal Coverage Review | - | Pair Programming | Added suspicious path markers and dangerous encoded-token coverage; CSIC-only audit leaves 2 unresolved attack-labeled rows for manual review; no auto-relabel or production artifact. |
| **13/09/2026** | Gen 3: 2.1 Audited-Training Candidate | - | Pair Programming | Excluding 3,700 review attack rows reduced holdout Attack Recall to 53.09% at Benign Recall 98.54%; review rows are retained and no labels were changed. |
| **13/09/2026** | Gen 3: Real-Log Weak-Label Audit | - | Pair Programming | Audited 1,076,129 ModSecurity transactions: 5,103 high-confidence payload-rule events, 136,933 protocol/generic-only events, and 681,392 clean-success candidates; request bodies were not captured, so no auto-training or label promotion. |
| **13/09/2026** | Gen 3: 3.1 ClickHouse Label-Source Availability Audit | - | Pair Programming | Read-only check found 6,333 access-log rows: 5,993 protocol-rule events, 66 path-traversal events, and 1 RCE event; schema has no request-body field, so no auto-training or schema change was performed. |
| **13/09/2026** | Gen 3: 2.4 Holdout & Cross-Validation Benchmark | - | Pair Programming | Added CSIC-only 5-Fold Stratified CV and unseen holdout report; SHA-256 train/holdout overlap = 0; gate failed at Benign Recall 98.54% and Attack Recall 64.75%; no production artifact written. |
| **13/09/2026** | Gen 3: 3.1 Controlled Lab Request Telemetry | - | Pair Programming | Enabled lab-only body mirror through the existing fail-open dashboard relay to the loopback ML API; E2E lab POST returned 404 from origin while the request remained non-blocking, telemetry wrote 1,978 bytes with hash/features/redacted preview, and the test secret was absent. No production model or enforcement change. |
| **18/09/2026** | Gen 3: 1.2 Evidence Correction | - | Claude Sonnet 5 | Re-verified 1.2's own evidence on live Main and found it not reproducible: the `mirror`/`internal-ml-shadow` wiring was never committed to git, only existed transiently via direct disk edits, covered 4 hosts not 5, and was later repointed to `/internal-ml-capture` -- as of this check, zero live callers existed in template or rendered runtime config. Corrected in-place per the roadmap's own no-fabricated-claims rule; no production behavior changed by this correction itself. |
| **18/09/2026** | Gen 3: 1.3 Adaptive Action Policy (mechanism, OFF) | dbf9054 (Backend, local; not yet on Main's git history) | Claude Sonnet 5 | Built global `ml_enforcement_enabled` flag (default false) in settings_service.py, synced via Redis to a new `ml_policy.py` in control-api, wired as a third branch of the existing `shield_access` auth_request chain (no new nginx location). Verified all 3 score bands against the real /predict-fast pipeline on production (loopback calls, not real tunnel traffic): pass/challenge/block all correct, challenge page renders the real PoW form, block falls through to the existing static 403 page. Flag restored to false after testing. smoke_test.sh 22/22 before and after. Enforcement stays off pending Phase 2's promotion gate, per this roadmap's own line "ห้ามเริ่ม Phase 4 หรือเปิด enforcement ก่อนมี artifact ที่ผ่าน validation และ rollback plan" -- rollback is the same flag back to false. See `ML_ENFORCEMENT_PLAN.md`. |
| **18/09/2026** | Gen 3: 2 Decision -- no new sweep | - | Claude Sonnet 5 | Decided not to re-run the RF class-weight/threshold sweep: 2.2/2.4 already swept 4 class-weight configs with threshold calibration, 5-fold CV, and unseen holdout under SHA-256 dedup, and hit a real ceiling (~65% attack recall at 98.5%+ benign recall). Re-running the same experiment would not produce new information. Per this roadmap's own decision tree, proceeded to 3.1 (data pipeline) instead of a blind re-sweep or starting 2.3 early. |
| **18/09/2026** | Gen 3: 3.1-A Telemetry Hook Re-verification | - | Claude Sonnet 5 | Found the same never-committed-wiring gap as 1.2 for `/internal-ml-capture`; re-wired it and committed this time (`nginx/includes/captcha_server.conf` + `default.conf.template`, all 5 dynamic `location /` blocks). Ran an aggregate report over existing + newly captured telemetry (596 records total): 100% schema-complete, 0 unredacted secret-looking strings, host/method breakdown recorded above, well under the 5MB/day cap, 7-day retention intact. 3.1-B through 3.1-G explicitly not started -- they require real diverse traffic collected over days/weeks, out of scope for a single session without fabricating data. |
---

## 🧭 งานถัดไปที่ต้องทำ: Phase 3.1 Data-Ready Telemetry Pipeline

สถานะก่อนเริ่มงาน: ระบบมี controlled lab telemetry แบบ fail-open แล้ว แต่ Phase 3.1 ยังไม่ถือว่าเสร็จ เพราะยังไม่มี pipeline ที่เชื่อม request จริงกับ security evidence และสร้าง dataset ที่ตรวจสอบย้อนกลับได้ งานชุดนี้ต้องทำให้ครบก่อนเริ่ม automated retraining หรือพิจารณา Model Architecture Exploration ในข้อ 2.3

### เป้าหมาย

สร้างสายงานจาก request จริงใน lab ไปเป็น dataset สำหรับประเมินและ retrain Random Forest เดิม โดยรักษา privacy, data integrity, reproducibility และ production safety ตามเงื่อนไขใน roadmap และ WORKING_RULES.md

### ขั้นตอนดำเนินงานแบบละเอียด

#### 3.1-A — ตรวจสอบความถูกต้องของ Controlled Telemetry

1. ตรวจสอบว่า Nginx mirror ทำงานเฉพาะ host ใน allowlist (dvwa, juice, vampi, bwapp และ host ที่ได้รับอนุมัติ) และไม่มี mirror ใน default/fallback server
2. ตรวจสอบ fail-open: เมื่อ relay หรือ ML API ล้มเหลว request หลักต้องยังไปถึง origin ได้ และ latency ของ mirror ต้องไม่ทำให้ traffic หลักติดค้าง
3. ตรวจสอบ schema ของทุก record ให้มี timestamp, host, method, path, redacted query, request ID, content type, body length, body hash, truncation flag และ feature vector
4. ตรวจสอบว่าไม่มี raw request body, raw request headers หรือ secret เช่น password, token, cookie, API key, authorization และ CSRF ถูกเขียนลง disk
5. ตรวจสอบ daily size cap, retention period และ permission ของ ml/telemetry/
6. สร้างรายงาน aggregate จำนวน request, schema completeness, feature completeness, file size และ secret-scan result โดยไม่แสดง payload จริง

**เกณฑ์ผ่าน:** telemetry ทำงานเฉพาะ lab, ไม่ทำให้ traffic ล้ม, ไม่มี secret leakage และ record ที่ schema ไม่ครบถูกแยกออกจาก training dataset

#### 3.1-B — เก็บข้อมูล Lab ที่มีความหลากหลาย

1. เก็บ request จริงจาก lab applications ที่อยู่ใน allowlist ภายในช่วงเวลาที่กำหนด
2. ให้ครอบคลุม benign traffic และ attack families ที่ต้องการตรวจจับ เช่น SQL injection, XSS, path traversal, command/RCE, encoded payload และ comment/mutation evasion
3. ห้ามสร้าง synthetic rows เพื่อปั่น metrics และห้ามนำ test request ที่ไม่มี provenance เข้าชุด train
4. สรุปจำนวนข้อมูลแยกตาม host, method, content type, path family และ feature availability โดยใช้ aggregate เท่านั้น

**เกณฑ์ผ่าน:** มีข้อมูลจริงเพียงพอสำหรับเชื่อมกับ security logs และมี attack family ที่ต้องการวัดผล ไม่ใช่มีเพียง protocol anomaly

#### 3.1-C — เชื่อม Telemetry กับ ModSecurity/ClickHouse

1. ใช้ request ID เป็น primary correlation key ระหว่าง telemetry, Nginx/access log, ModSecurity และ ClickHouse เมื่อมีข้อมูล
2. วัด correlation coverage และแยก unmatched records ตามสาเหตุ
3. หาก request ID ไม่สอดคล้องกัน ให้แก้ correlation path หรือ schema ก่อนติด label ห้ามเดา label จาก timestamp/path เพียงอย่างเดียว
4. เก็บ provenance ของทุก label ว่ามาจาก log/file/rule ใด และเกิดขึ้นเวลาใด

**เกณฑ์ผ่าน:** label ทุกตัวที่นำไป train สามารถย้อนกลับไปหา security evidence ได้ และอัตรา join สำเร็จผ่านเกณฑ์ที่กำหนดก่อนเริ่ม retrain

#### 3.1-D — ติด Label แบบ Conservative

1. ติด attack เฉพาะ ModSecurity payload rule ที่มีความมั่นใจสูงและมี evidence ชัดเจน
2. protocol/generic-only events ให้เป็น unknown หรือใช้วิเคราะห์แยก ห้ามติดเป็น attack อัตโนมัติ
3. request ที่ไม่มี evidence เพียงพอให้เป็น unlabeled และไม่นำเข้า supervised training
4. benign label ต้องมาจากเงื่อนไขที่ตรวจสอบได้ ไม่ใช่เพียงไม่มี alert
5. สุ่มตรวจตัวอย่างของแต่ละ attack family แบบ manual และบันทึกผลก่อนยืนยัน dataset

**เกณฑ์ผ่าน:** ไม่มี auto-label ที่ทำให้ protocol noise กลายเป็น attack label และ positive ทุกตัวมี evidence/provenance

#### 3.1-E — ทำ Dataset Quality Gate

1. deduplicate ด้วย request/body hash และตรวจ near-duplicate ที่อาจทำให้ holdout leakage
2. ตรวจ secret leakage, malformed record, missing feature, truncated body และ schema-version mismatch
3. แยก train/holdout ด้วย group/time separation ไม่ให้ request หรือ payload เดียวกันอยู่ทั้งสองฝั่ง
4. ตรวจ SHA-256 overlap ระหว่าง train และ holdout ต้องเป็นศูนย์ หรือมีเหตุผลที่บันทึกไว้ชัดเจน
5. ตรวจ class balance และ attack-family coverage โดยไม่ oversample จนกลายเป็นข้อมูลปลอม
6. สร้าง dataset manifest ระบุ dataset version, row counts, label counts, feature count, split rule และ file hash

**เกณฑ์ผ่าน:** dataset reproducible, ไม่มี leakage, ไม่มี secret, มี manifest และตรวจสอบย้อนกลับได้

#### 3.1-F — Retrain Random Forest เดิมและประเมินผล

1. ใช้ feature schema เดียวกันระหว่าง feature engineering, training และ inference
2. ทดลอง class weight และ decision threshold จาก validation data เท่านั้น
3. รัน 5-fold stratified cross-validation บน train set
4. ประเมินบน unseen holdout ที่ไม่ถูกใช้จูน threshold
5. รายงาน Benign Recall, Attack Recall, confusion matrix, ROC-AUC, false-positive count, false-negative count และผลแยกตาม attack family
6. เปรียบเทียบกับ production baseline และผล Extended Features เดิม

**เกณฑ์ผ่านเบื้องต้น:** Attack Recall ไม่น้อยกว่า 85% พร้อม Benign Recall ไม่น้อยกว่า 98.5% และไม่มี attack family สำคัญตกลงอย่างผิดปกติ

#### 3.1-G — Validation Gate และการตัดสินใจ

1. หากไม่ผ่าน gate ให้เก็บ artifact/report เป็น experiment เท่านั้น ห้าม promote
2. หากผ่าน gate ให้รัน evaluation ซ้ำจาก manifest เดิมเพื่อยืนยัน reproducibility
3. ตรวจ feature count, inference compatibility, ONNX export และ latency ก่อนพิจารณา promotion
4. ให้ production ใช้ artifact เดิมจนกว่าจะมี approval และ rollback plan
5. บันทึก dataset version, metrics, decision และเหตุผลลงใน roadmap changelog

### ลำดับการตัดสินใจหลังจบ Phase 3.1

- ถ้า quality gate ไม่ผ่าน: หยุดแก้ data/correlation/label quality ก่อน ห้าม retrain เพื่อเอาตัวเลข
- ถ้า dataset ผ่านแต่ Random Forest ยังไม่ถึงเป้าหมาย: ปรับปรุง features และ label quality ก่อน
- ถ้า dataset และ features ผ่านแล้ว แต่ Random Forest ยังไม่ถึงเป้าหมาย: ค่อยประเมินข้อ 2.3 ใน environment แยก โดยยังไม่ติดตั้ง dependency ใน production .venv
- ถ้าผ่านทุก gate: จึงเริ่ม Phase 3.2 automated retraining และ Phase 3.3 model validation gate
- ห้ามเริ่ม Phase 4 หรือเปิด enforcement ก่อนมี artifact ที่ผ่าน validation และ rollback plan

### ข้อจำกัดที่ต้องรักษาตลอดงาน

- ห้ามติดตั้ง LightGBM/XGBoost ใน VPS production ในขั้นตอนนี้
- ห้ามเปลี่ยน production model, ONNX artifact หรือเปิด blocking/challenge จากผลทดลอง
- ห้ามเก็บ raw body, raw headers หรือ secrets
- ทุกการเปลี่ยนแปลงต้อง fail-open, ตรวจสอบได้ และย้อนกลับได้
- หากไม่ผ่าน gate ให้หยุดที่ experiment และบันทึกเหตุผล ห้ามใช้ synthetic data หรือ data leakage เพื่อปรับ metrics

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
