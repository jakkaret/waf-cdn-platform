# 🧠 รายงานสรุปการพัฒนา WAF Multi-Dataset ML, Auto Rule Generator & Web Dashboard

เอกสารฉบับนี้สรุปกระบวนการสร้างระบบ **Auto Rule Generator** สำหรับสร้างกฎ ModSecurity WAF SecRule อัตโนมัติจากภัยคุกคามที่ ML ตรวจพบ ควบคู่ไปกับผลการวัดประสิทธิภาพ **Accuracy 93.40% (ROC-AUC 0.9895)** ตามแนวทางใน [ml_deployment_guide](file:///home/chirachot/seminar/waf_project/ml_deployment_guide) และ [ml_ai_proposal.md](file:///home/chirachot/seminar/waf_project/ml_ai_proposal.md)

---

## 🟢 1. สรุปภาพรวมระบบ Auto Rule Generation

เมื่อระบบ ML ตรวจพบภัยคุกคามหรือ Anomaly ทราฟฟิก สคริปต์ [ml/auto_rule_generator.py](file:///home/chirachot/seminar/waf_project/ml/auto_rule_generator.py) จะสกัด Signature Pattern และสร้างกฎ **ModSecurity SecRule** มาตรฐานให้อัตโนมัติ:

```
[ ML Microservice / Playground ] ──> ตรวจเจอ Anomaly Payload (SQLi, XSS, Path Traversal, RCE)
                                             │
                                             ▼
                             [ ml/auto_rule_generator.py ]
                                             │
                        (สกัด Signature Pattern & รัน Rule ID อัตโนมัติ)
                                             ▼
               [ บันทึกลง modsecurity/custom-rules/auto_generated_rules.conf ]
                                             │
                                             ▼
                      [ ซิงค์ไปยัง WAF Edge Nodes (Nginx/ModSec) ]
```

---

## ⚙️ 2. รูปแบบโครงสร้างกฎ ModSecurity ที่ถูก Auto-Generated

สคริปต์จะออกรหัส **Rule ID** ถัดไปให้อัตโนมัติ (เช่น `#1000501`, `#1000502`, `#1000503`) และสร้างคำสั่ง SecRule ดังนี้:

```modsecurity
# ------------------------------------------------------------------------
# ML Auto-Generated WAF Rule (ID: 1000503)
# Created: 2026-08-10 06:37:15 UTC
# Source Target: GET /login?user=admin' OR '1'='1' --
# ------------------------------------------------------------------------
SecRule REQUEST_URI|REQUEST_BODY "@rx or\s+['\"]?1['\"]?\s*=\s*['\"]?1" \
    "id:1000503,\
    phase:2,\
    deny,\
    status:403,\
    severity:CRITICAL,\
    log,\
    msg:'ML Auto-Generated WAF Rule: Blocked SQL Injection Pattern'"
```

---

## 🖥️ 3. การใช้งาน Auto Rule Generator บน Web Application Dashboard

1. เปิดใช้งาน Web Dashboard ที่ **`http://localhost:5000/`**
2. เลือก Quick Preset (เช่น `🚨 SQLi Auth Bypass`) แล้วกด **`⚡ Run Hybrid Model Predict`**
3. เมื่อระบบทำนายผลลัพธ์เป็น **🚨 ANOMALY DETECTED (ATTACK)** ปุ่ม **`⚙️ Auto Generate ModSecurity WAF SecRule`** จะปรากฏขึ้นมา
4. เมื่อกดปุ่มดังกล่าว ระบบจะสร้างโค้ด SecRule อัตโนมัติ แสดงผลบนหน้าเว็บ และบันทึกไปที่ `modsecurity/custom-rules/auto_generated_rules.conf` ทันที

---

## 📂 4. โครงสร้างไฟล์ในโปรเจกต์ (Updated Layout)

```
ml/
├── dataset/
│   ├── csic_final.csv             # ชุดข้อมูล CSIC 2010 (26.11 MB)
│   └── enhanced_payloads.csv      # ชุดข้อมูล Web Attack Payloads เสริม
├── models/
│   ├── random_forest_waf.joblib   # โมเดล Random Forest Classifier (Supervised)
│   ├── isolation_forest_waf.joblib # โมเดล Isolation Forest (Anomaly Score)
│   └── eval_results.json          # ไฟล์เก็บค่า Accuracy (93.40%), ROC Curve, Confusion Matrix
├── dashboard/
│   ├── index.html                 # หน้าเว็บ Single-Page Dashboard & Auto Rule Generator
│   ├── styles.css                 # สไตล์ชีต Cyber Obsidian Theme
│   └── app.js                     # โค้ด JavaScript แสดงผลและยิง API /generate-rule
├── auto_rule_generator.py         # มอดูลสร้าง ModSecurity SecRules อัตโนมัติ
├── download_dataset.py            # สคริปต์ดาวน์โหลดและรวม Multi-Dataset
├── feature_engineering.py         # มอดูลสกัดฟีเจอร์ 14 ตัวแปร (พร้อม URL Decoding)
├── train_model.py                 # สคริปต์ฝึกโมเดล Random Forest + Isolation Forest (Accuracy 93.40%)
└── ml_api.py                      # FastAPI Microservice (Port 5000) สำหรับ Predict & /generate-rule
```

---

## 🚀 5. คำสั่งการรันและทดสอบยิง API Auto Generate Rule

### 1. ทดสอบยิง API สร้างกฎอัตโนมัติจาก Terminal:
```bash
wsl env PYTHONPATH=/home/chirachot/seminar/waf_project /home/chirachot/seminar/waf_project/.venv/bin/python -c "import requests; r=requests.post('http://localhost:5000/generate-rule', json={'url': '/login?user=admin\' OR \'1\'=\'1\' --', 'method': 'GET', 'attack_type': 'SQL Injection'}); print(r.json())"
```

### 2. ดูไฟล์กฎ ModSecurity ที่ถูกบันทึกไว้:
```bash
wsl cat /home/chirachot/seminar/waf_project/modsecurity/custom-rules/auto_generated_rules.conf
```
