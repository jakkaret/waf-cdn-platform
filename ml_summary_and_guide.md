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

---

## 🧠 6. สรุปภาพรวมและสถาปัตยกรรมของโฟลเดอร์ `ml` (WAF Intelligence Layer)

### 6.1 ใช้อะไร (What is used)
* **Machine Learning Models**: 
  * `RandomForestClassifier` (Supervised Learning) สำหรับจับการโจมตีรูปแบบที่รู้จัก (Known attacks)
  * `IsolationForest` (Unsupervised Learning) สำหรับตรวจจับความผิดปกติ (Anomaly Detection) จากข้อมูลปกติ
* **API Framework**: ใช้ `FastAPI` (Python) รันบนพอร์ต 5000 เพื่อให้บริการ API (`/predict`, `/generate-rule`) 
* **Feature Engineering**: สคริปต์สกัดคุณลักษณะ (Features) (`feature_engineering.py`) จะแปลง HTTP Request เป็นฟีเจอร์ตัวเลข 14 ชนิด (เช่น ค่า Entropy, อัตราส่วนอักขระพิเศษ, คำต้องห้าม) แบบรองรับ URL Decoding
* **Data/Stats**: ใช้ `pandas`, `numpy`, `scikit-learn` และเซฟโมเดลเป็นไฟล์ผ่าน `joblib`
* **Log Processing**: สคริปต์ `async_log_analyzer.py` สำหรับ Tail อ่านไฟล์ Log แบบ Real-time เพื่อส่งวิเคราะห์

### 6.2 ใช้ทำไม (Why is it used)
ใช้เพื่อเป็น **"สมอง (Intelligence Layer)"** ให้กับ WAF แบบเดิม (ModSecurity) ที่พึ่งพาแค่ Rule-based การใช้ ML จะช่วยรับมือกับ Payload Obfuscation (การแปลงโค้ด/เข้ารหัสตัวอักษรเพื่อหลบเลี่ยง) และช่วยตรวจจับ Zero-day Attack ได้ดีกว่าการดักจับ Keyword ตายตัว

### 6.3 เพราะอะไรถึงใช้ (Why these specific tools/models)
* **Random Forest**: ถูกเลือกใช้เพราะให้ความแม่นยำสูงมาก (>85-95%) สำหรับชุดข้อมูลที่มี Label (เช่น CSIC 2010 dataset) และจัดการกับข้อมูลที่ซับซ้อนได้ดีโดยไม่ค่อยเกิด Overfitting
* **Isolation Forest**: เหมาะสำหรับการหา "สิ่งที่ผิดปกติไปจากธรรมชาติ" โดยให้มันเรียนรู้จากข้อมูล "Request ปกติ" เพียงอย่างเดียว หากเจอสิ่งที่แปลกไปจากธรรมชาติจะถูกตีเป็น Anomaly Score เหมาะมากกับการจับ Zero-day
* **FastAPI**: ประมวลผลรวดเร็ว (High performance) เหมาะสำหรับทำ API รับ HTTP Request จำนวนมหาศาลจาก WAF

### 6.4 ดียังไง (What are its benefits)
* **ตรวจจับการหลบเลี่ยง (Evasion) ได้ดี**: ระบบถอดรหัส URL (URL Decoding) และนำมาคำนวณค่าทางสถิติ (เช่น นับวงเล็บ, สัดส่วนอักขระพิเศษ, ค่าความมั่ว Entropy) ทำให้เทคนิคการเลี่ยง WAF ตกม้าตาย
* **ผสมผสานจุดแข็ง (Hybrid Ensemble)**: ได้ความชัวร์จาก Random Forest ควบคู่กับความสามารถในการหาของแปลกจาก Isolation Forest 
* **Auto-Remediation**: หากเจอของแปลก จะสร้างกฎ WAF Rule กลับไปป้องกันอัตโนมัติได้ทันที (`/generate-rule`)

### 6.5 ทำอะไรได้ (What it can do)
* ดึงค่าพารามิเตอร์ของ Request (Method, URL, Body) มาสกัดเป็นฟีเจอร์ทางสถิติ 14 ตัว
* พยากรณ์ผ่าน API (`/predict`) ว่า Request นั้นเป็น `PASS` (ปกติ) หรือ `ANOMALY_DETECTED` (ถูกโจมตี) พร้อมแจ้งระดับความน่าจะเป็น
* Generate กฎของ ModSecurity (SecRule) ในรูปแบบ Regular Expression อัตโนมัติ เพื่อบล็อกในครั้งถัดไป
* อ่าน Log สตรีมของ WAF เพื่อเช็ค Traffic แบบตามหลัง (Asynchronous Analysis)

---

## 🚧 7. ข้อจำกัดและแนวทางแก้ไข (Limitations & How to Implement Solutions)

สิ่งที่ระบบปัจจุบันทำไม่ได้ หากต้องการให้ระบบทำงานได้สมบูรณ์ขึ้น ต้องแก้ไขและเพิ่มเติมระบบดังต่อไปนี้แบบละเอียด:

### 7.1 ไม่ได้ Block Traffic ด้วยตัวเองแบบ Real-time (Not Inline Blocking)
**ปัญหา:** ตัว ML ปัจจุบันทำงานเป็นเพียงแค่ API service ยืนรอรับ Request ไม่มีอำนาจ Drop Connection ของผู้โจมตีด้วยตัวเอง ต้องรอให้ Log analyzer ส่งข้อมูลมาถาม ซึ่งเป็นการตรวจจับแบบตามหลัง (Asynchronous)
**วิธีแก้ไข (How to Implement):**
มี 2 แนวทางหลักในการทำให้บล็อกได้จริง:
1. **บล็อกแบบ Real-time (Inline Blocking ผ่าน NGINX):**
   * **เครื่องมือ:** ติดตั้ง `lua-nginx-module` หรือ `njs` (NGINX JavaScript) เข้าไปที่ NGINX Proxy
   * **การทำงาน:** เข้าไปแก้ไฟล์ `nginx.conf` โดยเพิ่ม Script เข้าไปใน HTTP `access` phase ให้ NGINX ทำการพัก Request ของผู้ใช้ไว้ก่อน แล้วทำการส่ง HTTP Sub-request ที่มี payload ของผู้ใช้ ยิงไปหา API `http://ml_api:5000/predict` 
   * **การบล็อก:** หาก ML ตอบสถานะกลับมาว่า `"is_anomaly": true` ให้ Script สั่งให้ NGINX คืนค่า `HTTP 403 Forbidden` ให้ผู้ใช้ทันที (วิธีนี้ชัวร์ที่สุดแต่แลกกับ Latency ที่เพิ่มขึ้นต่อ Request)
2. **บล็อกแบบ IP Ban (ทำงานร่วมกับระบบ OS / Firewall):**
   * **การแก้ไขโค้ด:** เข้าไปแก้ไฟล์ `async_log_analyzer.py` ในส่วนที่จับได้ว่ามีการโจมตี (`if result.get("is_anomaly"):`)
   * **การบล็อก:** ให้สคริปต์สั่งรัน Command ระดับ OS เช่น `os.system(f"iptables -A INPUT -s {ip} -j DROP")` สำหรับ Linux หรือทำการอัปเดตไฟล์ NGINX `deny_ip.conf` โดยการเขียน `deny <IP>;` ต่อท้ายไฟล์ แล้วสั่งรัน `os.system("nginx -s reload")` (คล้ายการทำงานของ Fail2Ban)

### 7.2 ไม่ได้เข้าใจ Data Structure เชิงลึก (No Deep Semantic Analysis)
**ปัญหา:** โมเดลไม่ได้ทำการแยกส่วน (Parse) โครงสร้างข้อมูลอย่าง JSON หรือ XML Body เชิงลึก และไม่ได้เข้าใจ Syntax ของ SQL ว่าเป็นคำสั่งอะไรจริงๆ โมเดลแค่เอา String มาต่อกันและวิเคราะห์ลักษณะทางสถิติของข้อความ
**วิธีแก้ไข (How to Implement):**
1. **สำหรับ JSON / XML Object (โครงสร้าง Payload):**
   * **การแก้ไข:** ในฟังก์ชัน `extract_features_from_request` ของไฟล์ `feature_engineering.py` ให้ดึง Header (ต้องให้ API รับค่า Headers เข้ามาด้วย) มาเช็ค `Content-Type`
   * หากเป็น `application/json` ให้ใช้ไลบรารี `json.loads(body)` พยายามแปลงข้อมูลกลับเป็น Dictionary
   * วิเคราะห์ลึกไปถึงโครงสร้าง: นับความลึกของ Nested Object (Depth), จำนวน Keys, หรือโยน Value ของแต่ละ Key แตกเป็นชุดเล็กๆ เพื่อสกัดฟีเจอร์แยกทีละตัว จะช่วยจับ SQLi ที่ซ่อนอยู่ใน JSON value เดี่ยวๆ ได้แม่นขึ้น
2. **สำหรับ SQL Injection (ใช้ AST - Abstract Syntax Tree):**
   * **เครื่องมือ:** ติดตั้งไลบรารีของ Python เช่น `sqlparse` 
   * **การแก้ไข:** เมื่อได้รับ Query String หรือ Body ให้ทดลองนำไป Parse ผ่าน `sqlparse.parse()` เพื่อวาดโครงสร้างต้นไม้ของคำสั่ง (AST) 
   * หาโครงสร้างต้นไม้ที่ผิดธรรมชาติ (เช่น มี Statement ที่ไม่ปกติ อย่าง `UNION` ข้าม Table หรือ Expression `OR 1=1` ไปอยู่ผิดที่) แล้วบวกค่า `sql_ast_anomaly_score`
   * จากนั้นนำค่า Score ใหม่นี้บรรจุลงในลิสต์ `FEATURE_COLUMNS` และทำการรันสคริปต์ `train_model.py` ใหม่อีกครั้งเพื่อ Retrain

### 7.3 ไม่ได้วิเคราะห์ HTTP Headers แบบละเอียด
**ปัญหา:** การสกัดฟีเจอร์ปัจจุบันโฟกัสแค่ URL path, Query string, Method และ Body (Headers สำคัญๆ อย่าง User-Agent, Cookie, Referer ยังไม่ได้ถูกสกัดมาเป็นฟีเจอร์)
**วิธีแก้ไข (How to Implement):**
1. **อัปเดต Schema API:** ไปที่ `ml_api.py` แก้ไขคลาส `PredictionRequest` ให้ยอมรับพารามิเตอร์ `headers: dict = {}` เข้ามา
2. **สกัด Feature เพิ่ม:** เปิด `feature_engineering.py` และเพิ่มการอ่านสถิติจาก Headers:
   * `missing_user_agent`: = 1 ถ้า Request นั้นไม่มี `User-Agent` (บอตส่วนใหญ่มักไม่ค่อยใส่)
   * `user_agent_entropy`: หาความมั่ว (Shannon Entropy) ของ `User-Agent` string (จับพวกบอตสุ่ม User-Agent ประหลาด)
   * `abnormal_content_type`: ตรวจสอบความถูกต้องว่าค่า Header สอดคล้องกับ Body จริงหรือไม่
3. **Retrain Models:** นำตัวแปรที่ดึงมาใหม่นี้ใส่ใน Return ของ `extract_features_from_request` อัปเดต `FEATURE_COLUMNS` ให้ครอบคลุม และรัน `train_model.py` ใหม่เพื่อให้ Random Forest อัปเดตน้ำหนักความสำคัญของฟีเจอร์เหล่านี้
