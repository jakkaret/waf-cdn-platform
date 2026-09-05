# 🚀 แนวทางการนำโมเดล ML ไปใช้งานต่อในระบบ WAF + CDN (ML Integration Guide)

เมื่อทำการฝึกโมเดลและวัดผลสำเร็จแล้ว (**Accuracy 93.40% / ROC-AUC 0.9895**) ไฟล์โมเดล `random_forest_waf.joblib` และ `isolation_forest_waf.joblib` จะถูกนำไปใช้งานต่อในระบบ WAF/CDN ของคุณผ่าน 3 แนวทางหลักตามสเปกใน [ml_deployment_guide](file:///home/chirachot/seminar/waf_project/ml_deployment_guide) ดังนี้:

---

## 🏗️ ภาพรวมสถาปัตยกรรม (Architecture Diagram)

```
[ User Request ] ──> [ WAF / CDN Node (Nginx + ModSec) ] ──(ส่งตอบกลับรวดเร็ว 0ms)──> [ Origin Server ]
                              │
                    (เขียน Log อะซิงโครนัส)
                              ▼
                      [ ClickHouse DB / Log Stream ]
                              ▲
                              │ (ดึง Log มาวิเคราะห์)
                              ▼
                [ ML Service (ml/ml_api.py - Port 5000) ]
                              │
              (ตรวจเจอ Anomaly / IP โจมตีซ้ำซ้อน)
                              ▼
              [ สั่งอัปเดตกฎบล็อก IP / แจ้งเตือน Telegram ]
```

---

## 🎯 3 แนวทางการนำไปต่อยอดใช้งานจริง

### แนวทางที่ 1: การวิเคราะห์ Log เบื้องหลัง (Asynchronous Log Analysis) — ⭐ [แนะนำที่สุด]

เป็นแนวทางตามที่อาจารย์แนะนำ เพื่อป้องกันปัญหาความเสียหายลุกลาม (Domino Effect) และทำให้หน้าเว็บของผู้ใช้งานรวดเร็วที่สุด (Zero Latency Overhead)

* **วิธีการทำงาน:**
  1. ตัว **WAF / CDN Edge Node** (Nginx + ModSecurity) ทำหน้าที่ประมวลผลคำขอและเขียน Log ลงตาราง ClickHouse DB `access_logs` หรือไฟล์ Log
  2. สร้างสคริปต์ **ML Worker** (เช่น [ml/async_log_analyzer.py](file:///home/chirachot/seminar/waf_project/ml/async_log_analyzer.py)) ให้คอยดึง Log มายิงยิงหา `http://localhost:5000/predict`
  3. หากพบไอพีใดมีค่า `attack_probability > 90%` หรือพยายามยิงการโจมตีซ้ำๆ ให้สคริปต์สั่งเพิ่ม IP นั้นเข้า **Blacklist** ใน ClickHouse หรือ Nginx Deny Rules
* **ข้อดี:**
  - **Zero Latency:** ผู้ใช้เข้าเว็บได้อย่างรวดเร็ว ไม่ต้องรอให้โมเดลประมวลผลก่อนโหลดหน้าเว็บ
  - **No Domino Effect:** หากบริการ ML ดับไป ตัว CDN และ WAF หลักของเว็บไซต์ยังทำงานได้อย่างสมบูรณ์ 100%

---

### แนวทางที่ 2: การตรวจสอบแบบเรียลไทม์ผ่าน Nginx Lua (Synchronous Real-Time Check)

หากต้องการให้ WAF ส่งข้อมูลมาถามโมเดลทันทีก่อนส่งต่อให้เครื่องปลายทาง (Origin Server)

* **วิธีการทำงาน:**
  1. ใน Nginx / OpenResty ให้เขียน Lua Script (`access_by_lua_block`) เพื่อยิง HTTP POST ไปที่ `http://127.0.0.1:5000/predict`
  2. หากโมเดลตอบกลับมาว่า `{"is_anomaly": true}` ให้ Nginx คืนค่า `HTTP 403 Forbidden` ทันที
  3. **⚠️ นโยบาย Fail-Open (สำคัญมาก):** ต้องตั้งค่า Timeout ไว้น้อยมาก (เช่น **30ms**) หาก ML ตอบช้าหรือล่ม ให้ Nginx ปล่อยผ่านคำขอนั้นไปเลยทันทีเพื่อไม่ให้เว็บหลักล่มตาม
* **ตัวอย่างการตั้งค่า Nginx Lua (`default.conf.template`):**
  ```nginx
  access_by_lua_block {
      local http = require "resty.http"
      local hc = http.new()
      hc:set_timeout(30) -- Timeout 30ms (Fail-Open)
      
      local res, err = pcall(function()
          return hc:request_uri("http://127.0.0.1:5000/predict", {
              method = "POST",
              body = ngx.req.get_body_data(),
              headers = { ["Content-Type"] = "application/json" }
          })
      end)
      
      -- หาก ML ตอบกลับมาว่าเป็น Attack ให้บล็อกทันที
      if res and res.status == 200 and string.find(res.body, '"is_anomaly":true') then
          ngx.exit(ngx.HTTP_FORBIDDEN)
      end
  }
  ```

---

### แนวทางที่ 3: การส่งวิเคราะห์ร่วมกับ Gemini AI (Daily Security Summary Report)

เป็นการทำงานร่วมกันระหว่าง **ML (Isolation Forest / Random Forest)** และ **Generative AI (Gemini)** ตามข้อเสนอใน [ml_ai_proposal.md](file:///home/chirachot/seminar/waf_project/ml_ai_proposal.md)

* **วิธีการทำงาน:**
  1. ทุกๆ 24 ชั่วโมง (เช่น เวลาเที่ยงคืน) ระบบหลังบ้านจะรวบรวมสถิติทราฟฟิกและผลการวิเคราะห์จาก ML
  2. ส่งข้อมูลสรุปประจำวันไปให้ **Gemini Reasoning API** เพื่อให้ AI ทำหน้าที่เป็น **SOC Manager** ช่วยวิเคราะห์พฤติกรรมการโจมตี
  3. Gemini จะเขียนบทสรุปภาพรวมพร้อมเสนอแนะ **SecRule (WAF Custom Rules)** ส่งเข้า Telegram Admin Bot

---

## 🛠️ ขั้นตอนการเริ่มเปิดใช้งาน ML Service (Step-by-Step Guide)

### ขั้นตอนที่ 1: รัน ML Microservice เป็น Background Process
```bash
# รัน ML API Service ที่พอร์ต 5000 ในเบื้องหลัง
wsl env PYTHONPATH=/home/chirachot/seminar/waf_project /home/chirachot/seminar/waf_project/.venv/bin/python ml/ml_api.py
```

### ขั้นตอนที่ 2: รัน Real-time Log Stream Analyzer (Worker)
```bash
# รัน Worker สแกน Log เรียลไทม์
wsl env PYTHONPATH=/home/chirachot/seminar/waf_project /home/chirachot/seminar/waf_project/.venv/bin/python ml/async_log_analyzer.py
```

### ขั้นตอนที่ 3: ทดสอบยิง Request เพื่อดูผลการวิเคราะห์
```bash
# ยิงคำขอปกติ
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "/index.html", "method": "GET"}'

# ยิงคำขอโจมตี SQL Injection
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "/login?user=admin'\'' OR '\''1'\''='\''1'\'' --", "method": "GET"}'
```
