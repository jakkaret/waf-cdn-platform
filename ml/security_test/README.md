# วัดการตรวจจับของโมเดล Gen 3 ด้วยเครื่องมือทดสอบ WAF

ชุดนี้วัดว่าโมเดล Gen 3 จับการโจมตีได้แค่ไหน โดยยิงเครื่องมือมาตรฐาน 3 ตัวเข้าที่
harness ในเครื่อง แล้วนับว่าโมเดลตอบ 403 (จับได้) หรือ 200 (ปล่อยผ่าน) กี่ครั้ง

> ⚠️ รันบน **เครื่อง local เท่านั้น** ยิงไปที่ `127.0.0.1` ของตัวเอง
> ห้ามยิงไปที่ VPS production หรือเครื่องที่ไม่ใช่ของตัวเอง (ดู `WORKING_RULES.md`)

## ส่วนประกอบ

| ไฟล์ | หน้าที่ |
| :--- | :--- |
| `waf_test_harness.py` | WAF gate เชิงป้องกัน: รับ request, ให้คะแนนด้วยโมเดล Gen 3, ตอบ 403 เมื่อจับได้ |
| `run_tests.sh` | ยิง GoTestWAF, Nuclei, sqlmap เข้า harness แล้วเก็บรายงาน |
| `summarize.py` | อ่าน `decisions.jsonl` + รายงาน แล้วสรุปเป็น Precision / Recall / F1 |

## เครื่องมือ (binary สำเร็จรูป ไม่ต้องใช้ Docker)

- **GoTestWAF** (Wallarm) — benchmark ประสิทธิภาพ WAF โดยเฉพาะ มีทั้งชุดโจมตีและชุดปกติ
- **Nuclei** (ProjectDiscovery) — template สแกน CVE / หน้า admin / ไฟล์หลุด (โชว์จุดอ่อน probe ที่ไม่มี payload)
- **sqlmap** — ทดสอบว่าโมเดลยังจับ SQLi ที่ถูกดัดแปลง (tamper) ได้ไหม

## ขั้นตอน

```bash
# 1. โมเดลรุ่นปัจจุบัน (F-noopenappsec) อยู่ใน repo แล้วที่ ml/models/gen3/gen3_f_noopenappsec.onnx

# 2. เปิด harness (serve venv มี onnxruntime + libinjection)
WAF_GEN3_ONNX_PATH=ml/models/gen3/gen3_f_noopenappsec.onnx PYTHONPATH=. \
  uvicorn ml.security_test.waf_test_harness:app --host 127.0.0.1 --port 8088

# 3. ยิงเครื่องมือทั้ง 3 (คนละ terminal)
TOOLS=~/.cache/wafprobe/tools bash ml/security_test/run_tests.sh

# 4. สรุปผล
PYTHONPATH=. python ml/security_test/summarize.py
```

รายงานและ log อยู่ใน `reports/` และ `decisions.jsonl` ไม่ขึ้น git (traffic ทดสอบ)

## การตีความ

- harness ตอบ 403 = โมเดลให้คะแนน ≥ threshold (จับว่าเป็นการโจมตี)
- request โจมตีที่ได้ 403 = TP, ที่ได้ 200 = FN (หลุดรอด)
- request ปกติ (GoTestWAF ส่งเอง, หรือ url มี `waf_test=benign`) ที่ได้ 403 = FP
- โมเดลให้คะแนนจาก **URL + body** เท่านั้น การ probe ที่ไม่มี payload (เช่น `/wp-admin`)
  โมเดลจะปล่อยผ่าน ซึ่งตรงกับข้อจำกัดที่ทราบอยู่แล้ว งานนั้นเป็นของ ModSecurity rule
