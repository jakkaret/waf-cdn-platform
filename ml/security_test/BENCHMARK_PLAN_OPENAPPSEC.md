# แผนเทียบระบบ WAF ของเรากับผลิตภัณฑ์อื่นด้วย open-appsec WAF Comparison

> สถานะ: **กำลังทำ — อัปเดต 3 ต.ค. 2569** บนเครื่องใหม่ (WSL2 + Docker)
> ขั้นที่ 1, 2, 3 เสร็จสมบูรณ์ · ขั้นที่ 4 (วัดจริงแบบ --fast) ได้ผลระบบ K, A, D แล้ว · เหลือระบบ B, C และรอบเต็ม
> ทุกการทดสอบรันบน Docker ในเครื่อง ไม่แตะ VPS production และไม่มีค่าใช้จ่าย · branch `trainmodelgen3`

**เริ่มงานต่อบนเครื่องใหม่: ไปที่หัวข้อ 11 และ 12 ได้เลย**

## 1. เป้าหมาย

วัดระบบของเราด้วยชุดทดสอบและเครื่องมือ **ชุดเดียวกับที่ open-appsec ใช้วัด 14 ผลิตภัณฑ์ในปี 2026**
แล้ววางตัวเลขของเราไว้ในตารางเดียวกัน (True Positive Rate, False Positive Rate, Balanced Accuracy)

เหตุที่เลือกชุดนี้เป็นตัวเทียบหลัก:

| เกณฑ์ | open-appsec WAF Comparison | GoTestWAF | SecureIQLab |
| :--- | :--- | :--- | :--- |
| รันเองได้ | ได้ (โค้ด Apache 2.0, malicious dataset MIT) | ได้ | ไม่ได้ (ชุด attack ของแล็บ) |
| มีผลของเจ้าอื่นให้เทียบ | 14 ผลิตภัณฑ์ ปี 2026 | ค่าอ้างอิงของ Wallarm (ไม่ระบุวันที่) | มี แต่รันซ้ำไม่ได้ |
| ขนาด | ปกติ 1,040,242 / โจมตี 73,924 | 816 request | ~1,600 attack |

ข้อควรระวัง: ผลที่เผยแพร่ทำโดย **Check Point** (เจ้าของ open-appsec) แต่เปิด dataset และเครื่องมือให้รันซ้ำได้

## 2. ข้อมูลที่ตรวจแล้ว

| รายการ | ค่า |
| :--- | :--- |
| Repo | https://github.com/openappsec/waf-comparison-project (commit ที่อ่าน: `8ec8263`, 11 ก.พ. 2026) |
| Docker image | `ghcr.io/openappsec/waf-comparison-project:latest` |
| Legitimate dataset | `https://downloads.openappsec.io/waf-comparison-project/legitimate.zip` · 1,203,983,791 bytes · last-modified 1 ธ.ค. 2024 · sha256 `58faee18…d778` |
| Malicious dataset | `https://downloads.openappsec.io/waf-comparison-project/malicious.zip` · 452,537 bytes · last-modified 17 ก.ค. 2023 · sha256 `131314e5…b7b2b` |
| ตัวเลือกของเครื่องมือ | `--waf-name`, `--waf-url` (หลายคู่ได้), `--max-workers` (ค่าเริ่มต้น 4), `--fast` (สุ่ม 15% seed 42), `--fresh-run` (ลบเฉพาะ DB/config/log ไม่ลบ dataset) |
| ผลลัพธ์ | `results/waf-comparison-report.pdf` + ฐานข้อมูล DuckDB `results/db/waf_comparison.duckdb` |

### วิธีที่เครื่องมือตัดสิน (อ่านจากโค้ด `helper.py`, `report/data_loader.py`)
- **บล็อก** = status **403** หรือหน้าเว็บมีข้อความ block page ของ F5 · status อื่น (200, 400, 404 …) = ไม่บล็อก
- **timeout 0.5 วินาที** ลอง 3 ครั้ง ถ้ายังไม่ได้ จะบันทึก status 0
- **request ที่ได้ status 0 ถูกตัดออกจากทั้ง TPR และ FPR** → ต้องรายงานจำนวนที่ถูกตัดทุกรอบ ถ้ามาก ผลเชื่อไม่ได้
- ก่อนเริ่ม เครื่องมือตรวจ: `GET <url>` ต้องได้ 200 และ `<url>/?a=<script>alert(1)</script>` ต้องโดนบล็อก ไม่งั้นหยุด
- ส่ง request ทีละไฟล์ ไฟล์ละระบบ (ระบบแรกครบก่อนแล้วค่อยระบบถัดไป) แล้วเขียนผลลง DuckDB

### dataset ที่นับจริงหลังแตกไฟล์
| ชุด | จำนวน |
| :--- | ---: |
| Legitimate | **1,040,242** request จาก **692 ไฟล์ (692 เว็บ)** — ตรงกับบทความปี 2026 |
| Malicious | **73,924** — บทความปี 2026 ระบุ 74,284 (ต่าง 360) |
| แยก malicious | xss 41,888 · traversal 28,314 · cmdexe 2,468 · sqli 916 · log4shell 220 · xxe 70 · shellshock 48 |

ข้อสังเกต: malicious เป็น **XSS + path traversal รวม 95%** มี SQLi แค่ 916 ตัว → TPR ของชุดนี้สะท้อนการจับ XSS/traversal เป็นหลัก

### ผลที่เผยแพร่ (open-appsec, ม.ค. 2026 แก้ไข ก.พ. 2026)

| WAF | การตั้งค่า | True Positive | False Positive | Balanced Accuracy |
| :--- | :--- | ---: | ---: | ---: |
| open-appsec / CloudGuard WAF | Critical Profile | 99.47% | 0.563% | 99.453% |
| open-appsec / CloudGuard WAF | Default Profile | 99.56% | 0.994% | 99.283% |
| F5 NGINX App Protect | Default Profile | 91.009% | 2.868% | 94.071% |
| F5 NGINX App Protect | Strict Profile | 97.907% | 25.4% | 86.254% |
| F5 BIG-IP Advanced WAF | Rapid Deployment Policy | 79.039% | 2.894% | 88.072% |
| AWS WAF | Managed + F5 Rules | 80.445% | 6.133% | 87.156% |
| AWS WAF | AWS Managed Ruleset | 79.891% | 6.046% | 86.922% |
| NGINX ModSecurity | OWASP CRS 4.20.0 | 92.257% | 18.638% | 86.81% |
| Cloudflare WAF | Managed + OWASP CRS | 63.462% | 0.06% | 81.701% |
| Microsoft Azure WAF | OWASP CRS 3.2 | 97.537% | 54.412% | 71.562% |
| Fortinet FortiAppSec | Default Configuration | 70.143% | 21.388% | 74.378% |
| Google Cloud Armor | ModSecurity (Sensitivity 2) | 91.006% | 56.999% | 67.004% |
| Barracuda WAF | Default (Modified) | 34.32% | 18.197% | 58.061% |
| Imperva Cloud WAF | Default Configuration | 11.97% | 0.009% | 55.981% |

ที่มา: https://www.openappsec.io/post/best-waf-solutions-in-2026-real-world-comparison

## 3. ปัญหาหลัก: ข้อมูลรั่ว (data leakage)

- โมเดล Gen 3 รุ่น F-canon2 (ตัวหลักใน git) เทรนด้วย `openappsec_legitimate.jsonl` (97,378 แถว) และ `openappsec_malicious.jsonl` (66,373 แถว)
- ทั้งสองไฟล์สร้างจาก **zip ชุดเดียวกับ benchmark** (`ml/prepare_external_datasets.py` ดาวน์โหลดจาก URL เดียวกัน ไฟล์ตรงกันทุก byte)
- ถ้าวัดด้วยโมเดลนี้ ผลจะสูงเกินจริง ใช้เทียบกับเจ้าอื่นไม่ได้

วิธีแก้:
1. **ใช้โมเดลรุ่นที่ไม่ใช้ OpenAppSec เลย** (CSIC + SR-BH เท่านั้น) — เทรนแล้ว (ข้อ 10.4)
2. ตรวจ overlap ด้วย SHA-256 ของ request ระหว่าง benchmark กับข้อมูลเทรนของรุ่นนี้ ต้องเป็น 0 (หรือรายงานจำนวนถ้าไม่เป็น 0)
3. ไม่ใส่ผลของ F-canon2 เดิมในตาราง (ข้อ 9)

**CRS ล้วนไม่มีปัญหานี้** เพราะไม่ได้เรียนรู้จากข้อมูล

## 4. กติกาการวัด (ตั้งก่อนเห็นผล ห้ามปรับหลังเห็นผล)

- **ห้ามปรับ threshold หรือ rule โดยดูผลจาก benchmark**
  - threshold ของ ML ใช้ค่าจาก model card (benign ผ่าน 99% บน OOF ของข้อมูลเทรน) และค่าคงที่ 0.99 ที่เลือกไว้ก่อนแล้ว
- **ห้ามเอา request ของ benchmark ไปเทรน**
- CRS ใช้ค่าเดียวกับ production: PL1, inbound anomaly threshold 5 (`modsecurity/custom-rules/00-modsecurity-override.conf`)
- ทุกแถวของเราต้องระบุว่า "วัดเองบน replica ในเครื่อง" และแนบ PDF ของเครื่องมือ
- ทุกรอบต้องรายงานจำนวน request ที่ถูกตัดเพราะ status 0

## 5. ระบบที่จะวัด

| รหัส | ระบบ | Image / Backend | หมายเหตุ |
| :--- | :--- | :--- | :--- |
| **K** | CRS 4.20.0 ค่าเริ่มต้น | `owasp/modsecurity-crs:4.20.0-nginx-202511100111` → stub | ใช้ตรวจวิธีวัด (ขั้นที่ 2) |
| **A** | CRS 3.3.8 PL1 anomaly 5 | `owasp/modsecurity-crs:nginx` → stub | **ตรงกับ production** |
| **B** | A + ML (threshold 0.99) | CRS 3.3.8 → ML harness | ค่าที่ได้คะแนน GoTestWAF ดีสุด |
| **C** | A + ML (threshold จาก model card) | CRS 3.3.8 → ML harness | ค่าตามที่โมเดลกำหนด |
| **D** | ML อย่างเดียว (threshold จาก model card) | ML harness ตรง | ดูความสามารถของโมเดลล้วน |

ML ใน B / C / D = โมเดลรุ่นไม่ใช้ OpenAppSec (`gen3_f_noopenappsec.onnx`, threshold ใน card 0.8749)
stub = `traefik/whoami` (ตอบ 200 ทุก method ทุก path)

## 6. ขั้นตอน (checklist)

### ขั้นที่ 1 — ติดตั้งและตรวจเครื่องมือ ✅
- [x] clone repo และอ่านโค้ดว่าตัดสิน "บล็อก" อย่างไร (ข้อ 2)
- [x] harness ตอบ 403 เมื่อ ML บล็อก ตรงกับที่เครื่องมือเข้าใจ — ไม่ต้องแก้
- [x] ใช้ zip ที่มีอยู่แล้ว แตกลง `results/datasets/` (ไม่ต้องโหลด 1.2 GB ใหม่)
- [x] นับจำนวน request จริง (ข้อ 2)
- [ ] ~~ทดสอบกับ stub ที่ไม่บล็อก / บล็อกทุกอย่าง~~ — ทำไม่ได้ เครื่องมือหยุดถ้า health/functional check ไม่ผ่าน ใช้ calibration กับ K แทน

### ขั้นที่ 2 — calibration ✅ (เสร็จสมบูรณ์ 3 ต.ค. 2569)
- [x] ตรวจเวอร์ชัน CRS: `owasp/modsecurity-crs:nginx` = **CRS 3.3.8** จึง pin tag `4.20.0-nginx-202511100111` ให้ K
- [x] รัน **K** และ **A** แบบ `--fast` ครบ 699 ไฟล์บนเครื่องใหม่ (ข้อ 10.5)
- [x] ตรวจสอบผล: TPR ของ K ผ่านเกณฑ์ (90.142% vs เผยแพร่ 92.257% ต่าง -2.115 อยู่ในเกณฑ์ ±3), FPR ได้ 34.600% (สูงกว่าที่เผยแพร่ 18.638%), status 0 อยู่ที่ 2.69%

### ขั้นที่ 3 — โมเดลที่ไม่ใช้ OpenAppSec ✅ (เหลือตรวจ overlap)
- [x] เพิ่ม `--exclude-dataset NAME` ใน `ml/train_final_gen3.py` (commit `c1d3d58e`) ทดสอบด้วยข้อมูลจำลองแล้ว
- [x] notebook: `FINAL_FEATURE_SETS = ["F"]`, `FINAL_EXCLUDE_DATASETS = ["OpenAppSec"]`, `EXPERIMENT_MODE = "none"`
- [x] เทรนบน Colab แล้ว: `gen3-final-f-noopenappsec-20261002-153004` (ข้อ 10.4)
- [x] ดาวน์โหลด ONNX มาวางที่ `ml/models/gen3/gen3_f_noopenappsec.onnx` แล้ว
- [ ] ตรวจ overlap ด้วย SHA-256 ระหว่าง benchmark กับข้อมูลเทรนของรุ่นนี้ (CSIC + SR-BH)

### ขั้นที่ 4 — วัดจริง
- [x] รอบทดลอง `--fast` (16 workers): K, A, D เสร็จสมบูรณ์ (ข้อ 10.5 และ 10.7)
- [ ] รอบทดลอง `--fast`: เหลือ B (CRS+ML@0.99) และ C (CRS+ML@card)
- [ ] จับเวลารอบ `--fast` แล้วประมาณเวลารอบเต็ม
- [ ] รอบจริง: K, A, B, C, D แบบเต็ม (1.1 ล้าน request ต่อระบบ) — ตัวเลขที่ใช้ในตารางมาจากรอบนี้
- [x] เก็บ PDF, DuckDB, `summary-*.txt` และ log ของ harness ทุกรอบไว้ใน `~/waf-bench/results/` (ไม่ขึ้น git)

### ขั้นที่ 5 — วิเคราะห์
- [ ] คำนวณ TPR, FPR, Balanced Accuracy ของทุกระบบ (`summarize_db.py`)
- [ ] แยกตามประเภทการโจมตี (ชื่อไฟล์ malicious = ประเภท) เทียบ A กับ B ว่า ML เติมตรงไหน
- [ ] สุ่มดู request ปกติที่โดนบล็อก (FP) ของ B และ D อย่างละ 50 ตัว จัดกลุ่มสาเหตุ
- [ ] เทียบกับผลของ GoTestWAF ว่าทิศทางตรงกันไหม

### ขั้นที่ 6 — สรุปผล
- [ ] `ml/security_test/RESULTS_OPENAPPSEC_BENCHMARK.md`: ตารางรวม 14 แถวที่เผยแพร่ + K, A–D ของเรา พร้อมคอลัมน์ "ที่มา"
- [ ] อัปเดตคู่มือ WAF Gen 3 และสไลด์
- [ ] commit และ push เฉพาะ branch `trainmodelgen3` (รายงานและสคริปต์ ไม่รวม dataset)

## 7. ข้อจำกัดที่ต้องเขียนไว้ในรายงาน

1. เจ้าอื่นวัดบนบริการจริงบน AWS ส่วนเราวัดบน replica ในเครื่อง — ผลขั้นที่ 2 บอกว่าต่างกันแค่ไหน
2. ผลที่เผยแพร่ทำโดย Check Point ซึ่งเป็นเจ้าของ open-appsec
3. dataset สาธารณะอาจไม่ใช่ชุดเดียวกับที่ใช้วัดปี 2026 ทุก request (malicious 73,924 กับ 74,284)
4. ML ในตารางเป็นรุ่นที่ไม่ใช้ OpenAppSec — ความสามารถจริงของรุ่นที่ใช้งาน (F-canon2) บนข้อมูลชุดนี้วัดอย่างยุติธรรมไม่ได้
5. benchmark นี้วัดเฉพาะ request เดี่ยว ไม่วัด bot, DDoS, rate limit และ API protocol
6. request ที่ timeout (status 0) ถูกเครื่องมือตัดออก — รายงานจำนวนทุกรอบ
7. nginx ของ replica ตอบ 400 กับ request ปกติบางตัว (เช่น parse body ไม่ได้) เครื่องมือนับว่า "ไม่บล็อก"
8. production ใช้ CRS 3.3.8 ส่วนแถวที่เผยแพร่ใช้ CRS 4.20.0 — ระบบ A เทียบกับแถว ModSecurity ตรงๆ ไม่ได้ ต้องดูคู่กับ K

## 8. ทรัพยากร

| รายการ | ค่า |
| :--- | :--- |
| ค่าใช้จ่าย | 0 บาท (Docker, Colab ฟรี, เครื่องตัวเอง) |
| ดิสก์ | dataset แตกแล้ว ~7 GB + zip 1.2 GB + DB/log ~2–5 GB ต่อรอบเต็ม · เผื่อว่าง ≥ 20 GB |
| RAM ที่ benchmark ใช้จริง | tool ~250 MB, CRS ~70–90 MB/ตัว, stub ~10 MB, ML harness ~250–300 MB/ตัว |
| RAM ที่แนะนำของเครื่อง | ≥ 16 GB (เครื่องเดิม 7.8 GB เหลือว่าง 0.6 GB ระหว่างรัน → ช้าและ timeout) |
| CPU ที่แนะนำ | ≥ 8 core |
| เวลา | ดูข้อ 10.6 |

## 9. การตัดสินใจ (2 ต.ค. 2569)

- [x] **รอบเต็ม** สำหรับทุกระบบที่ขึ้นตาราง (ผลที่เผยแพร่วัดจาก dataset เต็ม) — รัน `--fast` ก่อนเพื่อจับเวลาและตรวจความถูกต้อง
- [x] **เทรนโมเดลรุ่นที่ไม่ใช้ OpenAppSec** (ขั้นที่ 3) — จำเป็นสำหรับการเทียบที่ยุติธรรม
- [x] **ไม่ใส่ผลของ F-canon2 เดิมในตาราง** — เขียนเหตุผลไว้ในข้อจำกัดข้อ 4 เท่านั้น กันตัวเลขที่สูงเกินจริงถูกนำไปใช้
- [x] **ย้ายไปรันบนเครื่องที่แรงกว่า** — เครื่องเดิมช้าและเริ่มมี timeout (ข้อ 10.6)

## 10. บันทึกความคืบหน้า (สิ่งที่ทำมาแล้ว)

### 10.1 ก่อนเริ่มแผนนี้ (เพื่อเข้าใจที่มา)
- ทดสอบด้วย GoTestWAF บน replica ในเครื่อง (CRS 3.3.8 ตามที่รู้ทีหลัง): CRS anomaly 5 ได้ D 63.3, CRS + ML (F-canon2) threshold 0.99 ได้ D 64.9 ดีที่สุด
- รายงาน GoTestWAF บน production (C+ 78.2) สูงเกินจริงเพราะ request 292 ตัวได้ 405 และถูกตัดออก
- ค้นหา benchmark มาตรฐาน: SecureIQLab (AMTSO) รันซ้ำไม่ได้ · open-appsec รันซ้ำได้ → เลือกเป็นตัวเทียบหลัก · CrowdStrike ไม่มีผลิตภัณฑ์ WAF

### 10.2 โค้ดที่เพิ่ม (ขึ้น git แล้ว)
| ไฟล์ | ใช้ทำอะไร |
| :--- | :--- |
| `ml/security_test/openappsec/run_benchmark.sh` | ตั้ง container ระบบ K/A/B/C/D + stub + ML harness แล้วรันเครื่องมือ และสรุปผล |
| `ml/security_test/openappsec/Dockerfile.harness` | image ของ ML harness (Python 3.12 + `ml/requirements-serve.txt`) |
| `ml/security_test/openappsec/summarize_db.py` | อ่าน DuckDB ของเครื่องมือ → TPR/FPR/Balanced + จำนวน status 0 ที่ถูกตัด |
| `ml/train_final_gen3.py --exclude-dataset` | เทรนโดยตัด dataset ที่ระบุ |
| `ml/waf_gen3_colab.ipynb` | ตั้งค่าเทรนรุ่นไม่ใช้ OpenAppSec |

### 10.3 ข้อค้นพบสำคัญ
- **production ใช้ CRS 3.3.8** (`owasp/modsecurity-crs:nginx`) ไม่ใช่ 4.x — ผล GoTestWAF ของ CRS replica ก่อนหน้านี้ทั้งหมดเป็น 3.3.8
- เครื่องมือ **ตัด status 0 (timeout) ออกจากการคำนวณ** — ต้องรายงานทุกรอบ
- CRS บล็อก traffic ปกติจริงในชุดนี้ด้วย rule เช่น 932270 (RCE Unix shell), 920420 (content type), 932250
- nginx ตอบ 400 กับ request ปกติบางตัว (rule 200002 "Failed to parse request body" และ nginx เอง)

### 10.4 โมเดลรุ่นไม่ใช้ OpenAppSec (Colab, 2 ต.ค. 2569)
| รายการ | ค่า |
| :--- | :--- |
| โฟลเดอร์บน Drive | `waf_ml/models/gen3-final-f-noopenappsec-20261002-153004/` |
| ข้อมูล | ตัด OpenAppSec 163,751 แถว เหลือ 133,977 แถว (CSIC 2010 + SR-BH 2020) |
| Threshold (card) | 0.8749 |
| Scenario | ปกติ 37/37 · โจมตี 23/26 (พลาด probe หน้า admin 3 ข้อเหมือนเดิม) |
| OOF รวม | Precision 99.81% / Recall 92.03% / F1 95.76% |
| ONNX | parity 3.7×10⁻⁷ · latency p50 0.30 ms |

### 10.5 ผล calibration K และ A (--fast 16 workers ครบ 699 ไฟล์, 3 ต.ค. 2569)
รันครบ 100% ของตัวอย่าง (156,038 legit จาก 692 เว็บ, 11,087 malicious) ใช้เวลา 44 นาที (2,649 วินาที):

| ระบบ | TPR (จับโจมตี) | FPR (บล็อกผิด) | Balanced Acc | status 0 ที่ถูกตัด (legit) | status 0 (malicious) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| K CRS 4.20.0 default | **90.142%** | 34.600% | 77.771% | 4,199 / 156,038 (2.69%) | 0 / 11,087 (0%) |
| A CRS 3.3.8 PL1 a5 (Prod) | 90.376% | 27.626% | 81.375% | 4,182 / 156,038 (2.68%) | 0 / 11,087 (0%) |

- **TPR ของ K (90.142% vs เผยแพร่ 92.257%):** ต่าง −2.115 จุด **ผ่านเกณฑ์ ±3 จุด** ยืนยันว่าการส่ง request และการตัดสินบล็อกถูกต้อง
- **FPR ของ K (34.600% vs เผยแพร่ 18.638%):** สูงกว่าที่เผยแพร่ +15.96 จุด ไม่ผ่านเกณฑ์ (สาเหตุ: CRS stock image ไม่มี tuning/exclusions เฉพาะเหมือนที่ open-appsec ทดสอบ และ status 0 timeout 2.7%)
- **Malicious dataset:** ไม่มี timeout เลย (status 0 = 0) แสดงว่าตัวเลข TPR เสถียรและน่าเชื่อถือ 100%

> ⚠️ **แก้ไข 3 ต.ค. 2569: แถว A น่าจะไม่ใช่ CRS 3.3.8** image `owasp/modsecurity-crs:nginx` บนเครื่องนี้ build วันที่ 30 ก.ย. 2569 และ `crs-setup.conf` ระบุ `OWASP_CRS/4.29.0` (container ยัง log ว่า `Detected CRS config file version: v4`) tag `nginx` เลื่อนเวอร์ชันได้ แถว A ที่รันบนเครื่องนี้จึงเป็น **CRS 4.29.0 PL1 anomaly 5** ห้ามอ้างเป็นตัวเลขของ CRS 3.3.8
> - CRS 3.3.8 แบบ pin: `owasp/modsecurity-crs:3.3.8-nginx-202603150103`
> - สคริปต์ตอนนี้ pin tag ทุกตัว (ค่า default เป็น 4.25.1 ดูหัวข้อ 14)
> - `docker-compose.yml` ของ production ก็ใช้ tag `nginx` ถ้าสร้าง container ใหม่ CRS จะเปลี่ยนเวอร์ชันเอง ควร pin (แจ้งผู้ดูแล production ไม่ได้แก้บน VPS)

### 10.6 เรื่องเวลาและเครื่อง
| การตั้งค่า | ความเร็ววัดจริง | เวลาโดยประมาณ (K + A) |
| :--- | :--- | :--- |
| 4 workers (ค่าเริ่มต้น) | 200–750 request/นาที/ระบบ | `--fast` 2.5–5 ชม. |
| 16 workers | 2,000–2,800 request/นาที/ระบบ | `--fast` ~40–45 นาที/2 ระบบ |

- คอขวดอยู่ที่ตัวเครื่องมือ (CPU ของ CRS 0–5%) และ RAM ที่ว่างเหลือน้อยบนเครื่องเดิม
- เครื่องมือส่ง request ทีละระบบ จึงใช้เวลาแปรตามจำนวนระบบที่ใส่ในรอบเดียว

### 10.7 ผลการทดสอบระบบ D: ML-only @ Card Threshold 0.8749 (--fast 16 workers, 3 ต.ค. 2569)
รันโมเดล `gen3_f_noopenappsec.onnx` เดี่ยวๆ ไม่ผ่าน CRS ครบ 699 ไฟล์ ใช้เวลา 31 นาที (1,862 วินาที):

| ระบบ | TPR (จับโจมตี) | FPR (บล็อกผิด) | Balanced Acc | status 0 (legit) | status 0 (malicious) |
| :--- | ---: | ---: | ---: | ---: | ---: |
| **D** ML-only @ card (0.8749) | **93.037%** 🥇 | **24.522%** 🥇 | **84.257%** 🥇 | 4,941 (3.16%) | 0 (0%) |

- **TPR (93.037%):** ชนะทั้ง CRS 3.3.8 (+2.66%) และ CRS 4.20.0 (+2.90%) และสูงกว่า AWS WAF (79.9%), Fortinet (70.1%), Cloudflare (63.5%)
- **FPR (24.522%):** ต่ำกว่า CRS 3.3.8 (27.63%) และต่ำกว่า CRS 4.20.0 (34.60%) อย่างชัดเจน
- **Balanced Accuracy (84.257%):** สูงที่สุดในบรรดาระบบที่วัดในเครื่อง

### 10.8 ข้อค้นพบจากการทดสอบยิง Production จริง (`Httpbin.originweb.site`)
- ยิงผ่านอินเทอร์เน็ตไปยัง VPS จริงด้วย 16 workers:
  - ความเร็วลดลงเหลือ ~10–25 req/s (ช้ากว่า local 20 เท่า)
  - เกิด **Status 0 (Timeout/Drop) สูงถึง 54.1%** (23,791 / 44,000 req) เนื่องจาก VPS Reverse Proxy รับโหลดพร้อมกันไม่ทัน
  - ยืนยันตามแผนข้อ 4 ว่า **การวัดด้วย Local Replica ในเครื่องเหมาะสมและถูกต้องตามมาตรฐานที่สุด** เพราะไม่มี Network drop และไม่กระทบ production

## 11. วิธีรันบนเครื่องใหม่

### ขั้นที่ 1 — เตรียมเครื่อง
- Docker Desktop (Linux containers) หรือ Docker Engine บน Linux · ถ้าเป็น Windows ให้รันใน WSL2 และเปิด WSL Integration ให้ distro ที่ใช้
- ตั้ง RAM ให้ Docker/WSL อย่างน้อย 8 GB (Docker Desktop: Settings → Resources หรือ `.wslconfig`)
- ดิสก์ว่าง ≥ 20 GB

### ขั้นที่ 2 — โหลดโค้ด
```bash
git clone -b trainmodelgen3 https://github.com/jakkaret/waf_project.git
cd waf_project
```

### ขั้นที่ 3 — วางโมเดลรุ่นไม่ใช้ OpenAppSec
ดาวน์โหลด `gen3_f_model.onnx` จาก Drive `waf_ml/models/gen3-final-f-noopenappsec-20261002-153004/`
แล้ววางที่ **`ml/models/gen3/gen3_f_noopenappsec.onnx`** (ตั้งแต่ 3 ต.ค. 2569 ไฟล์นี้อยู่ใน git แล้วและเป็นค่าเริ่มต้นของ `ml_api.py` ข้ามขั้นนี้ได้)

### ขั้นที่ 4 — (ไม่บังคับ) ใช้ dataset ที่มีอยู่แล้ว
ถ้ามี `legitimate.zip` / `malicious.zip` แล้ว ให้แตกไว้ที่ `~/waf-bench/results/datasets/` จะได้ไม่ต้องโหลดใหม่
(ไม่มี: เครื่องมือโหลดเองในรอบแรก ~1.2 GB และแตกเป็น ~7 GB)

### ขั้นที่ 5 — calibration (K + A แบบ fast)
```bash
bash ml/security_test/openappsec/run_benchmark.sh --systems K,A --fast --workers 32
```
- ตรวจผลตามเกณฑ์ขั้นที่ 2 (TPR/FPR ของ K ห่างจาก 92.257% / 18.638% ไม่เกิน ±3 จุด และ status 0 < 1%)
- ถ้า status 0 สูง ให้ลด `--workers` แล้วรันใหม่

### ขั้นที่ 6 — ระบบที่มี ML (fast ก่อน)
```bash
bash ml/security_test/openappsec/run_benchmark.sh --systems A,B,C,D --fast --workers 32
```

### ขั้นที่ 7 — รอบเต็ม (ตัวเลขที่ใช้จริง)
```bash
bash ml/security_test/openappsec/run_benchmark.sh --systems K,A,B,C,D --workers 32
```
หรือแยกรันทีละ 1–2 ระบบถ้าอยากให้แต่ละรอบสั้นลง (แต่ละรอบใช้ `--fresh-run` จะลบ DB ของรอบก่อน → **เก็บ PDF และ `summary-*.txt` ก่อนรันรอบถัดไป**)

### ผลที่ได้แต่ละรอบ (ใน `~/waf-bench/results/`)
- `waf-comparison-report.pdf` — รายงานของเครื่องมือ
- `summary-<เวลา>.txt` — TPR / FPR / Balanced + จำนวน status 0
- `db/waf_comparison.duckdb` — ผลราย request (ใช้ในขั้นที่ 5)
- `harness-logs/oa-ml-*.jsonl` — คะแนน ML ราย request (ระบบ B/C/D)

ส่งไฟล์ PDF และ `summary-*.txt` มาให้ Claude วิเคราะห์ต่อได้

## 12. สิ่งที่จะทำต่อ (เรียงตามลำดับ)

1. [x] รัน calibration K + A แบบ fast บนเครื่องใหม่ให้ครบ (เสร็จ 3 ต.ค. 2569 — ข้อ 10.5)
2. [x] รันระบบ D (ML-only @ card) แบบ fast (เสร็จ 3 ต.ค. 2569 — ข้อ 10.7)
3. รันระบบ B (CRS 3.3.8 + ML @ 0.99) และ C (CRS 3.3.8 + ML @ card) แบบ fast เพื่อเทียบประสิทธิภาพ Hybrid
4. ตรวจ overlap SHA-256 ระหว่าง benchmark กับข้อมูลเทรนของรุ่นไม่ใช้ OpenAppSec
5. รอบเต็ม K, A, B, C, D (1.1 ล้าน request ต่อระบบ สำหรับตัวเลขรายงานฉบับสมบูรณ์)
6. วิเคราะห์ (ขั้นที่ 5) และเขียน `RESULTS_OPENAPPSEC_BENCHMARK.md`
7. อัปเดตคู่มือ WAF Gen 3 และสไลด์
8. (ทางเลือก) วัด CRS 4.20 + ML เพิ่ม เพื่อดูว่าการอัปเกรด CRS ของ production จาก 3.3.8 เป็น 4.x ให้ผลอย่างไร

## 13. ผลลัพธ์ที่จะได้

- PDF ของเครื่องมือ open-appsec สำหรับระบบ K, A–D
- ตารางเทียบกับ 14 ผลิตภัณฑ์ที่ระบุที่มาทุกแถว
- คำตอบที่มีตัวเลขรองรับว่า ML ช่วย CRS ได้เท่าไหร่บนข้อมูลจริงขนาดใหญ่ และ FP เพิ่มเท่าไหร่

## 14. ML เสนอกฎ → admin อนุมัติ: วัดคุณค่าจริง (เริ่ม 3 ต.ค. 2569)

คำถาม: กลไกที่ paper อ้าง ("Random Forest + Isolation Forest เสนอกฎ ผู้ดูแลอนุมัติ") เพิ่ม detection และ false positive ให้ CRS เท่าไหร่ และถ้าเอา ONNX ขึ้นเซิร์ฟเวอร์จะทำให้ request ช้าลงไหม
ทุกขั้นรันใน WSL + Docker ในเครื่อง **ไม่แตะ VPS** · CRS ฐาน = **4.25.1 LTS** (`4.25.1-nginx-202609301109-lts`, ตัวที่ production จะอัปเป็น)

### 14.1 ชื่อระบบ (ใช้ชื่อจริงแทนตัวอักษร)
| ชื่อ | คืออะไร | ชื่อเดิม |
| :--- | :--- | :--- |
| `CRS-4.20.0-default` | CRS 4.20.0 ค่า default (calibrate) | K |
| `CRS-4.25.1` | CRS ฐาน PL1, inbound 5, outbound 4 | (A ใช้ image ที่จริงเป็น 4.29.0 ดู 10.5) |
| `Gen3@card` | ML อย่างเดียว (`gen3_f_noopenappsec.onnx`, 0.8749) | D |
| `CRS-4.25.1+Gen3@0.99` / `@card` | CRS แล้วส่งต่อให้ ML บล็อก | B / C |
| `CRS-4.25.1+RF-rules-all` / `-backtest` | CRS + กฎที่ตัวสร้างกฎปัจจุบันเสนอ (RF + regex 7 แบบ) | – |
| `CRS-4.25.1+Gen3-rules-all` / `-backtest` | CRS + กฎจาก detector ของ Gen3 | – |

`-all` = อนุมัติทุกกฎ · `-backtest` = อนุมัติเฉพาะกฎที่ไม่ match traffic ปกติของฝั่ง gen เลย (ModSecurity จริง)

### 14.2 สิ่งที่แก้ใน repo ก่อนวัด
- **SecRule injection ในตัวสร้างกฎ** (`ml/auto_rule_generator.py`): `re.escape` ไม่ escape `"` → body ที่มี `"` ปิด operator แล้วแทรก action เช่น `ctl:ruleEngine=Off` ได้ (ยืนยันกับโค้ดเดิมแล้ว) · แก้เป็น `regex_literal` (`\xHH`) + `assert_secrule_safe` · `/generate-rule` ตอบ 422 แทนการเสนอกฎอันตราย · test: `ml/tests/test_auto_rule_generator.py`
- **กฎที่ลงท้ายด้วย `%` ทำให้ไฟล์กฎทั้งไฟล์โหลดไม่ได้** (ModSecurity อ่าน `%` เป็น macro) → escape `%` ด้วย
- **test harness decode path ก่อนให้คะแนน** (`request.url.path`) → ใช้ `raw_path` ตามที่ส่งจริง (162 / 162,184 request ได้คะแนนต่างกัน)
- `async_log_analyzer.py`: env `ML_PREDICT_URL` เพื่อชี้ไป `/predict-gen3` ได้ (ค่า default เหมือนเดิม)

### 14.3 ข้อค้นพบระหว่างทาง
- **URL ที่ WAF ได้รับ ≠ URL ใน dataset** เครื่องมือส่งด้วย `requests` ซึ่ง requote URL ที่มี escape ผิดรูป (`%u2216` → `%25u2216`) 6,276 request · ทุกสคริปต์ใช้ `wire_url` (URL ตามที่ส่งจริง)
- **ML ของ production เห็นแค่ URL** log `json_combined` ของเซิร์ฟเวอร์หลักมี `$request` (ไม่มี body) · log ของ edge (`cdn_json`) มีแค่ `$uri` **ไม่มี query string** → ML บน edge มองไม่เห็น payload ใน query เลย
- **RF feature extraction ช้าลงเร็วกว่าเชิงเส้นตามขนาด body** (10 KB 0.006 วินาที, 100 KB 0.25 วินาที; ชุดนี้มี body ถึง 53 MB) · Gen3 จำกัดความยาว unit จึงเร็ว (100 KB 0.008 วินาที) · offline ให้ RF เห็น body 64 KB แรก (334 request)

### 14.4 ผลส่วนที่ 1: โมเดลแบบ offline บน request ชุดเดียวกับ `--fast` (167,125)
`ml/security_test/openappsec/score_offline.py` · Gen3 offline ตรงกับการตัดสินจริงของ harness 99.9% (162 ที่ต่างมาจาก bug path decode ข้างบน)

| โมเดล | ROC-AUC | TPR @ FPR 1% | TPR @ FPR 5% | FPR @ TPR 90% | ที่ threshold ใช้งาน: TPR / FPR / Balanced |
| :--- | ---: | ---: | ---: | ---: | :--- |
| RF (production, 0.5) | 0.874 | 0.0% | 0.0% | 42.8% | 85.3% / 35.8% / 74.7% |
| Gen3 (0.8749) | 0.965 | 79.1% | 90.5% | 4.3% | 93.0% / 24.0% / 84.5% |

TPR แยกประเภท (RF / Gen3): traversal 66.0 / 82.0 · xss 97.3 / 100 · sqli 95.6 / 99.3 · cmdexe 98.4 / 99.2 · log4shell, shellshock 100 / 100 · xxe 90.0 / 100
TNR แยกหมวดเว็บของ Gen3 ต่ำสุด: Videos 67.9, Travel 69.6, Technology 71.1, Social Media 71.7, Food 65.5

### 14.5 ผลส่วนที่ 2: กฎที่ ML เสนอ (รอผลรอบ benchmark)
วิธี: แบ่ง gen / eval ตามเว็บ (legit) และกลุ่ม payload (malicious) → สร้างกฎจากฝั่ง gen ด้วยมุมมองแบบ production (URL อย่างเดียว) → backtest → benchmark → นับเฉพาะฝั่ง eval
คำสั่งเดียว: `bash ml/security_test/openappsec/run_rule_ablation.sh` (ต้องมี `offline/requests.duckdb` จาก `score_offline.py`)

### 14.6 ผลส่วนที่ 3: latency (รอผล)
`ml/benchmark_latency.py --body-sizes ...` (โมเดลล้วน) และ `ml/security_test/latency/run_latency.py` (CRS + ML บน 2 CPU / 3.7 GB เท่าเซิร์ฟเวอร์หลัก, ยิงเฉพาะ container ในเครื่อง)
