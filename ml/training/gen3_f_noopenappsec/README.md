# ข้อมูลการเทรน Gen 3: `gen3_f_noopenappsec`

โฟลเดอร์นี้เก็บทุกอย่างที่ใช้สร้างโมเดล Gen 3 ตัวที่ ML service ใช้อยู่ ([`ml/models/gen3/gen3_f_noopenappsec.onnx`](../../models/gen3/gen3_f_noopenappsec.onnx)) ได้แก่ข้อมูลเทรน, log ของรอบเทรนจริง และสคริปต์สำหรับเทรนซ้ำ

| | |
| :--- | :--- |
| ชื่อรอบเทรน | `gen3-final-f-noopenappsec-20261002-153004` (เทรนบน Google Colab, 2 ต.ค. 2569) |
| โมเดล | LightGBM บนฟีเจอร์ชุด F (`gen3-F-2026-09-29-canon2`, 48 ฟีเจอร์), export เป็น ONNX |
| ข้อมูล | CSIC 2010 + SR-BH 2020 เท่านั้น (133,977 แถว) ไม่ได้ใช้ open-appsec เพื่อให้ benchmark open-appsec เป็นข้อมูลที่โมเดลไม่เคยเห็น |
| Threshold | 0.8749 (ทุก dataset ต้องปล่อย request ปกติผ่านได้อย่างน้อย 99% แบบ out-of-fold) |
| สถานะ | **ยังไม่ผ่านเกณฑ์ใช้งานจริง** (promotion gate 3.1-G.0 ผ่าน 3/5) ใช้ได้แค่ shadow / วิเคราะห์ / เสนอกฎให้คนอนุมัติ ห้ามใช้บล็อก traffic |
| Model card | [`ml/models/gen3/gen3_f_noopenappsec_model_card.json`](../../models/gen3/gen3_f_noopenappsec_model_card.json): hyperparameters, sha256 ของข้อมูลและโค้ด, ผลวัดทั้งหมด |

## ไฟล์ในโฟลเดอร์

| ไฟล์ | คืออะไร |
| :--- | :--- |
| `data/csic_final.csv.gz` | CSIC 2010 HTTP dataset (ฉบับ cleaned) ไฟล์เดียวกับที่ใช้เทรน บีบอัดด้วย gzip |
| `data/srbh2020_labelled.jsonl.gz` | SR-BH 2020 หลังติด label ด้วย `ml/prepare_external_datasets.py` บีบอัดด้วย gzip |
| `data/SHA256SUMS` | sha256 ของไฟล์ที่แตกแล้ว ตรงกับ `data.input_files` ใน model card |
| `logs/train.log` | log ของรอบเทรนจริงบน Colab (OOF metrics, threshold, 63 scenarios, latency, ONNX parity) |
| `logs/unit_tests.log` | unit test บน Colab ก่อนเทรน (43 passed) |
| `logs/reference_gate.json`, `.log` | ผล promotion gate ของ feature set บน Colab (29 ก.ย. 2569, `experiment-value-features-20260929-123839`) มาจาก zip ผลลัพธ์ชุดเดียวกัน ไม่ใช่รอบ reference ใน model card (`experiment-value-features-20260928-144424`) ซึ่งไม่มีไฟล์รายงานเหลืออยู่ |
| `reproduce.sh` | แตกข้อมูล ตรวจ sha256 แล้วเทรนซ้ำด้วย hyperparameters จาก model card |

## ข้อมูลที่ใช้

| Dataset | ที่มา | License | ใช้ในรอบนี้ (benign / attack แบบ unique) |
| :--- | :--- | :--- | :--- |
| CSIC 2010 (cleaned) | `ml/download_dataset.py` ดาวน์โหลดจาก [msudol/Web-Application-Attack-Datasets](https://github.com/msudol/Web-Application-Attack-Datasets) | ชุดข้อมูลวิจัยสาธารณะของ CSIC (สเปน) | 9,622 / 15,472 |
| SR-BH 2020 | Harvard Dataverse [doi:10.7910/DVN/OGOIXX](https://doi.org/10.7910/DVN/OGOIXX) แปลงด้วย `ml/prepare_external_datasets.py` | CC0 | 39,581 / 69,302 |

- **ไม่มีข้อมูลจาก VPS หรือ traffic ของลูกค้า:** โมเดลนี้ไม่ได้เทรนจากข้อมูลเหล่านั้น ข้อมูลส่วนนั้นยังห้ามเข้า repo นี้ตามเดิม (ดู `.gitignore`)
- **การติด label ของ SR-BH:** request นับเป็น attack เฉพาะคลาสที่มี payload เช่น SQLi, code/command injection, path traversal และ response splitting คลาส protocol, scan, verb tampering และ spoofing ถูกตัดทิ้ง ไม่ได้ติดเป็น attack รายละเอียดอยู่ใน docstring ของ `ml/prepare_external_datasets.py`
- **ขั้นตอนต่อจากนั้น:** ตัวเทรนลบแถวซ้ำ ให้น้ำหนักกลุ่ม near-duplicate และสุ่มกลุ่มแบบ deterministic เอง (`build_full_real_dataset` ใน `ml/train_gen3_full_real_benchmark.py`)

## ผลของโมเดล

**Out-of-fold, 5 fold แบบแบ่งตามกลุ่ม** (attack = positive, ถ่วงน้ำหนักตามกลุ่ม near-duplicate):

| Dataset | Precision | Recall | F1 | Benign ผ่าน |
| :--- | ---: | ---: | ---: | ---: |
| รวม | 99.81% | 92.03% | 95.76% | |
| CSIC 2010 | 99.12% | 58.66% | 73.70% | 99.01% |
| SR-BH 2020 | 99.86% | 96.17% | 97.98% | 99.80% |

- **63 scenarios:** request ปกติผ่าน 37/37, attack ถูกจับ 23/26 ที่หลุดคือ probe หา WordPress admin, phpMyAdmin และ Spring actuator
- **Latency ต่อ 1 request:** ONNX p50 0.30 ms, p95 0.49 ms
- **benchmark open-appsec** (ข้อมูลที่โมเดลไม่เคยเห็น, `ml/security_test/BENCHMARK_PLAN_OPENAPPSEC.md` ข้อ 14.4):
  - ROC-AUC 0.965 (RF เดิม 0.874)
  - ที่ threshold 0.8749 จับ attack ได้ 93.0% แต่ **ปล่อยผ่าน request ปกติแค่ 76%** (FPR 24%) ของเว็บจริงสมัยใหม่ เช่น telemetry ของ analytics และ GraphQL
  - นี่คือเหตุผลหลักที่ยังห้ามใช้บล็อก

## เทรนซ้ำ

ต้องใช้ Python 3.12 กับ `ml/requirements-train.txt` (บน Colab ใช้ LightGBM 4.7.0) และ RAM ประมาณ 4 GB

```bash
PYTHON=.venv/bin/python ml/training/gen3_f_noopenappsec/reproduce.sh
```

1. **สคริปต์จะไม่ยอมทำงาน** ถ้ามีข้อมูลอื่นที่ตัวเทรนจะหยิบไปใช้ด้วย ได้แก่ `ml/dataset/vps_audit_labelled.jsonl`, `nginx_real_benign.jsonl` และ `ml/telemetry/*.jsonl` เพราะรอบเดิมไม่มีข้อมูลเหล่านี้
2. **แตกข้อมูล:** แตกไปไว้ที่ `ml/dataset/` แล้วตรวจ sha256
3. **เทรน:** รัน `ml/train_final_gen3.py --exclude-dataset OpenAppSec --params-from <model card>`
4. **ผลลัพธ์:** ไปอยู่ที่ `ml/models/archive/gen3-final-f-noopenappsec-<เวลา>/` และไม่ทับไฟล์ที่ ML service ใช้อยู่ ถ้าจะใช้โมเดลใหม่ ให้คัดลอก `gen3_f_model.onnx` มาเป็น `ml/models/gen3/gen3_f_noopenappsec.onnx` เอง

### ผลเทรนซ้ำบนเครื่อง local (13 ต.ค. 2569)

ได้โมเดลที่แทบเหมือนเดิม แต่ไม่ตรงทุกบิต:

| | รอบเดิม (Colab) | เทรนซ้ำ |
| :--- | ---: | ---: |
| แถว | 133,977 | 133,980 |
| Threshold | 0.8749 | 0.8731 |
| OOF รวม P / R / F1 | 99.81 / 92.03 / 95.76% | 99.80 / 92.01 / 95.74% |
| Scenarios | 37/37, 23/26 | 37/37, 23/26 |

- **เทียบคำตัดสินของสองโมเดล:** ทดสอบบน 63 scenarios รวมกับ SR-BH ที่สุ่มมา 3,000 request คำตัดสินตรงกัน 99.93% (ต่างกัน 2 request) ค่ามัธยฐานของผลต่างคะแนนเป็น 0 และผลต่างสูงสุด 0.085
- **ทำไมจำนวนแถวต่างกัน 3 แถว:** รอบเดิมมีไฟล์ open-appsec อยู่ด้วย ตัวเทรนจึงลบแถวที่ซ้ำกับ open-appsec ออกก่อน แล้วจึงตัด open-appsec ทิ้งตาม `--exclude-dataset` ถ้าต้องการให้ตรงกว่านี้ ให้รัน `ml/prepare_external_datasets.py --download` ก่อนเทรน ซึ่งต้องดาวน์โหลดประมาณ 1.7 GB (วิธีนี้ยังไม่ได้ทดสอบ)
- **ONNX export:** ต้องมี `onnx` และ `onnxmltools` จาก `requirements-train.txt` ถ้าไม่มี ตัวเทรนจะยังบันทึก `.joblib` ไว้ และแปลงทีหลังได้ด้วย `ml/export_gen3_onnx.py`
