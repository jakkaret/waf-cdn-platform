# การเทรนโมเดล Gen 3 บนเครื่องอื่น (โน้ตบุ๊ก)

> โค้ด ML ชุดนี้ย้ายมาจาก repo `jakkaret/waf_project` (private) branch `trainmodelgen3` เมื่อ 9 ต.ค. 2569
> คำสั่ง clone และ Colab notebook ด้านล่างยังชี้ไปที่ repo เดิม ส่วน `PROGRESS_GEN3_CHECKPOINT.md` และรายงานใน
> `ml/models/archive/` ไม่ได้ย้ายมา (repo นี้เป็น public ห้ามนำข้อมูลจาก VPS หรือ archive ขึ้นมา)

เทรนบนเครื่อง local เท่านั้น — **ห้ามเทรนหรือติดตั้งอะไรบน VPS production** (ดู `WORKING_RULES.md`, `WAF_GEN3_ROADMAP.md`)
สถานะงานล่าสุดและงานที่ค้างอยู่: `PROGRESS_GEN3_CHECKPOINT.md`

## ไฟล์ที่ต้องมี (3 กลุ่ม)

| กลุ่ม | ได้มาจาก | อยู่ที่ |
| :--- | :--- | :--- |
| 1. โค้ด + เอกสาร + รายงานผลของ candidate (`ml/models/archive/**/*.json`) | `git checkout trainmodelgen3` | ใน repo |
| 2. Public dataset (~1.7 GB) | ดาวน์โหลดเองด้วยสคริปต์ (ตรวจ sha256) | `ml/dataset/external/`, `ml/dataset/csic_final.csv` |
| 3. ข้อมูลจาก VPS (~40 MB) | **คัดลอกเองแบบ private** — ห้ามขึ้น git เพราะเป็น traffic จริงจาก production | `ml/dataset/vps_audit_labelled.jsonl` (+ `.stats.json`), `ml/dataset/nginx_real_benign.jsonl`, `ml/telemetry/*.jsonl` |

ไฟล์โมเดล `.joblib` ของ candidate ไม่อยู่ใน git — สร้างใหม่ได้จากโค้ดและข้อมูลชุดเดียวกัน

## ขั้นตอน

```bash
git clone git@github.com:jakkaret/waf_project.git && cd waf_project
git checkout trainmodelgen3

python3.12 -m venv .venv
.venv/bin/pip install -r ml/requirements-train.txt

# กลุ่ม 3: แตกไฟล์ข้อมูล VPS ที่คัดลอกมา (สร้างจากเครื่องเดิมด้วยคำสั่งด้านล่าง)
tar -xzf waf_ml_private_data_<date>.tar.gz          # ได้ ml/dataset/*.jsonl และ ml/telemetry/

# กลุ่ม 2: ดาวน์โหลด open-appsec + SR-BH 2020 แล้วเตรียมข้อมูล (~3 นาที, RAM ~2.5 GB)
PYTHONPATH=. .venv/bin/python ml/prepare_external_datasets.py --download
# CSIC 2010 ถูกดาวน์โหลดอัตโนมัติตอนเทรนครั้งแรก

# เทรน + ประเมิน (ครั้งแรกสร้าง dataset ~6 นาที แล้วเก็บ cache ใน ml/dataset/.build_cache/)
PYTHONPATH=. .venv/bin/python ml/train_gen3_full_real_benchmark.py
PYTHONPATH=. .venv/bin/python ml/check_overfitting.py
PYTHONPATH=. .venv/bin/python ml/test_comprehensive.py
PYTHONPATH=. .venv/bin/python ml/evaluate_leave_source_out.py
PYTHONPATH=. .venv/bin/python -m pytest ml/tests -q
```

สร้างไฟล์ข้อมูล VPS (กลุ่ม 3) จากเครื่องที่มีข้อมูลอยู่แล้ว:

```bash
tar -czf ~/waf_ml_private_data_$(date +%Y%m%d).tar.gz \
    ml/dataset/vps_audit_labelled.jsonl ml/dataset/vps_audit_labelled.stats.json \
    ml/dataset/nginx_real_benign.jsonl ml/telemetry
```

หรือดึง audit log ใหม่จาก VPS แบบอ่านอย่างเดียว (ไม่เขียนไฟล์บน VPS):

```bash
ssh root@178.104.53.123 python3 - < scripts/extract_vps_audit_dataset.py > ml/dataset/vps_audit_labelled.jsonl
```

## เทรนบน Google Colab

เปิด `ml/waf_gen3_colab.ipynb` ใน Colab (File → Open notebook → GitHub → branch `trainmodelgen3`) แล้วรันตามลำดับ cell:
repo private ให้เพิ่ม Colab Secret `GITHUB_TOKEN` (fine-grained, Contents: read); ข้อมูล VPS (กลุ่ม 3) ใส่เป็น tar.gz ใน
`MyDrive/waf_ml/private/` เฉพาะเมื่อได้รับอนุญาตให้เก็บบน Google Drive — ถ้าไม่มี notebook จะรันด้วย public data อย่างเดียว.
Dataset, build cache และโมเดล `.joblib` เก็บใน `MyDrive/waf_ml/`; ผล (JSON + log) ดาวน์โหลดเป็น zip แล้วแตกที่ root ของ repo

## โมเดลสำหรับใช้งาน (Gen 3, ชุดฟีเจอร์ F)

```bash
PYTHONPATH=. .venv/bin/python ml/train_final_gen3.py        # หรือ Colab: RUN_FINAL_MODEL = True
mkdir -p ml/models/gen3 && cp ml/models/archive/gen3-final-f-<เวลา>/gen3_f_model.onnx ml/models/gen3/
# ml_api.py: POST /predict-gen3 {"url": "...", "method": "GET", "body": ""}  → คะแนนแบบ shadow (ไม่บล็อก)
```
- ผลที่พิมพ์ออกมาและเก็บใน `model_card.json` มี 3 ส่วน:
  1. Scenario ทั้ง 63 ข้อ (expected / predicted / score)
  2. Precision / Recall / F1 ของ scenario
  3. Precision / Recall / F1 แบบ out-of-fold ต่อ dataset (attack = positive)
- ได้ทั้ง `gen3_f_model.joblib` และ `gen3_f_model.onnx` (`ml/gen3_onnx.py`)
  - `.onnx` ถูกเขียนก็ต่อเมื่อผลตรงกับ LightGBM (ต่างกันน้อยกว่า 1e-5) ทั้งบนข้อมูลจริงและบนค่าที่อยู่ตรง split threshold
  - `ml_api.py` ใช้ `.onnx` ก่อน ถ้าไม่มีจึงใช้ `.joblib`
  - ถ้ามีแค่ `.joblib` จากรอบเก่า แปลงได้ด้วย `ml/export_gen3_onnx.py`
- ไฟล์โมเดลไม่ขึ้น git (`.gitignore`) ให้ commit `model_card.json` แทน
  - ยกเว้นรุ่นที่เลือกใช้: `ml/models/gen3/gen3_f_noopenappsec.onnx` (F-noopenappsec, เทรนจาก CSIC + SR-BH เท่านั้น, card: `ml/models/gen3/gen3_f_noopenappsec_model_card.json`) อยู่ใน repo และเป็นค่าเริ่มต้นของ `ml_api.py`
  - รุ่นก่อน `gen3_f_model.onnx` (F-canon2 เทรนรวม OpenAppSec) ไม่ได้อยู่ใน repo นี้ ถ้าต้องการใช้ ให้วางไฟล์เองแล้วชี้ด้วย `WAF_GEN3_ONNX_PATH`
  - รุ่นใหม่จาก Colab ชื่อ `gen3_f_model.onnx` ให้คัดลอกมาเป็น `ml/models/gen3/gen3_f_noopenappsec.onnx`
  - ต้องใช้กับโค้ด extraction `canon2` ขึ้นไป (commit `a3b11de` ขึ้นไป) โค้ดเก่าจะปฏิเสธไฟล์นี้
- ยังไม่ผ่าน promotion gate 3.1-G.0 จึงห้าม enforce
- รัน ML บนเครื่องแยก (Azure, onnxruntime อย่างเดียว ใช้ `ml/requirements-serve.txt`): ดู `deploy/azure-ml/README.md`

## ความต้องการของเครื่อง

- Python 3.12, RAM ≥ 8 GB (peak ~3 GB ตอนสร้าง dataset), ดิสก์ว่าง ≥ 6 GB
- ตัวเทรนใช้ `n_jobs = จำนวน core จริง` (ใช้ hyperthread ทั้งหมดแล้วช้าลง ~8 เท่าใน WSL)
- ตัวเลขที่ได้ควรตรงกับ `ml/models/archive/<candidate>/experiment_report.json` ถ้าใช้ข้อมูลชุดเดียวกัน — ตรวจ `dataset_manifest.json` (sha256 ของไฟล์ input ทุกไฟล์)
