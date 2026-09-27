---
title: "Flow F — Machine Learning"
part: "Part VII — Complete Data Flows"
status: PARTIAL
---

# Flow F — Machine Learning

```mermaid
flowchart LR
  log["logs/nginx/access.json"] --> an["waf-log-analyzer tail ทุก 0.5s"]
  an -->|POST /predict| ml["waf-ml :5000"]
  an -->|ผิดปกติ: POST /generate-rule| ml
  an -.->|พิมพ์ผลลง journal เท่านั้น| out["ไม่ได้บันทึกลง DB"]
  ui["หน้า AI Security Analyst"] -->|POST /api/ml/predict-and-suggest| be["FastAPI"]
  be -->|/predict| ml
  ml --> rf["Random Forest ONNX/joblib + Isolation Forest"]
  be -->|ผิดปกติ: /generate-rule| ml
  be -->|create_pending_rule| pend["waf_pending_rules status=pending"]
  admin["Admin หน้า ML Rules"] -->|approve| apply["rule_manager.write_ml_rule"]
  pend --> admin
  apply --> conf["custom-rules/ml-*.conf"]
  conf -->|nginx -t + reload| waf["waf-nginx"]
```

*รูปที่ 14 — ML จาก log ถึงการอัปเดตกฎ*

```text
Logs → ML (/predict) → Detection (is_anomaly, attack_probability) → Recommendation (/generate-rule)
     → [บันทึกเฉพาะเส้นทาง AI Security Analyst] → waf_pending_rules → Admin review → ml-<id>.conf → reload
```

ข้อสำคัญ: เส้นทางอัตโนมัติจาก log analyzer ยังไม่บันทึกกฎรออนุมัติ (บทที่ 16)

## แหล่งอ้างอิง (Evidence)
- `ml/async_log_analyzer.py`, `dashboard/backend/api/ml.py:174`, `services/ml_rule_service.py`
