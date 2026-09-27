---
title: "Flow B — การโจมตีที่ถูกบล็อก (Blocked Attack)"
part: "Part VII — Complete Data Flows"
status: VERIFIED
---

# Flow B — การโจมตีที่ถูกบล็อก (Blocked Attack)

```mermaid
sequenceDiagram
  participant C as Client
  participant EN as Edge nginx + ModSecurity
  participant MN as Main waf-nginx + ModSecurity
  participant BE as FastAPI workers
  participant DB as ClickHouse / DynamoDB
  participant TG as Telegram
  C->>EN: GET /?file=../../../../etc/passwd
  EN->>EN: CRS 930xxx +score, 949110 score ≥ 10
  EN-->>C: 403 (หน้า 403)
  EN->>BE: log forwarder → /api/cdn/logs/ingest
  BE->>DB: access_logs (alert=1)
  BE->>DB: waf_alerts_v2 (origin_id)
  BE->>TG: แจ้งเตือน + คำอธิบาย Gemini
  Note over MN: ถ้าคำขอมาถึง Main ตรง (:8080) Main บล็อกเองแบบเดียวกัน
```

*รูปที่ 10 — คำขอโจมตีถูก CRS บล็อก*

```text
Client → Edge → WAF (CRS anomaly ≥ 10) → Block 403 → Response → Logging → Alert
```

- ทดสอบจริง 2026-09-27: `?file=../../../../etc/passwd` และ `?id=1' OR '1'='1` ได้ **403** ทั้งผ่าน edge และที่ Main :8080
- log ที่ถูกบล็อกมี `alert=1`, `rule_id`, `attack_type` และเกิด alert ใน `waf_alerts_v2` + Telegram (บทที่ 15)

## แหล่งอ้างอิง (Evidence)
- บทที่ 19–21, 14–15; ModSecurity error log (949110)
