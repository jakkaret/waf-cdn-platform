---
title: "Flow D — Deception"
part: "Part VII — Complete Data Flows"
status: VERIFIED
---

# Flow D — Deception

```mermaid
sequenceDiagram
  participant C as Client
  participant EC as Edge Caddy
  participant EN as Edge nginx + ModSecurity
  participant MN as Main waf-nginx + ModSecurity
  participant API as FastAPI /api/deception/respond
  participant O as Origin
  C->>EC: HTTPS GET /path?deceive marker
  EC->>EN: HTTP
  EN->>EN: rule DECEIVE phase 1 → deny 418
  EN->>MN: error_page 418 → @deception_via_main (ส่งคำขอเดิมต่อ)
  MN->>MN: rule เดียวกัน → 418 → @deception
  MN->>API: internal key, X-Original-URI/Method/Host, X-Request-ID
  API->>API: classify → เลือก template, บันทึก log (background)
  API-->>MN: 200 + body สังเคราะห์ + no-store
  MN-->>EN: 200
  EN-->>C: 200 (ไม่ถูก cache)
  Note over O: origin ไม่ถูกเรียกเลย
```

*รูปที่ 12 — คำขอที่เข้า deception*

```text
Client → Edge → WAF (กฎ DECEIVE, phase 1, 418) → Main → Deception layer → Synthetic response → Client
```

**ยืนยันว่า origin ไม่ถูกติดต่อ:** `@deception` และ `@deception_via_main` proxy ไปเฉพาะ FastAPI/Main ไม่มี upstream ของ origin; ทดสอบจริงได้ 200 + body สังเคราะห์ + `no-store` และ edge ไม่ใส่ `X-Cache-Status` (ไม่ผ่าน cache)

รายละเอียด: บทที่ 17

## แหล่งอ้างอิง (Evidence)
- smoke test 2026-09-27 (11/11 ผ่าน), template ของ Main และ edge
