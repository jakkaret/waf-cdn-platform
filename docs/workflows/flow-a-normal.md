---
title: "Flow A — คำขอปกติ (Normal Request)"
part: "Part VII — Complete Data Flows"
status: VERIFIED
---

# Flow A — คำขอปกติ (Normal Request)

```mermaid
sequenceDiagram
  participant C as Client
  participant D as DNS
  participant EC as Edge Caddy
  participant EN as Edge nginx
  participant MN as Main waf-nginx
  participant S as control-api shield
  participant T as Tunnel (frps / cloudwaf)
  participant O as Origin
  C->>D: resolve shop.example.com
  D-->>C: CNAME cdn.waf-it-kku.online → edge-th
  C->>EC: HTTPS
  EC->>EN: HTTP + security headers
  EN->>EN: rate limit, ModSecurity (ผ่าน), cache MISS
  EN->>MN: HTTP :8080 (Host เดิม)
  MN->>MN: ModSecurity (ผ่าน)
  MN->>S: auth_request /internal-shield-check
  S-->>MN: 200 (ไม่ต้อง challenge)
  MN->>T: proxy_pass
  T->>O: ผ่าน tunnel ที่ origin เปิดไว้
  O-->>C: 200 (ย้อนกลับทางเดิม, edge อาจ cache)
  MN-->>MN: access.json → log_forward → ClickHouse
```

*รูปที่ 9 — คำขอปกติจาก client ถึง origin*

| ลำดับ | องค์ประกอบ | สิ่งที่เกิด |
|---|---|---|
| 1 | Hostinger DNS | คืน CNAME → edge-th |
| 2 | Edge Caddy | TLS (ใบรับรอง on-demand), เพิ่ม security headers |
| 3 | Edge nginx | rate limit, ModSecurity CRS, ค้น cache |
| 4 | Main waf-nginx | ModSecurity อีกชั้น, `auth_request` shield/rate limit |
| 5 | Tunnel | FRP หรือ CloudWAF tunnel ส่งต่อไป origin |
| 6 | Logging | Main เขียน `access.json` → ClickHouse; edge ส่ง log ผ่าน forwarder |

ถ้าเป็น GET ที่ cache ได้และ HIT ขั้น 4–5 จะไม่เกิด (บทที่ 24)

## แหล่งอ้างอิง (Evidence)
- บทที่ 18, 22–25; template ของ edge และ Main
