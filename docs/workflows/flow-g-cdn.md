---
title: "Flow G — CDN (Cache Hit / Miss)"
part: "Part VII — Complete Data Flows"
status: VERIFIED
---

# Flow G — CDN (Cache Hit / Miss)

```mermaid
sequenceDiagram
  participant C as Client
  participant EC as Edge Caddy
  participant EN as Edge nginx
  participant K as proxy_cache /var/cache/nginx/edge
  C->>EC: HTTPS GET /logo.png
  EC->>EN: HTTP
  EN->>EN: ModSecurity ผ่าน, rate limit ผ่าน
  EN->>K: key = host|method|uri+args
  K-->>EN: HIT
  EN-->>C: 200 + X-Cache-Status: HIT, X-Edge-Region
```

*รูปที่ 16 — Cache hit*

```mermaid
sequenceDiagram
  participant C as Client
  participant EN as Edge nginx
  participant K as proxy_cache
  participant M as Main waf-nginx :8080
  participant O as Origin
  C->>EN: GET /page (ผ่าน Caddy)
  EN->>K: lookup
  K-->>EN: MISS (หรือ skip: ไม่ใช่ GET/HEAD, มี Authorization, cookie session, มี query)
  EN->>M: proxy_pass website_origin
  M->>M: ModSecurity CRS
  M->>O: tunnel / upstream
  O-->>M: 200
  M-->>EN: 200
  EN->>K: เก็บ 200/301/302 (10 นาที dynamic, 1 ชั่วโมง static) ถ้าไม่ถูก skip
  EN-->>C: 200 + X-Cache-Status: MISS
```

*รูปที่ 17 — Cache miss*

- ตรวจสถานะได้จาก header `X-Cache-Status` (HIT / MISS / BYPASS / EXPIRED …) และ `X-Edge-Region`
- ทดสอบจริง: `robots.txt` ของ dvwa และ juice ได้เนื้อหาของใครของมัน คำขอที่สองเป็น HIT ต่อ host (cache key มี `$host`)

## แหล่งอ้างอิง (Evidence)
- บทที่ 24, ผลตรวจของ tester 2026-09-27
