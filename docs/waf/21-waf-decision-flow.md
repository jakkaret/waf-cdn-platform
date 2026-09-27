---
title: "บทที่ 21 — ลำดับการตัดสินใจของ WAF"
chapter: 21
part: "Part IV — WAF"
status: VERIFIED
---

# บทที่ 21 — ลำดับการตัดสินใจของ WAF (WAF Decision Flow)

```text
Request
 ↓ (edge) rate limit 50 r/s → ModSecurity phase 1 → phase 2 (CRS + custom) → cache
 ↓ (Main) ModSecurity phase 1 → phase 2 → auth_request (shield / rate limit ต่อ path)
 ├── Allow      → upstream (origin / tunnel)
 ├── Block      → 403 /403.html
 ├── Challenge  → 401 → captcha / OTP (control-api)
 ├── RateLimit  → 429
 └── Deceive    → 418 → @deception → 200 synthetic
```

## 21.1 ลำดับจริง

| ขั้น | ที่ไหน | ผลที่เป็นไปได้ |
|---|---|---|
| 1. TLS + security headers | Edge Caddy | ปฏิเสธ TLS ถ้าโดเมนไม่ได้รับอนุญาต |
| 2. `limit_req` zone `edge_ratelimit` | Edge nginx | 429 |
| 3. ModSecurity phase 1 (header/URI) | Edge nginx | 418 (DECEIVE) / 403 (blocklist) |
| 4. ModSecurity phase 2 (body, CRS 949110) | Edge nginx | 403 |
| 5. Cache lookup | Edge nginx | HIT → ตอบเลย |
| 6. ModSecurity phase 1–2 | Main waf-nginx | 418 / 401 / 403 |
| 7. `auth_request` shield + rate limit | Main waf-nginx | 401 → challenge, 429 |
| 8. proxy ไป upstream | Main | response จาก origin |

## 21.2 ลำดับความสำคัญ

1. phase 1 ก่อน phase 2 เสมอ → DECEIVE (phase 1) ชนะ CRS (phase 2)
2. ใน phase เดียวกัน CRS โหลดก่อนกฎ custom → กฎ BLOCK/CHALLENGE (phase 2) ของ custom จะไม่ได้ทำงานถ้า CRS บล็อกไปแล้ว
3. คำขอที่ถูก cache ที่ edge ไม่ผ่าน Main เลย (แต่ผ่าน WAF ของ edge แล้ว)

ดู sequence diagram ของแต่ละผลลัพธ์ใน Part VII

## แหล่งอ้างอิง (Evidence)
- template ของ edge และ Main, `setup.conf.template`, ผลทดสอบ 2026-09-27
