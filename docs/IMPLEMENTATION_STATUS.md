---
title: "Implementation Status"
status: VERIFIED
---

# สถานะการพัฒนา (Implementation Status)

ประเมินจากหลักฐาน ณ 2026-09-27/28 (commit `c033758`)

| Component | Status | Evidence | Notes |
|---|---|---|---|
| WAF Main (ModSecurity + CRS 3.3.10) | VERIFIED | config + runtime + ทดสอบ 403 | PL1, threshold 10 |
| WAF Edge | VERIFIED | env + log ModSecurity ของ edge | ตรวจซ้ำสองชั้น |
| Custom rules BLOCK/CHALLENGE/DECEIVE | VERIFIED | `rule_manager.py` + tests | ไม่มี enable/disable แยก |
| Deception layer | VERIFIED | smoke test + tests | template SQLi เลือกด้วย heuristic |
| Challenge captcha | VERIFIED (โค้ด) | control-api, nginx includes | พฤติกรรม 429 บน Main ควรทดสอบเพิ่ม |
| Challenge OTP ทางอีเมล | UNKNOWN | SMTP ไม่ได้ตั้งค่า | |
| CDN cache | VERIFIED | template + tester | |
| Cache purge ถึง edge | PARTIAL | `api/cdn.py`, ไม่มี endpoint ที่ edge | บทที่ 24/45 |
| Edge-th | VERIFIED | runtime | รับ traffic จริง |
| Edge-asia | PARTIAL | runtime | ไม่มีเส้นทาง DNS สาธารณะ |
| GeoDNS | PARTIAL | container รัน, NS เป็น Hostinger | |
| TLS on-demand | VERIFIED | Caddy config + openssl | |
| Tunnel FRP / CloudWAF | VERIFIED | systemd + code | |
| Backend API (123 endpoints) | VERIFIED | AST + runtime | |
| Frontend | VERIFIED | build + vitest | |
| Multi-tenant logs | VERIFIED | `tenant_service.py`, tests | ช่องโหว่ substring แก้แล้ว 2026-09-28 (KNOWN_ISSUES #7) |
| Multi-tenant alerts | VERIFIED | `waf_alerts_v2` partition, `_alert_recipients` + tests | Telegram ส่งเฉพาะผู้มีสิทธิ์ตั้งแต่ 2026-09-28 (KNOWN_ISSUES #8) |
| Authentication (JWT, Argon2, Google OAuth) | VERIFIED | code | ไม่มี refresh token |
| Logging → ClickHouse | VERIFIED | runtime | IP ผ่าน edge เป็น IP ของ edge |
| Alerting (DynamoDB + Telegram + Gemini) | VERIFIED | code + journal | Gemini quota free tier |
| ML inference | VERIFIED | `/health` | accuracy 0.8047 < เป้า |
| ML → pending rules อัตโนมัติ | PARTIAL | analyzer ไม่บันทึก | ผ่านหน้า Analyst เท่านั้น |
| ML rule approval → deploy | VERIFIED | `ml_rule_service.approve_rule` | |
| Threshold proposals | VERIFIED | code | admin approve/rollback |
| BOLA guard | PARTIAL | API + หน้าเว็บ | ยังไม่ได้ตรวจการบังคับใช้ |
| IP rules / rate limit | VERIFIED (โค้ด) | code + nginx auth_request | |
| Public status page | VERIFIED | `/api/status/public` 200 | |
| Concepts pages | PLANNED | หน้า preview | ไม่ได้เชื่อมการทำงานจริงทั้งหมด |
| Backup / DR | UNKNOWN | ไม่พบงาน backup | ต้องจัดทำ |
| CI | PARTIAL | `ci.yml` | trigger ไม่ตรง branch `Backend`, ไม่รัน pytest |
| Legacy local CDN (SG/JP/TH containers, purge-api, stats) | DEPRECATED | ไม่รัน, log หยุดตั้งแต่ ส.ค. | |
