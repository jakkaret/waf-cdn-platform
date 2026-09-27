---
title: "Documentation Traceability"
status: VERIFIED
---

# ตารางอ้างอิงหลักฐาน (Documentation Traceability)

| Documentation claim | Evidence | Status |
|---|---|---|
| มี VM 3 เครื่อง: Main (Hetzner), edge-th, edge-asia (Azure) | `hostnamectl`, DMI, Hetzner metadata, `docker ps` บนทั้งสาม | VERIFIED |
| Main 2 vCPU / 3.7 GiB / Ubuntu 26.04 | `nproc`, `free -h`, `hostnamectl` | VERIFIED |
| container บน Main 7 ตัว | `docker ps -a` 2026-09-27 | VERIFIED |
| FastAPI ให้บริการ dashboard API ที่ :8000 | `systemctl show waf-dashboard`, `ss -ltnp`, `main.py` | VERIFIED |
| 24 routers / 123 endpoints | `main.py` include_router, AST ของ `api/*.py` (`reference/api-reference.md`) | VERIFIED |
| WAF ใช้ ModSecurity + CRS 3.3.10, PL1, threshold 10 | `docker-compose.yml` env, audit `OWASP_CRS/3.3.10`, env edge | VERIFIED |
| custom rules โหลดหลัง CRS | `nginx/templates/modsecurity.d/setup.conf.template` | VERIFIED |
| DECEIVE = phase 1 status 418 | `services/rule_manager.py::_build_secrule_directives`, `custom-deceive.conf` | VERIFIED |
| Deception คืนข้อมูลสังเคราะห์และไม่ติดต่อ origin | template nginx `@deception`, smoke test 11/11 | VERIFIED |
| Edge ส่ง 418 ต่อไป Main | edge template `@deception_via_main`, ทดสอบผ่าน https | VERIFIED |
| `cdn.waf-it-kku.online` → edge-th, NS = Hostinger | `dig` | VERIFIED |
| GeoDNS ไม่อยู่ในเส้นทาง DNS สาธารณะ | `dig NS` + `cdn/geodns/server.py` | VERIFIED |
| Edge ดึงกฎทุก 5 วินาที | `99-rulesync.sh`, env `SYNC_INTERVAL_SEC=5` | VERIFIED |
| Edge ส่ง log ไป Main :8000 | edge compose `MAIN_SERVER_URL`, `api/cdn.py:507` | VERIFIED |
| Port 8000 เปิดจากอินเทอร์เน็ต | `nc -z` จากภายนอก, `ufw status` | VERIFIED |
| Redis/ClickHouse ไม่เปิดสู่ภายนอก | `nc -z` จากภายนอก | VERIFIED |
| JWT HS256 อายุ 60 นาที, Argon2 | `services/auth_service.py:18–75` | VERIFIED |
| ผู้ใช้คนแรกเป็น admin อัตโนมัติ | `api/auth.py:44–58` | VERIFIED |
| Log แยก tenant ด้วย `host` แบบ fail closed | `services/tenant_service.py:72–96` | VERIFIED |
| การตรวจ origin ของ viewer เป็นแบบตรงตัว (แก้จาก substring 2026-09-28) | `services/tenant_service.py::is_origin_owned`, `tests/test_host_attribution.py`, `tests/test_logs_router.py` (722 passed) | VERIFIED |
| Alert partition ตาม `origin_id`, `unattributed` | `scripts/migrate_alerts_to_origin_key.py`, `telegram_listener.py` | VERIFIED |
| Telegram ส่งเฉพาะ admin + owner/editor/viewer ของ origin | `telegram_listener.py::_alert_recipients`, `tests/test_telegram_recipients.py` | VERIFIED |
| access_logs TTL 30 วัน | `clickhouse_service.py:17,131` | VERIFIED |
| ML accuracy 0.8047 ไม่ผ่านเป้า | `GET 127.0.0.1:5000/health` | VERIFIED |
| analyzer ไม่บันทึก pending rule | `ml/async_log_analyzer.py:108–118` | VERIFIED |
| pending rule สร้างผ่าน `/api/ml/predict-and-suggest` | `api/ml.py:174`, `MLAnalyst.tsx:55` | VERIFIED |
| Cache key มี host และ skip เมื่อมี query/cookie session | edge `default.conf.template` | VERIFIED |
| Purge ไม่ถึง edge | `api/cdn.py:30`, `.env` ไม่มี `CDN_PURGE_API_URL`, edge ไม่มี purge location | VERIFIED |
| ใบรับรองจาก Let's Encrypt/ZeroSSL | `openssl s_client` | VERIFIED |
| Caddy ask อนุญาตเฉพาะโดเมนที่ลงทะเบียน | `api/domains.py`, ทดสอบ 400 กับโดเมนแปลกปลอม | VERIFIED |
| Backend tests 714 passed | รันในสำเนาแยก 2026-09-27 | VERIFIED |
| Frontend unit 33 passed | `npx vitest run` 2026-09-28 | VERIFIED |
| ไม่มี backup อัตโนมัติ | `/etc/cron.d`, `crontab -l` | VERIFIED |
| Edge-asia รับ traffic จริง | ไม่มีหลักฐาน DNS | UNKNOWN |
| OTP ทางอีเมลทำงาน | SMTP ว่าง | UNKNOWN |
| DynamoDB PITR เปิดอยู่ | ไม่ได้ตรวจ | UNKNOWN |
