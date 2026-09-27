---
title: "บทที่ 42 — การจัดการฐานข้อมูล"
chapter: 42
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 42 — การจัดการฐานข้อมูล

## 42.1 ClickHouse (อ่านอย่างเดียว)

เขียน SQL ลงไฟล์แล้วส่งผ่าน stdin เพื่อเลี่ยงปัญหา quoting ของ shell:
```bash
cat > /tmp/q.sql <<'SQL'
SELECT toStartOfHour(timestamp) h, count() FROM default.access_logs
WHERE timestamp > now() - INTERVAL 1 DAY GROUP BY h ORDER BY h;
SQL
docker exec -i waf-clickhouse clickhouse-client --multiquery < /tmp/q.sql
```

การลบข้อมูล (`DELETE FROM ...`) เปลี่ยนข้อมูลจริง ให้ `SELECT count()` ด้วยเงื่อนไขเดียวกันก่อนเสมอ

## 42.2 DynamoDB

จัดการผ่านโค้ด/สคริปต์ใน `dashboard/backend/scripts/` (สร้างตาราง, GSI, migration) หรือ AWS CLI จากเครื่องที่มีสิทธิ์ การ migrate สำคัญในอดีต: `migrate_alerts_to_origin_key.py` (`waf_alerts` → `waf_alerts_v2`)

## 42.3 SQLite

`dashboard/backend/data/ip_rules.db`, `rate_limits.db` — แก้ผ่าน API/หน้าเว็บเท่านั้น ชุดทดสอบเคยสำรองไฟล์เหล่านี้เป็น `*.pytest-backup-*`

## 42.4 Redis

`docker exec -it waf-redis redis-cli` (อย่าใช้ `FLUSHALL` บน production)

## แหล่งอ้างอิง (Evidence)
- คำสั่ง ClickHouse ใช้จริง 2026-09-27
