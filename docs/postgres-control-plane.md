# ฐานข้อมูล control-plane: PostgreSQL

ย้ายจาก DynamoDB 14 ตาราง และ SQLite 2 ไฟล์ มาเป็น PostgreSQL ตัวเดียวบนเครื่อง Main เสร็จเมื่อ 15 ต.ค. 2026 (Phase 0-8 ของแผนย้าย) ส่วน ClickHouse, Redis และไฟล์ JSON config ยังอยู่ที่เดิม

## อยู่ที่ไหน

| อะไร | ที่ |
|---|---|
| container | service `postgres` ใน `docker-compose.yml` หลัก ชื่อ container `waf-postgres` (postgres:16.15-alpine) |
| พอร์ต | `127.0.0.1:5432` เท่านั้น (เปลี่ยนได้ด้วย `WAF_PG_PORT`) |
| ข้อมูล | docker volume `waf_pgdata` |
| schema | `waf` มี 19 ตาราง, `schema_migrations` และ view `origin_hostnames` |
| migration | `dashboard/backend/db/migrations/*.sql` รันด้วย `db/migrate.py` (ไฟล์ที่ apply แล้วห้ามแก้ ให้เพิ่มไฟล์ใหม่) |
| รหัสผ่าน | โฟลเดอร์ `WAF_SECRETS_DIR` (บน Main คือ `/root/.waf-secrets/`; เครื่องใหม่ค่าเริ่มต้นคือ `./secrets/` ซึ่ง git ไม่ track) ได้แก่ `pg_owner_password` (compose secret), `pg_owner.env` (DSN ของเจ้าของ schema ใช้กับ migrate เท่านั้น), `pg_app_password`, `pg_maint_password` |
| ค่าที่แอปใช้ | `.env`: `DATABASE_URL` (role `waf_app_login`), `DATABASE_URL_MAINT` (role `waf_maint_login`), `JWT_SECRET_KEY` |
| backup | `/etc/cron.d/waf-pg-backup` รัน `deploy/postgres/backup.sh` ทุก 6 ชม. ไปที่ `WAF_BACKUP_DIR` (บน Main คือ `/root/backups/pg/`) และเก็บไว้ 7 วัน |

## ติดตั้งบนเครื่องใหม่ (หลัง clone)

ต้องมี docker compose, openssl และ Python 3.12+ ที่ติดตั้ง `dashboard/backend/requirements.txt` แล้ว (ค่าเริ่มต้นคือ `dashboard/backend/.venv`; ถ้าอยู่ที่อื่นให้ตั้ง `PYTHON=`)

```bash
cp .env.example .env                  # แล้วใส่ค่าอื่นของระบบตามต้องการ
bash deploy/postgres/bootstrap.sh     # สร้างรหัสผ่าน, start postgres, migrate, สร้าง role, เติม .env
dashboard/backend/.venv/bin/python dashboard/backend/scripts/seed_admin.py \
    --email you@example.com --role admin --generate-password secrets/admin_login_password
docker compose up -d                  # service อื่นของระบบ
```

`bootstrap.sh` รันซ้ำได้: ไม่สร้างรหัสใหม่ทับของเดิม และไม่แก้ค่าที่มีอยู่แล้วใน `.env` (เติมเฉพาะค่าที่ว่างหรือยังไม่มี รวมถึงสุ่ม `JWT_SECRET_KEY`, `CLICKHOUSE_PASSWORD`, `CONTROL_TOKEN` และ `ML_RELAY_SECRET` ให้เมื่อว่าง ค่าพวกนี้ต้องมีก่อน เพราะ `docker-compose.yml` จะไม่ยอมรันถ้าขาด)

## Role

- `waf_owner`: เจ้าของ schema ใช้รัน migration เท่านั้น และไม่อยู่ใน env ของแอป
- `waf_app` (login: `waf_app_login`):
  - อ่านและเขียนตารางงานทั่วไปได้
  - `audit_logs` ทำได้แค่ INSERT/SELECT
  - `statement_timeout` 5 วินาที, `idle_in_transaction_session_timeout` 10 วินาที
- `waf_maintenance` (login: `waf_maint_login`): รัน `waf.run_retention()` ได้อย่างเดียว

## กฎที่โค้ดต้องรักษา

- `audit_logs` เป็น append-only:
  - trigger ปฏิเสธ UPDATE และ TRUNCATE
  - ลบได้เฉพาะแถวที่อายุเกิน 180 วัน
  - การเขียน audit เป็นแบบ fail-closed และอยู่ใน transaction เดียวกับการแก้ไข (`services.txn.atomic`)
- ห้ามเรียก I/O ภายนอกระหว่างที่ transaction เปิดอยู่ เช่น Gemini, NVD, DNS, reload nginx หรือเขียนไฟล์
- id ที่มาจาก URL หรือ token ต้องผ่าน `db.values.as_uuid()` ก่อน ถ้าไม่ใช่ uuid ให้ถือว่า "ไม่พบ" (ไม่ใช่ 500)

## งานลบข้อมูลตามอายุ

`services/retention_worker.py` รันตอน start และทุก 1 ชม.:

1. รัน `waf.run_retention()` ในฐานะ maintenance role:

   | ตาราง | เก็บไว้ |
   |---|---|
   | audit_logs | 180 วัน |
   | threat_patterns | 72 ชม. |
   | status_history_days | 400 วัน |
   | alerts | 90 วัน |

2. ลบ temp ban ของ IP ที่หมดอายุ แล้ว render ไฟล์ block/allow ของ ModSecurity ใหม่จากตารางทุกรอบ จะ reload nginx เฉพาะเมื่อไฟล์เปลี่ยน

## งานที่ทำบ่อย

```bash
# สถานะ migration
cd /root/waf_project/dashboard/backend
WAF_PG_OWNER_ENV=/root/.waf-secrets/pg_owner.env .venv/bin/python db/migrate.py --status

# apply migration ใหม่
WAF_PG_OWNER_ENV=/root/.waf-secrets/pg_owner.env .venv/bin/python db/migrate.py

# สร้างหรือเลื่อนสิทธิ์ admin (สมัครเองบนเว็บได้แค่ viewer)
.venv/bin/python scripts/seed_admin.py --email someone@example.com --role admin \
    --generate-password /root/.waf-secrets/someone_login_password

# backup ทันที / ดูไฟล์ backup
bash /root/waf_project/deploy/postgres/backup.sh
docker exec waf-postgres pg_restore --list /backups/<file>.dump | head

# ตรวจว่าแอปต่อ DB ได้
curl -s http://127.0.0.1:8000/api/health    # ต้องมี "db": "ok"
```

## กู้คืนจาก backup

ระบบอยู่ในขั้น DEV:

1. หยุดแอป: `systemctl stop waf-dashboard`
2. กู้คืน: `docker exec waf-postgres pg_restore -U waf_owner -d waf --clean --if-exists /backups/<file>.dump`
3. เปิดแอปกลับ: `systemctl start waf-dashboard`

ต้องซ้อมกู้คืนเข้า database ชั่วคราวก่อนทำกับของจริง

## เทส

ทุกเทสรันบน PostgreSQL จริง: `tests/pg_harness.py` สร้าง database ชั่วคราวจาก migrations และล้างข้อมูลก่อนทุกเทส

```bash
TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:55432/postgres python -m pytest tests/
```

ใน CI มี service `postgres:16.15-alpine` ให้แล้ว

## ของเดิมที่ปลดระวางแล้ว

- compose project แยก `waf-postgres` (`deploy/postgres/compose.yml`) เลิกใช้แล้ว ย้าย container เดิมมาอยู่ใต้ `docker-compose.yml` หลักเมื่อ 15 ต.ค. 2026 (ใช้ volume `waf_pgdata` เดิม)
- DynamoDB:
  - โค้ดไม่เรียกแล้ว และถอน boto3 ออกจาก venv แล้ว
  - ลบ AWS key ออกจาก `.env` แล้ว (backup อยู่ใน `/root/backups/pre-pg-switch-20261014-210433/`)
  - **ที่เหลือต้องทำใน AWS console โดยเจ้าของบัญชี:**
    - backup แล้วลบตาราง `waf_*`
    - ลบ IAM user/key เดิม (ทำจากที่นี่ไม่ได้เพราะ key ใช้ไม่ได้แล้ว)
- SQLite:
  - `data/ip_rules.db` และ `data/rate_limits.db` เปลี่ยนชื่อเป็น `*.retired-20261015`
  - สำเนาอยู่ใน `/root/backups/pre-pg-switch-20261014-210433/sqlite/`
  - ตอนย้าย ip_rules ไม่มีข้อมูล และกฎ rate limit 3 ตัวตรงกับ seed ใน `0002`
