---
title: "บทที่ 47 — การสำรองและกู้คืน (Backup & Restore)"
chapter: 47
part: "Part VIII — Operations"
status: UNKNOWN
---

# บทที่ 47 — การสำรองและกู้คืน (Backup & Restore)

## 47.1 สิ่งที่พบ

ไม่พบงาน backup อัตโนมัติ (cron มีเพียง `waf-geoip`, `e2scrub_all`) และยังไม่เคยทดสอบการกู้คืน → **UNKNOWN / ต้องจัดทำ**

## 47.2 ข้อมูลที่ต้องสำรอง

| ข้อมูล | ที่อยู่ | วิธีที่เสนอ (ยังไม่ได้ทดสอบ) |
|---|---|---|
| โค้ดและ config | git (GitHub `Backend`) | push ทุกครั้งที่ deploy |
| `.env`, `/etc/frp/frps.toml`, `/opt/cloudwaf-tunnel` | Main | เข้ารหัสแล้วเก็บนอกเครื่อง |
| กฎ custom | `modsecurity/custom-rules/` | อยู่ใน git บางส่วน; tar ทั้งไดเรกทอรี |
| ClickHouse | volume `clickhouse_data` | `BACKUP` ของ ClickHouse หรือ export ตามช่วงเวลา (log อายุ 30 วัน) |
| DynamoDB | AWS | เปิด Point-in-Time Recovery (สถานะปัจจุบัน UNKNOWN) |
| SQLite + settings | `dashboard/backend/data/` | tar |
| ใบรับรอง Caddy | volume `caddy_data` | ออกใหม่อัตโนมัติได้ ไม่จำเป็นต้องสำรอง |

## 47.3 ตัวอย่างการสำรองก่อนเปลี่ยนแปลง (ใช้จริงระหว่าง deploy)

```bash
cd /root/waf_project && tar czf /root/deploy-backup-$(date -u +%Y%m%dT%H%M%SZ).tgz <ไฟล์ที่จะเปลี่ยน>
git stash create   # เก็บสถานะ working tree เป็น commit object โดยไม่แตะไฟล์
```

## แหล่งอ้างอิง (Evidence)
- `ls /etc/cron.d`, `crontab -l`
