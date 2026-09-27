---
title: "บทที่ 19 — ModSecurity"
chapter: 19
part: "Part IV — WAF"
status: VERIFIED
---

# บทที่ 19 — ModSecurity

## 19.1 เวอร์ชันและการเชื่อมกับ nginx

libmodsecurity **3.0.16** + connector ModSecurity-nginx **1.0.4** (จาก log ตอน reload ของ edge) ทำงานใน process ของ nginx ตรวจทุกคำขอก่อน proxy

## 19.2 การตั้งค่าหลัก (`nginx/templates/modsecurity.d/modsecurity.conf.template`)

| Directive | ค่า | ความหมาย |
|---|---|---|
| `SecRuleEngine` | `on` | บล็อกจริง (ไม่ใช่แค่ตรวจ) |
| `SecRequestBodyAccess` | `on` | ตรวจ body |
| `SecRequestBodyLimit` | 13107200 (12.5 MB) + `Reject` | body ใหญ่กว่านี้ถูกปฏิเสธ |
| `SecResponseBodyAccess` | `on` | ตรวจ response (outbound rules) |
| `SecAuditEngine` | `RelevantOnly` | บันทึก audit เฉพาะธุรกรรมที่เกี่ยวข้อง |
| `SecAuditLogFormat` / `Type` | `JSON` / `Serial` | เขียน `/var/log/modsecurity/audit.json` |
| `SecAuditLogParts` | `ABIJDEFHZ` | ส่วนของธุรกรรมที่บันทึก |

## 19.3 ลำดับการโหลดกฎ (`setup.conf.template`)

```text
modsecurity.conf → modsecurity-override.conf → owasp-crs/crs-setup.conf → owasp-crs/rules/*.conf → /opt/custom-rules/*.conf
```

ผล: กฎ custom ถูกโหลด **หลัง** CRS ภายใน phase เดียวกัน CRS 949110 (phase 2) จะตัดสินบล็อกก่อนกฎ custom ใน phase 2 นี่คือเหตุผลที่กฎ DECEIVE ใช้ phase 1

## 19.4 Disruptive actions ที่ระบบใช้

| Action | Status | ใครจัดการต่อ |
|---|---|---|
| Block | `deny,status:403` | หน้า `/403.html` |
| Challenge | `deny,status:401` + `tag:'action:challenge'` | captcha/OTP ของ control-api |
| Deceive | `deny,status:418` + `tag:'action:deceive'` | `@deception` (บทที่ 17) |
| Global blocklist | `SecRule REMOTE_ADDR "@ipMatchFromFile .../global_blocklist.txt"` | สร้างโดย control-api ใน bundle |

## 19.5 แหล่งกฎ custom

| ไฟล์ | สร้างโดย |
|---|---|
| `custom-<id>.conf` | หน้า WAF Rules (`services/rule_manager.py`) |
| `ml-<id>.conf` | การอนุมัติกฎจาก ML |
| `custom-deceive.conf` | กฎทดสอบ deception |
| `dashboard-sync.conf` | `scripts/sync_waf_rules.py` (container edge แบบเดิม — DEPRECATED) |

ทุกครั้งที่แก้กฎ ระบบรัน `nginx -t` ก่อน reload ถ้าไม่ผ่านจะลบ/คืนไฟล์

## แหล่งอ้างอิง (Evidence)
- `nginx/templates/modsecurity.d/*.template`, `modsecurity/custom-rules/`, `services/rule_manager.py`, `cdn/control-api/main.py:100`
