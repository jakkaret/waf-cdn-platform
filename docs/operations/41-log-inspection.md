---
title: "บทที่ 41 — การตรวจ Log"
chapter: 41
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 41 — การตรวจ Log

| Log | คำสั่ง |
|---|---|
| backend | `journalctl -u waf-dashboard -n 100 --no-pager` |
| ML / analyzer | `journalctl -u waf-ml`, `journalctl -u waf-log-analyzer` |
| nginx access (Main) | `tail -f /root/waf_project/logs/nginx/access.json` |
| ModSecurity audit (Main) | `/root/waf_project/logs/modsecurity/audit.json` |
| ModSecurity เหตุผลการบล็อก (edge) | `docker logs cdn-edge-node 2>&1 \| grep ModSecurity \| tail` |
| edge access | `/root/edge_node/logs/cdn/access.json` |
| ClickHouse | ดูบทที่ 42 |

การค้นคำขอหนึ่งรายการ: ใช้ `request_id` (มีทั้งใน access log, audit log และ `access_logs.request_id`)

## แหล่งอ้างอิง (Evidence)
- runtime (ใช้จริงในการสืบปัญหา)
