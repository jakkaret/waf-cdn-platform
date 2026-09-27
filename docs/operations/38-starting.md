---
title: "บทที่ 38 — การเริ่มระบบ"
chapter: 38
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 38 — การเริ่มระบบ

## 38.1 Main

```bash
cd /root/waf_project
docker compose up -d                      # caddy, waf-nginx, control-api, clickhouse, redis, dvwa
systemctl start frps cloudwaf-tunnel      # tunnel servers
systemctl start waf-ml waf-dashboard waf-log-analyzer
```

ลำดับที่แนะนำ: ฐานข้อมูล (clickhouse, redis) → ML → backend → nginx/caddy เพื่อให้ nginx เรียก backend ได้ทันที (`depends_on` ใน compose ควบคุมเฉพาะ container)

## 38.2 Edge

```bash
cd /root/edge_node          # edge-asia: /opt/edge_node
docker compose up -d
```

## 38.3 Frontend (เมื่อมีการเปลี่ยนโค้ด)

```bash
cd /root/waf_project/dashboard/frontend && npm run build   # tsc -b && vite build → dist/
```
backend เสิร์ฟไฟล์ใหม่ทันที ไม่ต้อง restart

## แหล่งอ้างอิง (Evidence)
- `docker-compose.yml`, systemd units, `package.json` (`"build": "tsc -b && vite build"`) — build ถูกรันจริง 2026-09-27
