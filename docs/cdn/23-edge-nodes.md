---
title: "บทที่ 23 — Edge Nodes"
chapter: 23
part: "Part V — CDN"
status: VERIFIED
---

# บทที่ 23 — Edge Nodes

| รายการ | edge-th | edge-asia |
|---|---|---|
| IP | 45.154.26.91 | 57.158.25.236 |
| ที่ตั้ง/ผู้ให้บริการ | VPS KVM (โค้ด GeoDNS ระบุ Nonthaburi, Thailand) | Microsoft Azure |
| สเปก | 1 vCPU, 1.9 GiB RAM | 1 vCPU, 893 MiB RAM |
| `EDGE_REGION` | `edge-th` | `edge-asia` |
| Deploy dir | `/root/edge_node` | `/opt/edge_node` |
| Container | cdn-caddy-ssl, cdn-edge-node (healthy), cdn-log-forwarder | เหมือนกัน |
| WAF | ModSecurity CRS 3.3.10, PL1, threshold 10, `MODSEC_RULE_ENGINE=on` | เหมือนกัน |
| Rate limit | 50 r/s, burst 100 (dynamic) / 200 (static), ตอบ 429 | เหมือนกัน |
| Cache | `proxy_cache_path /var/cache/nginx/edge`, zone `edge_cache:80m` | เหมือนกัน |
| Origin | `ORIGIN_HOST=178.104.53.123`, `ORIGIN_PORT=8080` | เหมือนกัน |
| Health check | `GET /healthz` ทุก 10 วินาที (docker) → JSON `{"status":"ok","region":...}` | เหมือนกัน |
| รับ traffic จริง | ใช่ (ปลายทางของ `cdn.waf-it-kku.online`) | ไม่พบเส้นทาง DNS สาธารณะ (PARTIAL) |

## 23.1 Security headers ที่ edge Caddy เพิ่ม

`Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy`, ลบ `Server`

## 23.2 Rule sync

`99-rulesync.sh`: ดาวน์โหลด bundle → เทียบ sha256 → แตกไฟล์ลง `/opt/custom-rules` → `nginx -s reload` ถ้าเปลี่ยน ทำซ้ำทุก `SYNC_INTERVAL_SEC` (5) วินาที control-api เปิดให้เฉพาะ IP ของ edge (ufw)

## แหล่งอ้างอิง (Evidence)
- `docker inspect cdn-edge-node` (env), `/root/edge_node/docker-compose.yml`, `edge/Caddyfile`, `edge/templates/nginx.conf.template`
