---
title: "บทที่ 46 — การจัดการ TLS"
chapter: 46
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 46 — การจัดการ TLS

| งาน | วิธี |
|---|---|
| ดูผู้ออกและวันหมดอายุ | `echo \| openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null \| openssl x509 -noout -issuer -enddate` |
| ตรวจว่า Caddy ใช้ ask ที่ถูกต้อง | `docker exec caddy-ssl-termination wget -qO- http://127.0.0.1:2019/config/ \| grep -o '"endpoint":"[^"]*"'` → ต้องเป็น `.../api/domains/check-ssl-allowed` |
| ทดสอบการตัดสินของ ask | `curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8000/api/domains/check-ssl-allowed?domain=<domain>'` → 200 = อนุญาต, 400 = ไม่อนุญาต |
| ตรวจ Caddyfile ก่อนใช้ | `docker run --rm -v /root/waf_project/nginx/Caddyfile:/etc/caddy/Caddyfile:ro caddy:alpine caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile` |
| ใช้ Caddyfile ใหม่ | `docker restart caddy-ssl-termination` (Caddyfile mount เป็นไฟล์เดี่ยว) |
| ต่ออายุ | Caddy ทำอัตโนมัติ |

## แหล่งอ้างอิง (Evidence)
- คำสั่งทั้งหมดใช้จริง 2026-09-27 (แก้กรณี ask ชี้ `/api/health`)
