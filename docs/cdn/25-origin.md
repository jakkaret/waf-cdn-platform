---
title: "บทที่ 25 — Origin"
chapter: 25
part: "Part V — CDN"
status: VERIFIED
---

# บทที่ 25 — Origin

## 25.1 วิธีที่ Main ติดต่อ origin

| โหมด | กลไก | การยืนยัน | สถานะ |
|---|---|---|---|
| FRP tunnel | origin รัน `frpc`/waf-agent ต่อขาออกไป `frps :7000`; Main ส่งคำขอผ่าน `frp_tunnel_router` (`172.18.0.1:8085`) โดยใช้ Host | token ที่ลงนาม (JWT) ตรวจโดย `/api/tunnels/frp-hook` | VERIFIED |
| CloudWAF tunnel | agent ของโครงการ (`tunnel/agent.py`) ต่อไป `:8050` (TLS + token ต่อ origin); Main ใช้ `cloudwaf_tunnel` (`172.18.0.1:8060`) | `/api/tunnel/verify-agent` เทียบ hash ของ token | VERIFIED |
| Lab container | `dvwa` บน docker network เดียวกัน | – | VERIFIED |
| Direct reverse proxy ไป IP ของ origin | route ต่อโดเมนใน nginx (`services/nginx_site_service.py`) | ต้องยืนยัน DNS | PARTIAL (มีโค้ด, ไม่ได้ตรวจ route ที่ใช้งานจริง) |

## 25.2 ข้อดีของ tunnel ขาออก

origin ไม่ต้องมี IP สาธารณะหรือเปิดพอร์ต จึงไม่มีทางเลี่ยง WAF ด้วยการยิง origin ตรง

## 25.3 การเพิ่ม origin (สรุป)

1. เจ้าของสร้าง origin และโดเมนในหน้า Origin Servers
2. ยืนยันโดเมนด้วย CNAME ไป `cdn.waf-it-kku.online` หรือ TXT `_waf-challenge.<domain>` (`dns_verification_worker` ตรวจอัตโนมัติ)
3. ติดตั้ง agent ด้วยคำสั่งจากหน้า Zero Trust Tunnels
4. เมื่อชี้ DNS แล้ว traffic เข้า edge → Main → tunnel → origin

## แหล่งอ้างอิง (Evidence)
- `nginx/templates/conf.d/default.conf.template` (upstreams), `api/tunnels.py`, `api/tunnel.py`, `tunnel/`, `services/dns_service.py`, `systemctl` (frps, cloudwaf-tunnel)
