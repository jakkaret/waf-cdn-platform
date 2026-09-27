---
title: "บทที่ 39 — การหยุดและเริ่มใหม่"
chapter: 39
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 39 — การหยุดและเริ่มใหม่

| งาน | คำสั่ง | Downtime |
|---|---|---|
| reload nginx หลังแก้ template (Main) | `docker exec waf-nginx sh -c '/docker-entrypoint.d/20-envsubst-on-templates.sh >/dev/null 2>&1; nginx -t' && docker exec waf-nginx nginx -s reload` | ไม่มี |
| reload nginx (edge) | `docker exec cdn-edge-node sh -c '/docker-entrypoint.d/20-envsubst-on-templates.sh >/dev/null 2>&1; nginx -t' && docker exec cdn-edge-node nginx -s reload` | ไม่มี |
| restart backend | `systemctl restart waf-dashboard` | ~5–10 วินาทีของ API |
| restart Caddy (หลังแก้ Caddyfile) | `docker restart caddy-ssl-termination` | ไม่กี่วินาที |
| restart waf-nginx (เมื่อ bind mount ค้าง inode เก่า) | `docker restart waf-nginx` | ~2 วินาที (วัดจริง) |
| หยุดทั้งหมด | `systemctl stop waf-log-analyzer waf-dashboard waf-ml; docker compose down` | ทั้งระบบ |

**ข้อควรระวัง:** ไฟล์ที่ mount เป็นไฟล์เดี่ยว (Caddyfile, template) ถ้าถูกแทนที่ด้วยไฟล์ใหม่ (เช่น `git checkout`, `mv`, `rsync`) container ยังอ่าน inode เดิม ตรวจด้วย
```bash
stat -c %i nginx/templates/conf.d/default.conf.template
docker exec waf-nginx stat -c %i /etc/nginx/templates/conf.d/default.conf.template
```
ถ้าไม่ตรงกันให้ restart container นั้น

## แหล่งอ้างอิง (Evidence)
- คำสั่งทั้งหมดถูกใช้จริงระหว่าง deploy 2026-09-27
