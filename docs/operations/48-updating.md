---
title: "บทที่ 48 — การอัปเดตระบบ"
chapter: 48
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 48 — การอัปเดตระบบ

## 48.1 หลักการ (บทเรียนจากเหตุการณ์ 2026-09-27)

- **deploy ด้วย git เท่านั้น** อย่าคัดลอกโฟลเดอร์จากเครื่องนักพัฒนาทับ server (เคยทำให้ไฟล์ 96 ไฟล์ถอยกลับเป็นรุ่นเก่า)
- ตรวจว่าไม่มีคนอื่นแก้ไฟล์อยู่ (`git status`, `find -mmin -15`)
- สำรองไฟล์ที่จะเปลี่ยนก่อน และเขียนไฟล์ที่ถูก mount แบบ in-place

## 48.2 ขั้นตอน

```bash
cd /root/waf_project
git status --short                     # ต้องไม่มีการแก้ที่ไม่รู้ที่มา
git fetch && git merge --ff-only origin/Backend
# backend
systemctl restart waf-dashboard && curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/health
# nginx template (render + test + reload)
docker exec waf-nginx sh -c '/docker-entrypoint.d/20-envsubst-on-templates.sh >/dev/null 2>&1; nginx -t' && docker exec waf-nginx nginx -s reload
# ถ้า git แทนที่ไฟล์ที่ mount ไว้ ให้ตรวจ inode (บทที่ 39) แล้ว restart container
# frontend
cd dashboard/frontend && npm run build
```

Edge: แก้ template ที่ `/root/edge_node` หรือ `/opt/edge_node` แล้ว render + `nginx -t` + reload แบบเดียวกัน

## แหล่งอ้างอิง (Evidence)
- ขั้นตอนนี้ใช้จริง 2026-09-27 (fast-forward เป็น `c033758`)
