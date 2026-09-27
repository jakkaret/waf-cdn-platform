---
title: "บทที่ 44 — การจัดการ CDN Cache"
chapter: 44
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 44 — การจัดการ CDN Cache

| งาน | วิธี |
|---|---|
| ดูว่า HIT หรือไม่ | `curl -sI https://<domain>/<path> \| grep -i x-cache-status` |
| ดู region ที่ตอบ | header `X-Edge-Region` |
| บังคับไม่ใช้ cache สำหรับการทดสอบ | ส่ง `Cache-Control: no-cache` หรือเพิ่ม query string (edge จะ skip cache) |
| ขนาด cache | zone `edge_cache` 80 MB ของ key, ข้อมูลใน volume `edge_node_edge_cache` |

## แหล่งอ้างอิง (Evidence)
- edge `default.conf.template`, `nginx.conf.template`
