---
title: "บทที่ 49 — การย้อนกลับ (Rollback)"
chapter: 49
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 49 — การย้อนกลับ (Rollback)

| สถานการณ์ | วิธีย้อน |
|---|---|
| โค้ด backend | `git checkout <commit ก่อนหน้า> -- <ไฟล์>` หรือ `git revert` แล้ว `systemctl restart waf-dashboard` |
| template nginx | คืนไฟล์จาก backup แบบ in-place (`tar xzf backup.tgz -O <file> > <file>`) → render → `nginx -t` → reload |
| frontend | คืน `dist/` จาก backup (`tar xzf /root/frontend-dist-backup-*.tgz`) |
| edge template | `cat <backup> > <template>` → render → `nginx -t` → reload |
| กฎ WAF ที่ทำให้ nginx -t ไม่ผ่าน | rule manager คืนกฎเดิมให้อัตโนมัติ |
| threshold ที่อนุมัติไป | `POST /api/threshold-proposals/{id}/rollback` |

สคริปต์ deploy ที่ใช้ในเหตุการณ์ 2026-09-27 พิมพ์คำสั่ง rollback ไว้ทุกครั้ง ใช้เป็นแม่แบบได้

## แหล่งอ้างอิง (Evidence)
- backup ที่มีจริง: `/root/deploy-backup-*.tgz`, `/root/frontend-dist-backup-*.tgz`, `/root/pre-integrate-*.tgz`
