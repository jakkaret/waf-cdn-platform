---
title: "บทที่ 50 — การแก้ปัญหา (Troubleshooting)"
chapter: 50
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 50 — การแก้ปัญหา (Troubleshooting)

แต่ละกรณีมาจากปัญหาที่พบจริงในระบบนี้

### 50.1 API ไม่ตอบ / `/api/health` timeout
- **สาเหตุที่เป็นไปได้:** โค้ด async เรียก boto3 แบบ blocking จน event loop ค้าง
- **ตรวจ:** `py-spy dump --pid $(systemctl show -p MainPID --value waf-dashboard)`
- **ผลที่คาด:** main thread ไม่อยู่ใน `botocore ... ssl read`
- **แก้:** ย้ายการเรียก boto3 ไป `asyncio.to_thread`, restart backend

### 50.2 แก้ Caddyfile/template แล้วไม่มีผล
- **สาเหตุ:** bind mount ไฟล์เดี่ยวยังชี้ inode เก่า
- **ตรวจ:** เทียบ `stat -c %i` บน host กับใน container
- **แก้:** `docker restart <container>`

### 50.3 หน้าเว็บขาดหน้า/ฟีเจอร์ (เช่นหน้า Concepts หาย)
- **สาเหตุ:** `dist/` เป็น build เก่า หรือ source ถูกแทนที่
- **ตรวจ:** `curl -s https://waf-it-kku.online/ | grep -o 'assets/index-[^"]*\.js'` แล้ว grep ข้อความที่ควรมีใน bundle
- **แก้:** `git status` ให้สะอาด แล้ว `npm run build`

### 50.4 Build frontend ล้มด้วย TS1005 จำนวนมาก
- **สาเหตุ:** ไฟล์ source ถูกสคริปต์แก้ผิด (เช่น `Rules.tsx` โตผิดปกติ)
- **ตรวจ:** `wc -l` เทียบกับ `git show HEAD:<file> | wc -l`
- **แก้:** `git checkout HEAD -- <file>` (สำรองก่อน)

### 50.5 Edge ตอบ `418`
- **สาเหตุ:** กฎ DECEIVE ถูก sync ไป edge แต่ edge ไม่มี `@deception_via_main`
- **แก้:** ใช้ template edge ที่มี `error_page 418 = @deception_via_main`

### 50.6 Log ของ tenant ว่าง
- **ตรวจ:** โดเมนยืนยัน DNS แล้วหรือยัง, `access_logs.host` ตรงกับ `domain_name` หรือไม่
- **แก้:** ยืนยันโดเมน; tenant ที่ไม่มีโดเมนจะเห็นข้อมูลว่างโดยตั้งใจ (fail closed)

### 50.7 ไม่ได้รับ Telegram / สรุป AI เป็นข้อความสำรอง
- **ตรวจ:** `journalctl -u waf-dashboard | grep -i -E 'telegram|quota'`
- **สาเหตุ:** ไม่มี bot token, ผู้ใช้ไม่ได้ผูก chat id, Gemini quota หมด

### 50.8 ตั้ง TLS ให้โดเมนใหม่ไม่ได้
- **ตรวจ:** `check-ssl-allowed?domain=<d>` ตอบ 400 หรือไม่
- **แก้:** ยืนยัน DNS ของโดเมนให้สำเร็จก่อน

## แหล่งอ้างอิง (Evidence)
- เหตุการณ์และการแก้ไข 2026-09-24 ถึง 2026-09-27 (commit `b8dd3f0`, `21ac721`, `c033758`)
