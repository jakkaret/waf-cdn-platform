---
title: "บทที่ 43 — การจัดการกฎ WAF"
chapter: 43
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 43 — การจัดการกฎ WAF

## 43.1 ทางที่แนะนำ: ผ่าน dashboard

หน้า WAF Rules (admin) → สร้าง/แก้/ลบ ระบบเขียน `modsecurity/custom-rules/custom-<id>.conf`, รัน `nginx -t`, reload waf-nginx และ edge จะได้กฎภายใน ~5 วินาทีผ่าน bundle

## 43.2 ตรวจว่า edge ได้กฎแล้ว

```bash
docker logs cdn-edge-node 2>&1 | grep rulesync | tail -3      # "[rulesync] updated + reloaded"
docker exec cdn-edge-node ls /opt/custom-rules
```

## 43.3 ทดสอบกฎ

- ใช้ปุ่ม **Blast radius** ก่อนเปิดใช้เพื่อประเมินผลกับ traffic จริง
- ทดสอบกับโดเมนแล็บ (`dvwa.waf-it-kku.online`) ด้วยคำขอเดียว ไม่ยิงซ้ำจำนวนมาก

## 43.4 ค่าระดับระบบ

paranoia / anomaly threshold ปรับที่หน้า Settings หรือผ่าน Tuning Proposals (มีผลทุก origin)

## แหล่งอ้างอิง (Evidence)
- `services/rule_manager.py`, `edge/entrypoint.d/99-rulesync.sh`
