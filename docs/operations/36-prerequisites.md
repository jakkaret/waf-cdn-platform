---
title: "บทที่ 36 — สิ่งที่ต้องมีก่อน (Prerequisites)"
chapter: 36
part: "Part VIII — Operations"
status: VERIFIED
---

# บทที่ 36 — สิ่งที่ต้องมีก่อน (Prerequisites)

| รายการ | Main | Edge | หมายเหตุ |
|---|---|---|---|
| OS | Ubuntu 26.04 (ที่ใช้จริง) | Ubuntu 24.04 | – |
| Docker + Compose plugin | 29.1.3 / 2.40.3 | ต้องมี | – |
| Python venv | `dashboard/backend/.venv` (Python 3.14) ใช้ร่วมกับ ML และ tunnel | – | ติดตั้งจาก `requirements.txt`; **ไม่มี pytest ใน venv production** |
| Node.js + npm | สำหรับ build frontend (`dashboard/frontend/node_modules`) | – | – |
| frps | `/usr/local/bin/frps` 0.61.1, config `/etc/frp/frps.toml` | – | – |
| บัญชีภายนอก | AWS (DynamoDB), Telegram bot, Gemini API, Google OAuth, DNS provider | – | ค่าลับอยู่ใน `.env` |
| พอร์ต | ดูบทที่ 07 | 80/443 | – |

## แหล่งอ้างอิง (Evidence)
- runtime snapshot, `systemctl show`, `requirements.txt`
