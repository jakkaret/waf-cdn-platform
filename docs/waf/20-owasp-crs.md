---
title: "บทที่ 20 — OWASP Core Rule Set"
chapter: 20
part: "Part IV — WAF"
status: VERIFIED
---

# บทที่ 20 — OWASP Core Rule Set (CRS)

## 20.1 เวอร์ชันและค่าที่ใช้จริง

| ค่า | Main | Edge | แหล่งที่มา |
|---|---|---|---|
| CRS version | 3.3.10 | 3.3.10 | ModSecurity audit (`OWASP_CRS/3.3.10`) |
| Paranoia level | 1 | 1 (`PARANOIA`, `BLOCKING_PARANOIA`) | `docker-compose.yml`, env ของ edge |
| Inbound anomaly threshold | 10 | 10 | `ANOMALY_INBOUND` |
| Outbound anomaly threshold | 10 | 10 | `ANOMALY_OUTBOUND` |

ค่าเหล่านี้ตั้งผ่าน environment ของ image (`crs-setup.conf` ถูก generate) และหน้า **Settings** ของ dashboard เปลี่ยนค่าได้ผ่าน `SettingsService` (มีผลกับทุก origin เพราะเป็นค่ากลางค่าเดียว)

## 20.2 Anomaly scoring

กฎตรวจจับของ CRS (เช่น 930xxx LFI, 941xxx XSS, 942xxx SQLi) **ไม่บล็อกทันที** แต่บวกคะแนนใน `TX:ANOMALY_SCORE` (critical = 5, error = 4, warning = 3, notice = 2) จากนั้นกฎ **949110** ใน phase 2 บล็อกเมื่อคะแนน ≥ threshold

ตัวอย่างที่ตรวจจริง (2026-09-27): คำขอ `?file=../../../../etc/passwd` ได้คะแนน 30 → 949110 บล็อกด้วย 403

## 20.3 Paranoia level

PL1 เน้น false positive ต่ำ ระดับที่สูงขึ้นจับได้มากขึ้นแต่บล็อกผิดมากขึ้น ระบบมี **threshold proposals** (บทที่ 16) ช่วยเสนอการปรับ threshold จากข้อมูลจริง

## 20.4 False positives

แนวทางที่ระบบรองรับ:
- เพิ่ม/ลด threshold ผ่าน Settings (มีผลทั้งระบบ)
- ไฟล์ `modsecurity-override.conf.template` สำหรับยกเว้นกฎ (มีทั้งที่ Main และ edge)
- กฎ custom แบบ allow/ยกเว้นเฉพาะ path (ต้องเขียน SecRule เอง)

## 20.5 ข้อควรรู้

- rule ของ CRS ที่ตรวจ Log4Shell ไม่พบในชุดที่ใช้ (CRS 3.3.10 ต้องเพิ่มกฎเอง) — UNKNOWN ว่ามีกฎ custom ครอบคลุมหรือไม่
- edge และ Main ตรวจซ้ำกันทั้งสองชั้น คำขอที่ผ่าน edge จะถูกตรวจอีกครั้งที่ Main

## แหล่งอ้างอิง (Evidence)
- `docker-compose.yml` (environment ของ `waf`), env ของ `cdn-edge-node`, ModSecurity error log (949110 score 30), `services/settings_service.py`
