# ML Adaptive Action Policy — Gen3 roadmap 1.3 (mechanism built, OFF by default)

> **หัวใจหลัก:** ระบบตัดสินใจ block/challenge/pass จาก ML score พร้อมใช้งานจริงแล้ว
> แต่ตั้งใจปิดไว้ (`ml_enforcement_enabled: false`) จนกว่าโมเดลจะผ่าน promotion gate
> ของ Phase 2 — เปิดตอนนี้เท่ากับให้โมเดลที่ recall ต่ำกว่าเกณฑ์ตัวเองไป block
> traffic จริงของลูกค้า

---

## 1. ทำไมต้องสร้าง "ปิด" ไว้ก่อน

`WAF_GEN3_ROADMAP.md` เขียนกฎตัวเองไว้ชัดว่า "ห้ามเริ่ม Phase 4 หรือเปิด
enforcement ก่อนมี artifact ที่ผ่าน validation และ rollback plan" — ตอนนี้โมเดล
production ยังเป็นตัวเดิม (62.26% attack recall) และทุก candidate ที่ทดลองปรับ
ในรอบก่อนหน้า (class weight + threshold calibration, 4 config, SHA-256 dedup,
unseen holdout) ได้ดีสุดแค่ ~65% attack recall ที่ benign recall 98.5%+ — ต่ำกว่า
เป้า 85-90% ทั้งหมด (ดู `WAF_GEN3_ROADMAP.md` Phase 2)

งานนี้จึงแบ่งเป็นสองส่วนตามกฎบรรทัดนั้นเป๊ะๆ: **artifact** (mechanism ที่ทำงานได้
จริง ทดสอบแล้ว) + **rollback plan** (flag เดียว ปิดได้ทันที) — โดยไม่แตะ "เปิดจริง"

## 2. สถาปัตยกรรม — ต่อยอดจาก Captcha/OTP Shield's combined gate

| ส่วน | ที่มา |
|---|---|
| Global toggle | `dashboard/backend/services/settings_service.py` — `ml_enforcement_enabled` (default `false`), `ml_block_threshold` (0.95), `ml_challenge_threshold` (0.70). Sync ไป Redis (`waf:ml:policy`) ทุกครั้งที่ save settings + ตอน service เริ่มใหม่ (self-heal) |
| Policy decision | `cdn/control-api/ml_policy.py` (ใหม่) — อ่าน policy จาก Redis, ถ้าปิดอยู่ return `"pass"` ทันทีไม่มี HTTP call เลย (latency เพิ่ม = 0 ตอนปิด) ถ้าเปิด เรียก `dashboard/backend/api/ml.py`'s shadow-decision relay ที่มีอยู่แล้ว (เส้นทางเดียวกับที่ nginx's เดิม (dead) mirror hook เคยเล็ง) ได้ `attack_probability` กลับมาตัดสิน band |
| Gate composition | `cdn/control-api/otp_engine.py`'s `shield_access` — เพิ่มเป็น branch ที่ 3 ต่อจาก captcha/otp ใน auth_request chain เดิม (`/internal-shield-check`) ไม่เพิ่ม nginx location ใหม่เลย เพราะ nginx จำกัดแค่ 1 auth_request ต่อ location (ปัญหาเดิมที่เจอตอนทำ OTP Shield) |
| Block (score >= 0.95) | ตอบ 403 พร้อม header `X-Shield-Type: ml-block` — ตกไปที่ `error_page 403 /403.html;` ที่มีอยู่แล้วทุก server block ไม่ต้องเพิ่มอะไรใหม่ |
| Challenge (0.70-0.95) | ตอบ 401 พร้อม `X-Shield-Type: ml` — `/cdn-cgi/challenge` route ใหม่: `issue_ml_challenge()` (ใน otp_engine.py) render PoW form เดียวกับ CAPTCHA Shield จริง (ใช้ `_new_challenge`/`_challenge_html` ของ captcha_engine.py ตรงๆ) แต่ **ไม่เช็ค** ว่า origin นั้นเปิด captcha เองหรือเปล่า — เพราะ ML enforcement เป็นนโยบาย global ไม่ใช่ per-origin opt-in แบบ captcha/otp |

## 3. ทดสอบแล้วจริง (18/09/2026)

ทดสอบผ่าน loopback บน control-api โดยตรง (ไม่ผ่าน tunnel จริงของลูกค้า เพื่อไม่ให้
กระทบ traffic จริงระหว่างทดสอบ เนื่องจาก ML enforcement เป็น global ไม่มี path
scoping แบบ captcha/otp):

- **Pass band** — path ปกติ (score 0.2479 ตามที่เคยวัดไว้) → `204`
- **Block band** — payload SQLi (score 1.0, threshold 0.95) → `403` + `X-Shield-Type: ml-block`
- **Challenge band** — payload เดิม (score 1.0) แต่ปรับ threshold ชั่วคราวเป็น 1.5
  เพื่อบังคับ band → `401` + `X-Shield-Type: ml` → `GET /cdn-cgi/challenge` คืนหน้า
  PoW จริง (`200`, มีคำว่า "Checking your browser")
- คืนค่า `ml_enforcement_enabled: false` และ threshold กลับ default หลังทดสอบ
- `scripts/smoke_test.sh`: 22/22 invariant ผ่านทั้งก่อนและหลัง (3 T4 gate fail เดิม
  ไม่เกี่ยวข้อง)

บั๊กที่เจอระหว่างทดสอบแล้วแก้: `issue_ml_challenge` เดิม import `_challenge_html`
จาก captcha_engine.py ชนชื่อกับฟังก์ชันของ otp_engine.py เอง (ไฟล์เดียวกันมีทั้ง
`_challenge_html()` แบบ OTP form ไม่รับ argument) ทำให้ Python resolve ผิดตัว
แก้ด้วยการ import แบบ alias (`_captcha_challenge_html`)

## 4. Rollback

`ml_enforcement_enabled: false` ใน system settings คือ rollback เต็มรูป — เขียนค่า
เดียวผ่าน `PUT /api/settings` ไม่ต้อง restart หรือ redeploy container ใดๆ
`ml_policy.py` อ่าน Redis สดทุกครั้ง ไม่ cache ใน process จึงมีผลทันที

## 5. ข้อจำกัด/สิ่งที่ยังไม่ทำ

- **ไม่ได้เปิด enforcement จริง** — รอ Phase 2 ผ่าน promotion gate ก่อน (ดู
  `WAF_GEN3_ROADMAP.md`)
- Score ตัดสินจาก URL/method เท่านั้น (ไม่รวม body) เพราะ shadow-decision relay
  เดิมที่ reuse ไม่ส่ง body ไปด้วย — ตรงกับ scope เดิมของ 1.2/1.1 ไม่ใช่ regression
  ใหม่จากงานนี้
- ทดสอบ 3 band ผ่าน synthetic score/threshold บน loopback เท่านั้น ยังไม่เคยเห็น
  พฤติกรรมจริงบน traffic ปริมาณมากเพราะ enforcement ปิดอยู่ตลอด
