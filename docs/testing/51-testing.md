---
title: "บทที่ 51 — การทดสอบ (Testing)"
chapter: 51
part: "Part IX — Testing"
status: PARTIAL
---

# บทที่ 51 — การทดสอบ (Testing)

> ผลในบทนี้มาจากการรันจริงเท่านั้น รายการที่ไม่ได้รันระบุว่า "ไม่ได้รันในรอบนี้"

## 51.1 สรุปผล

| ชุดทดสอบ | คำสั่ง | ผลจริง | วันที่ | สถานะ |
|---|---|---|---|---|
| Backend unit + integration (pytest, 68 ไฟล์) | `python -m pytest tests -q` ในสำเนาแยก | **714 passed, 1 xfailed** | 2026-09-27 | VERIFIED |
| Frontend unit (vitest, 4 ไฟล์) | `npx vitest run` | **33 passed** | 2026-09-28 | VERIFIED |
| Frontend type check + build | `npx tsc -b && npx vite build` | ผ่าน | 2026-09-27 | VERIFIED |
| Smoke test หลัง deploy (WAF/deception/regression) | ชุด `apply.sh` | **11/11 PASS** | 2026-09-27 | VERIFIED |
| ตรวจแบบ adversarial (read-only) | agent tester | 6 ผ่าน, 2 พบปัญหา (template SQLi, fingerprint) | 2026-09-27 | VERIFIED |
| Playwright e2e ใน repo (`tests/e2e.spec.ts`) | `npm run test:e2e` | ไม่ได้รันในรอบนี้ | – | UNKNOWN |
| Regression bracket ของทีม | `scripts/smoke_test.sh` (22 invariants + 6 security gates) | ไม่ได้รันในรอบนี้ | – | UNKNOWN |
| Tunnel tests | `tunnel/test_tunnel.sh` (28 tests) | ไม่ได้รันในรอบนี้ | – | UNKNOWN |
| Accessibility (axe) | ชุด Playwright + axe (ยังไม่อยู่ใน repo) | พบ contrast/label หลายจุด แก้ไปบางส่วน | 2026-09-25 | PARTIAL |

## 51.2 Backend (pytest)

- ที่อยู่: `dashboard/backend/tests/` (68 ไฟล์)
- `conftest.py` แทนที่ DynamoDB ด้วย `InMemoryTable` และ (ตั้งแต่ 2026-09-27) ปิดการเขียน ClickHouse/DynamoDB ของ deception service
- **ข้อควรระวัง:** venv บนเครื่อง production ไม่มี pytest และการรัน test บนเครื่อง production อาจแตะบริการจริง ให้รันในสำเนาแยก:
  ```bash
  mkdir -p /tmp/wt && cd /root/waf_project && git archive HEAD | tar -x -C /tmp/wt
  python3 -m venv /tmp/wt/venv && /tmp/wt/venv/bin/pip install -r /tmp/wt/dashboard/backend/requirements.txt pytest pytest-asyncio
  cd /tmp/wt/dashboard/backend && /tmp/wt/venv/bin/python -m pytest tests -q
  ```
- ตรวจว่าไม่มีการเขียนลง DB จริงระหว่างรัน: นับแถว `access_logs WHERE attack_type LIKE 'Deception:%'` ก่อน/หลัง (ใช้จริง ได้ค่าเท่ากัน)

## 51.3 Frontend

- unit: `src/lib/*.test.ts` (captchaForm, systemStatus, tunnelCommands, tunnelStatus) — `npm run test:unit`
- e2e: `playwright.config.ts`, `tests/e2e.spec.ts` — `npm run test:e2e`

## 51.4 WAF tests (ทำกับโดเมนแล็บ ครั้งละคำขอ)

| Test | คำขอ | ที่คาด | ผลจริง |
|---|---|---|---|
| LFI | `GET /?file=../../../../etc/passwd` (Host dvwa) | 403 | 403 |
| SQLi | `GET /?search=1' OR '1'='1` | 403 | 403 |
| คำขอปกติ | `GET /?id=5` | ไม่ถูกบล็อก | 302 (หน้า login ของ DVWA) |
| Deception (Main) | `GET /x?deceive_me_lfi` | 200 body สังเคราะห์, no-store | ผ่าน |
| Deception (ผ่าน edge) | เดียวกันผ่าน https | 200, ไม่มี `public` ใน Cache-Control | ผ่าน |
| Endpoint ภายในไม่มี key | `GET /api/deception/respond` | 403 | 403 |

## 51.5 CDN tests

| Test | ผล |
|---|---|
| Cache แยกตาม host (`robots.txt` ของ dvwa/juice) | เนื้อหาไม่ปนกัน, คำขอที่สองเป็น HIT |
| Deception ไม่ถูก cache | ไม่มี `X-Cache-Status`, `x-request-id` ต่างกันทุกครั้ง |
| Purge | ไม่ได้ทดสอบ (ทราบว่าไม่ถึง edge — บทที่ 24) |

## 51.6 End-to-end

เส้นทางจริง Client → edge-th → Main → origin ตรวจด้วย smoke test (`/api/status/public` 200, dashboard 200, deception ผ่าน edge 200, LFI จริง 403, Caddy ask ปฏิเสธโดเมนแปลกปลอม 400)

## 51.7 CI

`.github/workflows/ci.yml` รัน ruff, `tsc --noEmit` และ build แต่ตั้ง trigger ไว้ที่ branch ตัวพิมพ์เล็ก (`backend`) ขณะที่ใช้ `Backend` → อาจไม่ทำงานกับ branch หลัก (PARTIAL) และไม่ได้รัน pytest

## แหล่งอ้างอิง (Evidence)
- ผลรันจริงตามวันที่ในตาราง, `dashboard/backend/tests/conftest.py`, `dashboard/frontend/package.json`, `.github/workflows/ci.yml`
