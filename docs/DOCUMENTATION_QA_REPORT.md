---
title: "Documentation QA Report"
status: PARTIAL
---

# Documentation QA Report

วันที่ตรวจ: 2026-09-27 ถึง 2026-09-28 · ระบบอ้างอิง: commit `c033758` (branch `Backend`)

## 1. สิ่งที่ตรวจ (Inspection)

| ประเภท | รายการ |
|---|---|
| Runtime (อ่านอย่างเดียว) | Main, edge-th, edge-asia: `hostnamectl`, `nproc`, `free`, `df`, Hetzner metadata, `docker ps/inspect`, `systemctl show`, `ss -ltnpu`, `ufw status`, `iptables -S INPUT`, cron, `curl` health endpoints, ML `/health`, ClickHouse `system.columns` / นับแถว, Caddy admin config |
| ภายนอก | `nc -z` จากอินเทอร์เน็ตไปทุกพอร์ต, `dig NS/A`, `openssl s_client` (issuer/วันหมดอายุ) |
| Repository | `main.py` และ router ทั้ง 24 ไฟล์ (AST), `services/*` ที่อ้างในบท, compose ของ Main/edge, nginx/Caddy/ModSecurity templates, `cdn/control-api`, `cdn/geodns`, `ml/*`, `scripts/*`, frontend `App.tsx`/`Sidebar.tsx`/pages/api/store, `.github/workflows/ci.yml`, `ml/models/eval_results.json` |

## 2. ผลการ build

| ผลลัพธ์ | คำสั่ง | ผล |
|---|---|---|
| Mermaid 20 ภาพ | `npm run diagrams` | **ผ่าน 20/20** (รอบแรก ER diagram ใช้ `SK` ที่ไม่รองรับ → แก้เป็น PK + comment) |
| เว็บ VitePress | `npm run build` | **ผ่าน** (ตรวจ dead link ในตัว ไม่พบลิงก์เสีย) |
| DOCX | `npm run docx` | **สร้างได้**: 65 ไฟล์ต้นฉบับ, 108 ตาราง, 94 sections (หน้าแนวนอน 9 หน้าสำหรับ diagram กว้าง), `unzip -t` ผ่าน, `document.xml` well-formed, มี TOC field (`TOC \h \o "1-2"`) + `updateFields`, macOS `textutil` อ่านข้อความไทยได้ |
| PDF | `npm run pdf` | **สร้างได้**: 115 หน้า A4, มีปก ประวัติแก้ไข สารบัญ (ลิงก์) header/footer เลขหน้า; ตรวจภาพหน้า 1, 3, 5, 14, 20, 33, 60, 100 |

## 3. QA ของเว็บ (Playwright + Chrome, ตรวจจริง)

| ตรวจ | ผล |
|---|---|
| หน้าแรกโหลด, ชื่อเว็บ | ผ่าน |
| Sidebar กลุ่ม Part I–IX + Reference | 11 กลุ่ม |
| Search (local) ค้น "deception" | 32 ผลลัพธ์ |
| Mermaid render ในหน้า (บทที่ 17, 04) | 1 และ 2 ภาพ |
| Outline "ในหน้านี้" | 8 ลิงก์ (บทที่ 17) |
| ปุ่ม copy ของ code block | มี |
| มือถือ 390px: ไม่มี horizontal overflow ของหน้า | ผ่าน (ตารางกว้างเลื่อนในตัวเอง) |
| JavaScript error | ไม่มีหลังแก้; มี 1 รายการ 404 จาก resource ที่ไม่ได้ระบุ (หน้าหลักที่ตรวจไม่พบ 404) |

ปัญหาที่พบและแก้ระหว่าง QA:
1. `{{.Names}}` ใน inline code ถูก Vue ตีความ → ใส่ `v-pre` ให้ inline code ผ่าน markdown-it (ลองเปลี่ยน delimiter ของ Vue ก่อน แต่ทำให้ theme แสดง `{{ site.title }}` ดิบ จึงยกเลิก)
2. `|` ใน inline code ภายในตาราง และ `<placeholder>` นอก code → สคริปต์ `lint-md.mjs`
3. Vue resolve ไม่ได้เพราะหน้าอยู่นอก package → symlink `docs/node_modules` (ลอง alias ก่อน แต่เกิด runtime error `Cannot access 'Ue' before initialization`)
4. สคริปต์ lint รุ่นแรกแทนที่ผิดกลุ่ม regex ทำให้ `_evidence/TEAM_BRIEF.md` เสีย 1 บรรทัด → แก้คืนและแก้ regex แล้ว

## 4. Security QA

- สแกน `.md/.mmd/.html` ทั้งหมดด้วย pattern ของ GitHub token, AWS key, Google API key, Telegram bot token, private key, JWT, รหัสผ่าน, อีเมล → **ไม่พบในเอกสารชุดใหม่** (พบเพียงข้อความ `ghp_...` ที่ตัดแล้วในเอกสารเก่า `PROJECT_IMPLEMENTATION_REPORT.md` ซึ่งไม่ได้อยู่ในเว็บ)
- PDF: ไม่พบ `ghp_`, `PRIVATE KEY`, `eyJhbGci`
- ชื่อตัวแปรลับ (เช่น `DECEPTION_INTERNAL_KEY`) ปรากฏเฉพาะชื่อ ไม่มีค่า
- **ข้อควรระวัง:** เอกสารอธิบายจุดอ่อนที่ยังไม่แก้ (พอร์ต 8000, การแยก tenant แบบ substring ฯลฯ) และ IP ของโครงสร้างพื้นฐาน repository บน GitHub เป็น public จึง **ไม่ควร push เอกสารชุดนี้ขึ้น public** จนกว่าจะแก้จุดอ่อนหรือเปลี่ยน repo เป็น private

## 5. Repository / Runtime accuracy

- จำนวนเครื่อง/container/service, พอร์ต และ request path ตรวจกับ runtime ทั้งหมด
- API reference สร้างจากโค้ดโดยตรง (123 endpoints) ไม่ได้เขียนด้วยมือ
- diagram ทั้ง 20 ภาพใช้เฉพาะองค์ประกอบที่พบจริง; ภาพ 02 และ 14 ถูกแก้หลังพบว่า analyzer ไม่ได้บันทึก pending rule

## 6. ความไม่สอดคล้องที่พบ (Discrepancies)

| แหล่ง | บอกว่า | ของจริง |
|---|---|---|
| `CLAUDE.md` | อนุมัติกฎ ML ที่ `POST /api/ml_rules/{rule_id}/approve` | path จริง `POST /api/ml-rules/{rule_id}/approve` |
| `CLAUDE.md` | branch ในเครื่องชื่อ `backend` | เครื่องนักพัฒนาใช้ `Backend` (ตรงกับ remote) |
| ความคิดเห็นในโค้ด `ml/async_log_analyzer.py` | "Pending Approval" | analyzer ไม่ได้บันทึกกฎรออนุมัติ |
| `api/cdn.py` / Settings `auto_purge_edge_cache` | มี purge | ไม่มี endpoint purge ที่ edge |
| เอกสารเก่าใน `docs/` (ARCHITECTURE.md ฯลฯ, ตรวจล่าสุด 2026-08-26) | – | อาจล้าสมัย ให้ยึดชุดนี้ |
| `.github/workflows/ci.yml` | trigger `backend` | branch ที่ใช้คือ `Backend` |

## 7. สิ่งที่ยังไม่รู้ (Unknown) และต้องตรวจด้วยมือ

1. เปิด DOCX ใน Microsoft Word → อัปเดต field ให้สารบัญมีเลขหน้า และตรวจหน้าแนวนอน 9 หน้า (ไม่ได้เปิดใน Word ระหว่าง QA)
2. edge-asia รับ traffic จริงหรือไม่ (ไม่มีเส้นทาง DNS สาธารณะที่ตรวจพบ), Azure NSG
3. OTP ทางอีเมล (SMTP ไม่ได้ตั้ง), DynamoDB PITR/backup
4. key schema ของตาราง DynamoDB ที่ไม่มีสคริปต์สร้าง (`waf_rules`, `waf_threat_patterns`, …)
5. พฤติกรรม `error_page 401` สองรายการใน server block ของ Main (challenge vs 429)
6. Lab node `10.198.200.75` ไม่ได้ตรวจ
7. ชุด `scripts/smoke_test.sh`, `tunnel/test_tunnel.sh`, `npm run test:e2e` ไม่ได้รันในรอบนี้
8. ให้ทีมอ่านทวนเนื้อหาเชิงธุรกิจ (บทที่ 1–2) ว่าตรงกับเจตนาของโครงการ

## 8. สรุป

ไม่ได้อ้างว่า "ทุกอย่างผ่าน": build ทั้ง 4 ชนิดผ่านและตรวจแล้ว, test ที่อ้างในเอกสารรันจริงทั้งหมด, รายการในข้อ 7 ยังต้องตรวจเพิ่ม
