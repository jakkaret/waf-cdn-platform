# Handoff: งาน waf-cdn-platform (ต่อบน laptop)

อัปเดต 2026-10-11 · ฉบับใน repo (public) ตัดรายละเอียดช่องโหว่ของ VPS ออก ฉบับเต็มอยู่ในเครื่องของผู้ดูแล ห้ามเพิ่มรายละเอียดนั้นกลับเข้ามาในไฟล์นี้

---

## 0. กฎสำหรับ Claude ใน session ใหม่ (ให้อ่านส่วนนี้ก่อน)

- repo หลักคือ **waf-cdn-platform** (`github.com/jakkaret/waf-cdn-platform`) ส่วน `seminar/waf_project` ใช้ดูแค่ประวัติ ML
- **ห้าม push** ถ้าผู้ใช้ไม่ได้สั่งตรงๆ ทำงานเสร็จแล้วให้รายงานผลแล้วรอคำสั่ง ห้าม commit เองด้วยถ้าไม่ได้สั่ง
- **VPS 178.104.53.123 อ่านอย่างเดียว:** ห้ามแก้ ห้าม restart ห้ามยิง request ทดสอบไปที่เครื่องนั้น ใช้ได้เฉพาะคำสั่งอ่านผ่าน SSH ส่วนการเปลี่ยนแปลงบน production ผู้ใช้เป็นคนทำเอง
- ห้ามเอาไฟล์ test harness หรือ scenario เข้า repo
- ตอบเป็นภาษาไทย สั้นและตรงประเด็น (caveman mode) แต่คำเตือนเรื่องความปลอดภัยให้เขียนเป็นประโยคปกติ

---

## 1. สถานะตอนนี้

| | |
|---|---|
| branch | `feat/connect-site-flow` (push แล้ว, ยังไม่เปิด PR, ยังไม่ merge) |
| commit | `bf268a8` แตกมาจาก `93a78a0` (`origin/main`) |
| VPS รันอยู่ | `d5940c7` **เก่ากว่า main** ถ้า deploy branch นี้จะได้ commit ของเพื่อนระหว่าง `d5940c7..93a78a0` ไปด้วย |
| เปิด PR | https://github.com/jakkaret/waf-cdn-platform/pull/new/feat/connect-site-flow |
| คู่มือผู้ใช้ (ส่งเพื่อน) | https://claude.ai/artifact/XY2CytYwwLa7Gfw9uz6Up9 (แชร์เป็น anyone with link แล้ว) |

ผลเทสล่าสุด:
- backend 1071 passed
- vitest 62
- `tsc` และ build ผ่าน
- browser scenario 35/35, ไม่มี console error
- ruff ชุดที่ CI บล็อกผ่าน, bandit HIGH ไม่มี
- code-review 2 รอบ (รวม 20 ข้อ) แก้ครบ, security-review ไม่มีข้อที่มั่นใจ 8 ขึ้นไป

**ยังไม่เคยวิ่งกับ infra จริง:** `nginx -t` และ reload ของจริง, `docker exec` เข้า waf-nginx, DNS และ probe จริง, Caddy ออก cert ทุกตัวในเทสเป็นของปลอม

---

## 2. Setup บน laptop

```bash
git clone https://github.com/jakkaret/waf-cdn-platform.git waf-cdn
cd waf-cdn && git checkout feat/connect-site-flow

# backend (Python 3.12, คำสั่งเดียวกับ CI)
python3 -m venv ~/.venvs/wafcdn
~/.venvs/wafcdn/bin/pip install -r dashboard/backend/requirements.txt pytest httpx pytest-asyncio pytest-cov fakeredis ruff
cd dashboard/backend
~/.venvs/wafcdn/bin/python -m pytest -q                                    # ต้องได้ 1071 passed
~/.venvs/wafcdn/bin/ruff check . --select E9,F63,F7,F82,F811,B018          # ชุดที่ CI บล็อก

# frontend
cd ../frontend && npm ci
npx vitest run          # 62
npx tsc --noEmit -p .
npm run build
```

หมายเหตุสำหรับ WSL:
- รัน `npx` ภายใน WSL โดย source nvm ก่อน (`source ~/.nvm/nvm.sh`) ถ้ารัน `npx` ของ Windows บน path UNC จะพัง
- Git Bash บน path `\\wsl.localhost\...` จะฟ้อง dubious ownership ให้รัน git ใน WSL แทน
- ถ้า WSL ไม่มี credential GitHub ตอน push (เฉพาะเมื่อสั่ง) ให้ใช้ git ของ Windows แทน:
  `git -c "safe.directory=*" -C "\\wsl.localhost\Ubuntu\home\<user>\waf-cdn" push`
- ถ้ารันเทสแล้ว tracked `__pycache__/*.pyc` ถูกแก้ ให้คืนด้วย `git checkout -- "*.pyc"`

Browser test: harness (`uitest/harness.py`, `scenario.py`) อยู่ใน scratchpad ของเครื่องเดิม **ไม่ได้อยู่ใน repo**
- หลักการของ harness: ใช้ router จริงกับ fake จาก `tests/conftest.py` เสิร์ฟไฟล์ `frontend/dist` ที่ port 8765 และมี endpoint `/__test/dns|agent|cert/{domain}` ไว้จำลองโลกภายนอก
- รัน Playwright จาก venv ฝั่ง Windows เพราะ Chromium ใน WSL ขาด `libnspr4`

---

## 3. ทำอะไรไปแล้วใน branch นี้

### Flow เชื่อมเว็บใหม่
- ผู้ใช้กรอกโดเมน (วาง URL ได้ ระบบตัดเหลือ hostname) → `POST /api/onboarding/inspect` อ่าน DNS ปัจจุบัน, ตรวจ Cloudflare และ probe ไปที่ 443/80 → แนะนำ **direct** (ไม่ต้องติดตั้งอะไร) หรือ **agent** (FRP)
- `POST /connect` สร้าง origin และโดเมน ถ้าล้มจะ rollback
- ตั้ง DNS แค่ **CNAME 1 record** ไปที่ `cdn.waf-it-kku.online` ส่วน TXT ซ่อนไว้ใช้กับโดเมนหลักที่ไม่มี sub
- การ์ด `DomainStatusCard` เรียก `GET /progress/{origin_id}` ทุก 10 วินาที เช็ค DNS / การเชื่อมต่อ / HTTPS แล้วขึ้น LIVE เมื่อผ่านจริงครบ 3 ข้อ
- ลบ `AddOriginModal`, `DomainSetupWizard`, `DnsInstructions` และแท็บ SSL (`?tab=ssl` ยังพาไปแท็บ domains)

### Backend
- `nginx_site_service.reconcile_site_routes()` ทำงานตอน start, ทุก 120 วินาที และหลังโดเมนเปลี่ยน
  - แตะเฉพาะไฟล์ที่มี `# managed-by: site-reconcile`
  - รัน `nginx -t` baseline ก่อนเขียน แล้วเขียนทีละไฟล์พร้อมเทสต่อไฟล์
  - restore เมื่อล้ม และ retry restore ที่ค้าง
  - reload ครั้งเดียวต่อรอบ
- กัน SSRF: direct รับเฉพาะ public IP literal ไม่รับ private IP หรือ IP ของแพลตฟอร์มเอง (`WAF_SELF_IPS`, `WAF_EDGE_IPS`, ค่า default คือ 3 IP ของเรา)
- HTTPS origin ที่ระบุเป็น IP จะได้ Host และ SNI เป็นโดเมนของผู้เข้าชม
- verify โดเมน 3 ทางใช้ `after_domain_verified` ทางเดียว
- DNS worker รันใน thread มี backoff 60 วินาทีถึง 30 นาที และข้ามชื่อที่ไม่ถูกต้อง
- agent ต่อแล้วใช้ origin เดิม (adopt) ไม่สร้างซ้ำ
- ClickHouse client ตั้ง `autogenerate_session_id=False`
- bug ที่เพื่อนแจ้ง ("wizard ขึ้นเครื่องหมายถูกก่อนผูกโดเมน") แก้แล้ว: เปลี่ยนจากคำนวณรวมทั้งบัญชีเป็นคำนวณต่อ origin
- origin เดิม (FRP/tunnel ที่ไม่มี `connection_mode`) ไม่ถูกแตะ เช่น httpbin และ juiceshop ของ Rit Su

env ที่เกี่ยวข้อง:
- `WAF_CNAME_TARGET=cdn.waf-it-kku.online` ตั้งไว้แล้วบน VPS
- `WAF_ORIGIN_EGRESS_IPS=178.104.53.123` ควรตั้ง ใช้แสดงในคำแนะนำเรื่อง firewall บนการ์ด

---

## 4. งานถัดไป (เรียงตามที่แนะนำ)

### 4.1 Staging test บน WSL (ไม่แตะ VPS)
ยก waf-nginx และ ModSecurity image เดียวกับ production มาใช้กับ origin จำลอง (httpbin container) แล้วรัน reconcile จริงกับ `nginx -t` และ reload จริง ยิง request ผ่านแล้วดูว่า XSS ได้ 403 และหน้าปกติได้ 200 ข้อนี้จะปิดความเสี่ยงที่ใหญ่ที่สุดก่อน deploy

### 4.2 Deploy (ผู้ใช้เป็นคนทำ)
**ก่อน deploy:**
- จด commit ปัจจุบันไว้ (`d5940c7`)
- backup ข้อมูล (backup ล่าสุดคือ 2026-09-13)
- deploy ตอนที่มีคนใช้น้อย

**หลัง deploy เช็ค:**
- log ของ reconcile ไม่มี error และไม่ reload ทุก 2 นาทีโดยไม่จำเป็น
- httpbin และ juiceshop ยังเข้าได้
- ปุ่ม Verify DNS ของโดเมนเดิมยังใช้ได้
- ทดสอบ direct mode ด้วยโดเมนทดสอบ 1 ตัว

**Rollback (ประมาณ 5 นาที):** กลับไปใช้ `d5940c7` แล้ว rebuild และ restart backend กับ frontend จากนั้นลบไฟล์ route ที่ระบบสร้าง:
```bash
docker exec waf-nginx sh -c 'grep -l "managed-by: site-reconcile" /etc/nginx/conf.d/site-*.conf | xargs -r rm -f && nginx -t && nginx -s reload'
```
ฐานข้อมูลไม่ต้อง migrate เพราะ field ใหม่ (`connection_mode`, `origin_scheme`) โค้ดเก่าจะไม่สนใจ

### 4.3 ความปลอดภัยบน VPS (ผู้ใช้ทำเอง เร่งด่วน)
มีรายการที่ต้องแก้บน VPS 7 ข้อ รายละเอียด**ไม่ได้ใส่ไว้ในไฟล์นี้**เพราะ repo เป็น public ให้ดูจากฉบับเต็มที่โอนผ่านช่องทางส่วนตัว และห้าม commit รายละเอียดนี้ลง repo

### 4.4 ClickHouse และการเก็บข้อมูลจราจรตาม พ.ร.บ.คอมพิวเตอร์ (รอผู้ใช้ยืนยัน)
- กฎหมาย: มาตรา 26 ให้เก็บข้อมูลจราจรอย่างน้อย **90 วัน** และขยายได้ถึง 2 ปีเมื่อมีคำสั่ง ประกาศกระทรวงฯ ปี 2564 กำหนดเรื่องความครบถ้วนของข้อมูลและการ sync เวลา และต้องคำนึงถึง PDPA ด้วย
- ตอนนี้:
  - `access_logs` TTL 30 วัน (`ACCESS_LOGS_RETENTION_DAYS` ไม่ได้ตั้ง)
  - `shield_events` 90 วัน
  - `security_audit_logs` ไม่มี TTL
  - logrotate ของ nginx และ modsecurity ตั้ง `rotate 7`
  - NTP sync แล้ว
- แผนที่เสนอ (ในโค้ด):
  - default 120 วันสำหรับ `access_logs` และ `shield_events`
  - ไฟล์ ClickHouse `config.d/system-logs.xml` ปิด `trace_log` และตั้ง TTL ให้ system log
  - เทมเพลต logrotate `rotate 120`
- CPU 100%: `trace_log` 2.1 GB และ `text_log` 825 MB, merge ล้มเพราะชน memory limit และ insert หาย

### 4.5 งานในโค้ดที่ยังค้าง (รอคำสั่ง)
- โดเมนที่ไม่มี origin แล้ว (orphan) ยังอยู่ใน allow-list ของ TLS ตัวอย่างที่เจอ: `mytest.test`, `mywebsite.test`, `waf_project_web.com` ×2
- `libinjection` ไม่อยู่ใน `requirements.txt` ของ backend ทำให้ Gen3 ไม่ทำงาน
- lock กลางสำหรับทุกตัวที่เขียนหรือ reload nginx
- viewer เห็นปุ่ม Archive Origin
- Gemini โดน 429 ต้องมี backoff
- ปุ่ม "ตั้งเป็นแบบต่อตรง" สำหรับ origin เก่า (`www.originweb.site` ของ jakkaret ยัง 404 อยู่)
- ตั้ง DNS อัตโนมัติผ่าน Cloudflare API
- Gen3 auto-block ยังไม่พร้อม (TPR@FPR0.1% = 16%)

---

## 5. ข้อมูลอ้างอิง

| | |
|---|---|
| Main VPS | 178.104.53.123 (`/root/waf_project`) |
| edge-th | 45.154.26.91 |
| edge-asia | 57.158.25.236 |
| Dashboard | https://waf-it-kku.online |
| CNAME target | `cdn.waf-it-kku.online` |
| เส้นทาง traffic | CNAME → edge (Caddy on-demand TLS, ask = `/api/domains/check-ssl-allowed`) → Main waf-nginx :8080 → origin |
| FRP | frps :7000, `frp_tunnel_router` |

ถ้าต้องการให้ Claude บน laptop จำกฎในข้อ 0 ข้ามแต่ละ session ให้คัดลอกโฟลเดอร์ memory จากเครื่องเดิม
(`C:\Users\chira\.claude\projects\--wsl-localhost-Ubuntu-home-chirachot-seminar-waf-project\memory\`)
ไปไว้ที่ path เดียวกันบน laptop หรือบอก session ใหม่ให้อ่านไฟล์นี้ตอนเริ่ม
