---
title: "บทที่ 51 — ย้ายระบบจากคลาวด์ลง Docker ในเครื่อง"
chapter: 51
part: "Part VIII — Operations"
status: PLAN
---

# บทที่ 51 — ย้ายระบบจากคลาวด์ลง Docker ในเครื่อง

แผนนี้ย้ายทั้งระบบ (Main, edge-th, edge-asia และ lab origin) จากคลาวด์มาไว้บนเครื่องเดียวด้วย Docker
เพื่อเลิกจ่ายค่าคลาวด์ และให้ clone repo ไปทำต่อบนเครื่องอื่นได้ทันที

สำรวจเครื่องจริงแบบอ่านอย่างเดียวเมื่อ 4 พฤศจิกายน 2569 คำสั่งทุกบรรทัดในบทนี้ **ยังไม่ได้รัน**
ให้รันตามลำดับระยะ และผ่านด่านของแต่ละระยะก่อนไปต่อ

**กฎข้อเดียวที่สำคัญที่สุด:** การปิดคลาวด์ย้อนกลับไม่ได้ จึงเป็นขั้นสุดท้าย
ทำหลังจากขึ้นระบบบนเครื่องใหม่ด้วยข้อมูลที่เก็บออกมาและผ่านด่านตรวจแล้วเท่านั้น
และเจ้าของบัญชีเป็นคนกดลบเอง

## 51.1 ภาพรวม

| ระยะ | ทำอะไร | ด่านที่ต้องผ่านก่อนไปต่อ |
|---|---|---|
| 0 | ตัดสินใจ 4 เรื่อง (สอบ, โดเมน, ผู้ใช้จริง, ความลับ) | ตอบครบทั้ง 4 ข้อ |
| 1 | เก็บของทุกอย่างที่ไม่อยู่ใน git และข้อมูลทั้งหมดออกจากคลาวด์ | ไฟล์ครบตาม 51.3 + checksum + เข้ารหัสแล้วเก็บ 2 ที่ |
| 2 | ปิดช่องว่างใน git | edge config, log forwarder และกฎที่ใช้จริงอยู่ใน repo |
| 3 | ขึ้นระบบบนเครื่องใหม่ นำเข้าข้อมูล และตรวจ | `sim/test.sh` ผ่าน 19/19 และด่านเพิ่มใน 51.6 |
| 4 | เจ้าของบัญชีปิดคลาวด์ตามลำดับ | ลบครบทุกทรัพยากรที่คิดเงิน |
| 5 | ต่อยอด: ย้ายบริการ systemd เป็น image | ทำหลังจากนี้ได้ ไม่เร่ง |

## 51.2 ระยะ 0 — ตัดสินใจก่อนเริ่ม

1. **ยังมีสอบหรือนำเสนอที่อ้างระบบจริงไหม**
   เล่มรายงานและคู่มืออ้าง `waf-it-kku.online` และใช้ภาพหน้าจอจากระบบจริง
   ถ้ายังมีสอบ ให้เก็บคลาวด์ไว้ถึงวันนั้น และใช้ระบบบนเครื่องใหม่ที่ผ่านระยะ 3 เป็นตัวสำรองเวลา demo
2. **โดเมน `waf-it-kku.online`**
   nameserver ของโดเมนคือ PowerDNS บน edge ทั้งสองเครื่อง (ns1, ns2) ปิด edge เมื่อไรโดเมนและทุก subdomain
   (แดชบอร์ด, `cdn.`, ทุก CNAME ของ `originweb.site`) หาไม่เจอทันที
   เลือก: (ก) ย้าย nameserver กลับไป DNS ของ Hostinger ก่อนปิด edge แล้วจ่ายแค่ค่าต่ออายุโดเมน หรือ (ข) ปล่อยโดเมน
3. **ผู้ใช้จริง**
   ฐานข้อมูลมี 12 บัญชี บางบัญชีเป็นคนนอกทีม ก่อนปิด: ปิดการสมัครเอง, แจ้งผู้ใช้ล่วงหน้าพร้อมวันปิด
   และบอกว่าจะทำอะไรกับข้อมูล ข้อมูลที่เก็บต่อต้องเข้ารหัส (PDPA)
   ฐานข้อมูลที่ใช้พัฒนาบนเครื่องใหม่ควรเป็นสำเนาที่ปิดข้อมูลส่วนบุคคลแล้ว (51.6 ข้อ 6)
4. **ความลับ**
   เครื่องใหม่สร้างความลับชุดใหม่ทั้งหมด (`sim/up.sh` ทำให้อยู่แล้ว) `.env` ของ production เก็บไว้เฉพาะใน archive ที่เข้ารหัส
   บัญชีภายนอก (Telegram bot, Gemini API key, Google OAuth client, SMTP) ให้เลือกว่าจะเพิกถอนหรือหมุนใหม่ในระยะ 4

## 51.3 ระยะ 1 — เก็บของออกจากคลาวด์

ข้อมูลมีขนาดเล็กมาก: PostgreSQL 22 MB, ClickHouse ราว 5.5 MB (access_logs 84,370 แถว, honeypot_events 5,917,
ml_verdicts 4,278, security_audit_logs 6,755, shield_events 307)
ส่วนที่ต้องระวังคือไฟล์ที่ **ไม่อยู่ใน git** ซึ่งถ้าไม่เก็บตอนนี้จะหายไปพร้อมเครื่อง

### ของที่ต้องเก็บ

| เครื่อง | path | ทำไม | ไปที่ไหน |
|---|---|---|---|
| Main | `/root/waf_project/.env` | ความลับทั้งหมดของระบบ | archive เท่านั้น ห้ามเข้า git |
| Main | `/root/waf_project/modsecurity/custom-rules/` ทั้งโฟลเดอร์ | `custom-100002.conf` และ `00-modsecurity-override.conf` ต่างจาก repo, มีกฎ `ml-*`, `managed-*`, blocklist และ whitelist ที่ใช้จริง | archive และตัดสินใจฉบับจริงในระยะ 2 |
| Main | `/root/waf_project/Caddyfile` | ไม่อยู่ใน git | เทียบกับ repo แล้วเข้า git |
| Main | `/root/waf_project/dashboard/backend/data/` | ฐาน GeoIP (`dbip-country-lite.mmdb`) และข้อมูลที่ backend เก็บในเครื่อง | archive (โหลด GeoIP ใหม่ได้ด้วย `scripts/update_geoip.py`) |
| Main | `/etc/frp/frps.toml` | ค่าตั้ง frps มี token | archive, แม่แบบอยู่ที่ `sim/main/frps.toml` |
| Main | `/opt/cloudwaf-tunnel/` (52 KB) | ใบรับรองและสถานะของ CloudWAF Tunnel (โค้ดอยู่ใน `tunnel/`) | archive |
| Main | unit ของ systemd 5 ตัว: `waf-dashboard`, `waf-ml`, `waf-log-analyzer`, `cloudwaf-tunnel`, `frps` และ `/etc/cron.d/waf-*` | บอกวิธีรันบริการที่ยังไม่เป็น container | ตรวจว่าไม่มีความลับแล้วเข้า git ที่ `deploy/systemd/` |
| Main | PostgreSQL `waf` | ผู้ใช้ origin โดเมน กฎ ticket audit | `pg_dump` แบบเข้ารหัส |
| Main | ClickHouse 5 ตาราง | log และสถิติที่ใช้ในเล่ม | export ทีละตาราง พร้อม schema |
| edge-th | `/root/edge_node/` (ยกเว้น `logs/`) | compose, `.env`, `edge/Caddyfile`, templates, `edge/log_forwarder.py` (ไม่อยู่ใน repo), `edge/ssl/` | archive แล้วนำส่วนที่ไม่ใช่ความลับเข้า git |
| edge-th | `/opt/geodns-pdns/` | zone และค่าตั้ง PowerDNS ที่ใช้จริง | archive และเทียบกับ `cdn/geodns-pdns/` |
| edge-asia | `/opt/edge_node/` และ `/opt/geodns-pdns/` | โครงเดียวกับ edge-th | archive |
| edge ทั้งสอง | image `waf-edge-caddy:2.11.4-redis1.9.0` | build ในเครื่อง | build ใหม่จาก `cdn/edge/caddy/Dockerfile` ได้ |
| lab origin | `/var/www/originweb` (80 KB) และ `/etc/nginx/sites-available/` | เว็บทดสอบของ originweb.site | เข้า git ที่ `sim/lab/` หรือโฟลเดอร์ตัวอย่าง |
| lab origin | juice-shop, httpbin | image สาธารณะ | ไม่ต้องเก็บ |
| lab เดิม | `10.198.200.75` | เข้าจากภายนอกไม่ได้แล้ว | เก็บไม่ได้ สร้าง config ของ agent ใหม่จาก dashboard (`sim/lab/up.sh` ทำแบบนี้) |

ไม่ต้องเก็บ: Redis (สร้างใหม่จาก PostgreSQL ผ่าน `shield_sync`), ใบรับรองของ Caddy, `edge/custom-rules/` บน edge
(rulesync ดึงใหม่จาก control-api), WireGuard key (ใช้ไม่ได้อีกเมื่อปิดเครื่อง), log ใน `logs/`

### คำสั่ง (ยังไม่ได้รัน)

รันบนเครื่องที่ถือ SSH key ของทุกเครื่อง เก็บไว้นอก repo

```sh
D=~/waf-capture-$(date +%Y%m%d); mkdir -p "$D"; chmod 700 "$D"
MAIN=root@178.104.53.123

# Main: ไฟล์
ssh $MAIN 'cd /root/waf_project && tar czf - .env Caddyfile modsecurity/custom-rules dashboard/backend/data' > "$D/main-files.tgz"
ssh $MAIN 'tar czf - /etc/frp /opt/cloudwaf-tunnel /etc/cron.d' > "$D/main-system.tgz"
ssh $MAIN 'for u in waf-dashboard waf-ml waf-log-analyzer cloudwaf-tunnel frps; do systemctl cat $u; done' > "$D/main-systemd-units.txt"

# Main: ข้อมูล (ใช้ผู้ใช้เดียวกับ deploy/postgres/backup.sh)
ssh $MAIN 'docker exec waf-postgres pg_dump -U waf_owner -d waf -Fc' > "$D/waf.pgdump"
for t in access_logs honeypot_events ml_verdicts shield_events security_audit_logs; do
  ssh $MAIN "docker exec waf-clickhouse clickhouse-client -q 'SHOW CREATE TABLE default.$t FORMAT TSVRaw'" > "$D/ch-$t.sql"
  ssh $MAIN "docker exec waf-clickhouse clickhouse-client -q 'SELECT * FROM default.$t FORMAT Native'" > "$D/ch-$t.native"
done

# edge-th และ edge-asia
ssh root@45.154.26.91 'tar czf - --exclude=edge_node/logs -C /root edge_node -C /opt geodns-pdns' > "$D/edge-th.tgz"
ssh waf-node-azure 'sudo tar czf - --exclude=edge_node/logs -C /opt edge_node geodns-pdns' > "$D/edge-asia.tgz"

# lab origin
ssh waf-lab-origin 'sudo tar czf - /var/www/originweb /etc/nginx/sites-available' > "$D/lab.tgz"

# ตรวจและเข้ารหัส
(cd "$D" && shasum -a 256 * > SHA256SUMS && for f in *.tgz; do tar tzf "$f" > /dev/null || echo "BROKEN $f"; done)
tar cf - -C "$(dirname "$D")" "$(basename "$D")" | gpg --symmetric --cipher-algo AES256 -o "$D.tar.gpg"
```

**ด่านระยะ 1**
- ไฟล์ครบทุกแถวในตาราง, `pg_restore --list waf.pgdump` อ่านได้, ทุก `.tgz` เปิดได้
- `$D.tar.gpg` อยู่ 2 ที่ที่ไม่ใช่คลาวด์ที่จะปิด (เช่น external drive และ cloud drive ส่วนตัว) และทดลองถอดรหัสได้จริง
- ลบโฟลเดอร์ `$D` ที่ยังไม่เข้ารหัสหลังตรวจเสร็จ
- ห้าม commit ไฟล์ใดจากโฟลเดอร์นี้ตรง ๆ และห้ามพิมพ์ `.env` ออกหน้าจอ

## 51.4 ระยะ 2 — ปิดช่องว่างใน git

ทำใน worktree ใหม่จาก `origin/main` ถ้า clone เดิมมีงานที่ยังไม่ commit ให้เจ้าของงานตัดสินก่อนว่าจะ commit หรือทิ้ง
อย่าย้ายเครื่องโดยมีงานค้างนอก git

1. **edge config (Known Issue #1):** นำ `docker-compose.yml`, `edge/Caddyfile`, `edge/log_forwarder.py` และ `.env.example`
   (ชื่อตัวแปรเท่านั้น ไม่มีค่า) จาก archive ของ edge เข้า `cdn/edge/` ห้ามนำ `.env`, `ssl/edge.key`, `ssl/dhparam-*.pem` เข้า git
   edge ทั้งสองใช้ compose เดียวกัน ต่างกันแค่ digest ของ image (`095ec5…` บน edge-th, `ccec5e…` บน edge-asia ทั้งคู่เป็น CRS 3.3.10)
   ฉบับใน git ให้ใช้ CRS 4.25.1 ตาม `cdn/docker-compose-cdn.yml`
2. **สิทธิ์ของ `99-rulesync.sh`:** ใน git เป็น 100644 image nginx ข้ามสคริปต์ที่ไม่ executable ทำให้ edge ที่ติดตั้งจาก git ไม่ sync กฎ
   แก้ด้วย `git update-index --chmod=+x cdn/edge/entrypoint.d/99-rulesync.sh`
3. **กฎที่ต่างจาก repo:** ฉบับบน Main คือของที่ใช้จริง แนะนำให้ commit ฉบับ Main
   (`custom-100002.conf` เป็นกฎ deceive ระยะที่ 1 ตอบ 418, `00-modsecurity-override.conf` ระบุ Paranoia Level 1 ชัดเจน)
4. **systemd และ cron:** commit เป็นเอกสารอ้างอิงที่ `deploy/systemd/` หลังตรวจว่าไม่มีความลับ
5. **Caddyfile ของ Main และเว็บ originweb:** เทียบกับ repo แล้ว commit
6. **`sim/`:** อยู่บน branch `claude/project-thread-2vsr5p` ยังไม่ merge และยังไม่เคยรันในรอบนี้
   merge หลังผ่านด่านระยะ 3 บนเครื่องใหม่เท่านั้น

**ด่านระยะ 2:** clone ใหม่จาก GitHub แล้วมีทุกไฟล์ที่จำเป็นต่อการขึ้นระบบ ยกเว้นความลับ

## 51.5 ระยะ 3 — ขึ้นระบบบนเครื่องใหม่

### เครื่องที่ต้องใช้

- Docker Engine หรือ Docker Desktop
- RAM อย่างน้อย 16 GB (sim ใช้ราว 6 GB) และดิสก์ว่าง 30 GB
- แนะนำ amd64 ถ้าเป็น arm64 (เช่น Mac M-series) ต้องทดสอบว่าทุก image มี arm64 โดยเฉพาะ `owasp/modsecurity-crs` และ onnxruntime ของ waf-ml
- Mac ที่ใช้อยู่ตอนวางแผน (RAM 8 GB, ไม่มี Docker) ไม่พอ

### ขึ้นระบบเปล่าก่อน

```sh
git clone https://github.com/jakkaret/waf-cdn-platform.git && cd waf-cdn-platform
git checkout claude/project-thread-2vsr5p   # จนกว่าจะ merge sim/ เข้า main
bash sim/up.sh      # ครั้งแรก 15-25 นาที
bash sim/test.sh    # ต้องผ่าน 19/19
```

sim จำลอง 5 เครื่อง (main, edge-th, edge-asia, lab, client) แต่ละเครื่องมี Docker ของตัวเองและใช้ IP เดียวกับของจริง
ไฟล์ compose, template และสคริปต์ของ repo จึงรันข้างในได้โดยไม่ต้องแก้ รายละเอียดใน `sim/README.md`

### งานที่ต้องเติมให้ sim ครบ

| งาน | วิธี | เกณฑ์ผ่าน |
|---|---|---|
| TLS | ใช้ Pebble (ACME server ทดสอบของ Let's Encrypt) เป็น CA ให้ Caddy ของ edge และให้ client เชื่อ CA นี้ | `curl https://…` ผ่าน edge ได้ใบรับรองจาก Pebble |
| waf-ml และ waf-log-analyzer | container จาก `ml/` ใช้โมเดล `ml/models/gen3/gen3_f_noopenappsec.onnx` ที่อยู่ใน git | ML insights มีคะแนนของคำขอที่ยิงใน sim |
| cdn-log-forwarder | ใช้ `log_forwarder.py` ที่นำเข้า git ในระยะ 2 บน edge ทั้งสอง | Traffic logs เห็นคำขอที่ผ่าน edge |
| GeoIP | DB-IP Lite ผ่าน `scripts/update_geoip.py` สำหรับสถิติประเทศ (GeoDNS ใน sim ใช้ฐานสังเคราะห์ต่อได้) | หน้า dashboard แสดงประเทศ |
| อีเมล | Mailpit (มี `qa-mailpit` อยู่แล้ว) | สมัครสมาชิกแล้วรหัส OTP เข้า Mailpit |
| บริการภายนอก | Telegram, Gemini, Google OAuth ใส่ค่าสำหรับ dev หรือปล่อยว่าง (ระบบตอบว่ายังไม่ได้ตั้งค่า) | ไม่มีหน้าใดพังเพราะไม่มีค่า |

## 51.6 นำเข้าข้อมูลและด่านตรวจระยะ 3

1. ถอดรหัส archive บนเครื่องใหม่ (นอก repo)
2. **PostgreSQL:** กู้เข้า `waf-postgres` ใน sim (สร้างบทบาทด้วย `deploy/postgres/bootstrap.sh` ก่อน แล้ว `pg_restore --no-owner --role=waf_owner`)
3. **ClickHouse:** สร้างตารางจาก `ch-*.sql` แล้ว `INSERT … FORMAT Native` จาก `ch-*.native`
   **ระวัง:** `access_logs` มี TTL 30 วัน และ `ml_verdicts` 7 วัน ข้อมูลเดือนตุลาคมจะถูกลบทันทีหลังนำเข้า
   ถ้าต้องการเก็บไว้ใช้อ้างอิง ให้ตั้ง `ACCESS_LOGS_RETENTION_DAYS` และ `ML_VERDICTS_RETENTION_DAYS` ให้ยาวก่อนนำเข้า
   และเก็บไฟล์ `.native` ไว้ใน archive เสมอ
4. **กฎ:** วาง `modsecurity/custom-rules/` จาก archive (หรือฉบับที่ commit ในระยะ 2) แล้วให้ระบบสร้างไฟล์ `managed-*` และ hostmap ใหม่
5. **ความลับ:** ใช้ชุดใหม่ที่ sim สร้าง ไม่ใช้ `.env` ของ production
6. **ข้อมูลส่วนบุคคล:** ฐานข้อมูลสำหรับพัฒนาให้แทนอีเมลและชื่อของผู้ใช้ภายนอกด้วยค่าทดสอบ และลบ session กับ Telegram chat id ทิ้ง

**ด่านระยะ 3 (ต้องผ่านทุกข้อก่อนระยะ 4)**
- `sim/test.sh` ผ่าน 19/19
- เข้าแดชบอร์ดด้วยบัญชี admin ได้ และเห็น origin, โดเมน และกฎที่นำเข้า
- หน้า Traffic logs, Honeypot และ ML insights แสดงข้อมูลที่นำเข้า
- คำขอ SQLi ผ่าน edge ได้ 403, คำขอปกติผ่าน edge → Main → origin ได้ 200 ผ่าน HTTPS (Pebble)
- ปิดเครื่องแล้วเปิดใหม่ (`docker compose -f sim/compose.yml restart`) ข้อมูลยังอยู่
- คนอื่นในทีม clone ไปรันบนอีกเครื่องได้โดยอ่านแค่บทนี้กับ `sim/README.md`

## 51.7 ระยะ 4 — ปิดคลาวด์ (เจ้าของบัญชีทำเอง)

ทำตามลำดับ และทำหลังผ่านด่านระยะ 3 เท่านั้น

1. ปิดการสมัครเอง และแจ้งผู้ใช้ภายนอกพร้อมวันปิด
2. เก็บของรอบสุดท้าย (ทำ 51.3 ซ้ำ) แล้วทดลองกู้บนเครื่องใหม่อีกครั้ง
3. DNS: ย้าย nameserver ของ `waf-it-kku.online` กลับ Hostinger หรือปล่อยโดเมนตามที่ตัดสินใจในระยะ 0
   และลบ CNAME ของ `originweb.site` ที่ชี้มาที่ `cdn.waf-it-kku.online`
4. เพิกถอนหรือหมุนความลับของบัญชีภายนอก: token ของ Telegram bot (`/revoke` ที่ BotFather), Gemini API key,
   Google OAuth client (ลบ หรือเหลือไว้เฉพาะ redirect `localhost`), รหัส SMTP และ secret ใน GitHub Actions ที่อ้างเครื่องจริง (ถ้ามี)
5. ลบทรัพยากรที่คิดเงิน
   - **Azure (edge-asia, lab origin):** การ stop/deallocate ยังคิดค่าดิสก์และ public IP ให้ลบทั้ง resource group
   - **Hetzner (Main):** server ที่ปิดเครื่องยังคิดเงิน ต้องลบ server (snapshot ก็คิดเงิน)
   - **edge-th:** ยกเลิกบริการกับผู้ให้บริการ VPS
6. ลบ alias และ key ของเครื่องที่ปิดแล้วออกจาก `~/.ssh/config` ของเครื่องที่ใช้งาน

## 51.8 ระยะ 5 — ต่อยอดหลังย้ายเสร็จ

- ย้ายบริการ systemd 5 ตัว (waf-dashboard, waf-ml, waf-log-analyzer, frps, cloudwaf-tunnel) เป็น image
  เมื่อเสร็จ ทุกส่วนเป็น container และ compose เดียวกันใช้ได้ทั้งบนเครื่องพัฒนาและบนเซิร์ฟเวอร์ในอนาคต
- ทำ compose แบบแบนสำหรับพัฒนาประจำวัน (ทุกบริการเป็น container บน Docker เดียว ไม่ต้องจำลองเครื่อง)
  และเก็บ `sim/` ไว้ทดสอบแบบหลายเครื่อง เช่น GeoDNS และ failover
- ใส่ `sim/test.sh` ใน CI เพื่อให้ทุก commit ผ่าน end-to-end ก่อน merge

## 51.9 รันบน PC (Windows หรือ Linux)

### ระยะ 1 บน PC: ต้องมี SSH key ก่อน

คำสั่งใน 51.3 ต้องใช้ SSH key ที่ตอนนี้อยู่บน Mac ของผู้วางแผน มีสองทาง

- **ทาง ก (ง่ายกว่า):** รันระยะ 1 บน Mac ที่ SSH ได้อยู่แล้ว แล้วย้ายแค่ `waf-capture-*.tar.gpg` ไป PC
- **ทาง ข:** ย้าย key ไป PC ผ่าน USB หรือที่เก็บที่เข้ารหัส ห้ามส่งทางแชตหรืออีเมล

| ปลายทาง | ผู้ใช้ | key บน Mac |
|---|---|---|
| Main `178.104.53.123` | root | `~/.ssh/id_ed25519` |
| edge-th `45.154.26.91` | root | `~/.ssh/id_ed25519` |
| edge-asia (alias `waf-node-azure`, `57.158.25.236`) | azure | `~/.ssh/waf-node-us_key.pem` |
| lab origin (alias `waf-lab-origin`, `20.189.113.148`) | Origin | `~/.ssh/waf-origin/origin_key.pem` |

บน PC ให้วาง key ไว้ใน `~/.ssh/` ของ WSL หรือ Linux (ไม่ใช่ใต้ `/mnt/c` เพราะ ssh ปฏิเสธ key ที่สิทธิ์กว้าง)
แล้ว `chmod 600` ทุกไฟล์ และสร้าง `~/.ssh/config` ให้มี alias `waf-node-azure` และ `waf-lab-origin` ตามตาราง
ลบ key ออกจาก PC หลังปิดคลาวด์แล้ว เพราะไม่มีประโยชน์อีก

บน Linux ใช้ `sha256sum` แทน `shasum -a 256` ได้ และต้องมี `gpg` (`sudo apt install gnupg`)

### ระยะ 3 บน Windows

1. ติดตั้ง WSL2 กับ Ubuntu (`wsl --install -d Ubuntu` ใน PowerShell แบบ admin) แล้วติดตั้ง Docker Desktop
   เปิด Settings → Resources → WSL integration ให้ Ubuntu
2. ให้ WSL ใช้ RAM พอ: สร้าง `%UserProfile%\.wslconfig`
   ```ini
   [wsl2]
   memory=12GB
   processors=6
   ```
   แล้ว `wsl --shutdown` หนึ่งครั้ง (ปรับตัวเลขตามเครื่อง sim ต้องการ RAM ว่างราว 6 GB)
3. ทำทุกอย่างใน terminal ของ Ubuntu และ clone ไว้ใน home ของ WSL (`~/`) ไม่ใช่ `/mnt/c`
   ซึ่งช้ามากและทำให้สิทธิ์ไฟล์กับปลายบรรทัดของสคริปต์ผิด
   ```sh
   git config --global core.autocrlf input
   git clone https://github.com/jakkaret/waf-cdn-platform.git ~/waf-cdn-platform
   cd ~/waf-cdn-platform && git checkout claude/project-thread-2vsr5p
   bash sim/up.sh && bash sim/test.sh
   ```
4. เปิดแดชบอร์ดจากเบราว์เซอร์ของ Windows ที่ `http://localhost:8880`
5. ถอดรหัส archive และนำเข้าข้อมูลใน Ubuntu ตาม 51.6 เก็บ archive ที่ถอดรหัสแล้วไว้นอกโฟลเดอร์ repo

บน Linux ข้ามข้อ 1–2 ติดตั้ง Docker Engine แล้วทำข้อ 3–5 ได้เลย
