# สภาพแวดล้อมจำลอง (sim/)

จำลองทั้งระบบ WAF + CDN บนเครื่องเดียว ทุกเครื่องของ production เป็น container
ที่มี Docker daemon ของตัวเอง และอยู่บน network ที่ใช้ IP จริง ไฟล์ compose,
template และสคริปต์ของ repo จึงรันข้างในได้แบบไม่ต้องแก้ ทั้งพอร์ตที่ bind กับ
`10.88.0.1`, frps ที่ `172.18.0.1:8085` และ PowerDNS ที่ bind IP ของ edge เอง
ทุก secret เป็นค่าสุ่มใหม่ ไม่แตะเซิร์ฟเวอร์จริงเลย

| เครื่อง | IP | ข้างในมีอะไร |
|---|---|---|
| `main` | 178.104.53.123, WireGuard 10.88.0.1 | `docker-compose.yml` ของ repo (waf-nginx, Caddy, Redis, caddy-storage, ClickHouse, control-api, Postgres), qa-echo/qa-mailpit, และ "systemd" (waf-dashboard :8000 พร้อม frontend, frps, cloudwaf-tunnel) |
| `edge-th` | 45.154.26.91, WireGuard 10.88.0.2 | cdn-caddy-ssl, cdn-edge-node (CRS + rulesync + purge), geodns-pdns |
| `edge-asia` | 57.158.25.236, WireGuard 10.88.0.3 | เหมือน edge-th |
| `lab` | 178.104.53.75 | DVWA + FRP agent ที่ได้จาก config generator ของ dashboard |
| `client` | 45.154.26.10, 57.158.25.10, 178.104.53.10 | ผู้เข้าชม มี curl และ dig |

## ใช้งาน

ต้องมี Docker (Linux หรือ Docker Desktop) RAM ว่างราว 6 GB และดิสก์ราว 15 GB

```sh
bash sim/up.sh      # ครั้งแรก 15-25 นาที (ดึง image และ build ในแต่ละเครื่อง)
bash sim/test.sh    # ตรวจ end-to-end 19 ข้อ
bash sim/down.sh    # หยุด (down.sh -v ลบดิสก์ของทุกเครื่องด้วย)
```

ถ้าอยู่หลัง proxy ที่ตรวจ TLS ให้ส่ง CA ของ proxy เข้าไปด้วย:
`SIM_EXTRA_CA=/path/to/ca.crt bash sim/up.sh`
แต่ละเครื่องดึง image ผ่าน `mirror.gcr.io` (ตั้งเป็นค่าว่างด้วย
`SIM_REGISTRY_MIRROR=` ถ้าจะใช้ Docker Hub ตรงๆ)

เข้าไปดูในเครื่องไหนก็ได้:

```sh
docker compose -f sim/compose.yml exec main docker ps
docker compose -f sim/compose.yml exec edge-th docker logs cdn-edge-node
docker compose -f sim/compose.yml exec client curl -H 'Host: dvwa.waf-it-kku.online' http://45.154.26.91/login.php
docker compose -f sim/compose.yml exec client dig @45.154.26.91 x.cdn.waf-it-kku.online +subnet=1.46.0.0/24
```

Dashboard: เปิด http://localhost:8880 (ผ่าน Caddy ของ main เหมือนเข้าด้วย IP)
บัญชี admin อยู่ใน `sim/.state/secrets.env` (`SIM_ADMIN_EMAIL`, `SIM_ADMIN_PASSWORD`)

ดิสก์ของแต่ละเครื่อง (Docker data และโฟลเดอร์ที่ container ใช้) เป็น volume
ปิดเปิดใหม่ (`docker compose -f sim/compose.yml restart`) แล้วกลับมาเหมือนเดิม
`down.sh -v` คือล้างเครื่องทั้งหมด

## test.sh ตรวจอะไร

1. GeoDNS: คนไทย (`+subnet=1.46.0.0/24`) ได้ edge-th, คนต่างประเทศได้ edge-asia,
   สอง edge ตอบตรงกัน, ไม่ทำ recursion
2. เว็บผ่านทั้งสอง edge → waf-nginx บน Main → frps → agent ใน lab → DVWA
3. SQLi และ XSS โดน 403 ที่ edge
4. ไฟล์ static ได้ `X-Cache-Status: HIT` ครั้งที่สอง, สั่ง purge (คิวเดียวกับ
   `POST /api/cdn/purge`) แล้วกลับเป็น MISS
5. edge ทั้งสองรัน rule bundle ที่เซ็นแล้วจาก control-api
6. dashboard `/api/health`, Host อื่นที่เข้า Main ตรงโดน 403, log ของ Main เห็น IP
   ผู้เข้าชม ไม่ใช่ IP ของ edge
7. ปิด edge-asia แล้วคนต่างประเทศย้ายไป edge-th, เปิดคืนแล้วกลับมา

## ต่างจาก production ตรงไหน

- WireGuard เป็น Docker network ธรรมดา (IP เดียวกัน ไม่เข้ารหัส)
- edge เสิร์ฟ HTTP อย่างเดียว ไม่มี Let's Encrypt (ไม่มี CA สาธารณะในนี้) และ
  ไฟล์ compose/Caddyfile ของ edge (`sim/edge/`) เขียนใหม่ตามเอกสาร เพราะของจริง
  ไม่อยู่ใน git (Known Issue #1) และ `cdn/edge/Caddyfile` ที่ใช้ storage กลางยังไม่ได้ commit
- ไม่มี cdn-log-forwarder (สคริปต์ไม่อยู่ใน repo), waf-ml, waf-log-analyzer
- ฐาน GeoIP เป็นของสังเคราะห์ (`sim/edge/make_geo_mmdb.py`) แทน DB-IP Lite
- ไม่มี SMTP บัญชี admin เลยถูกตั้งว่ายืนยันอีเมลแล้วตรงๆ ในฐานข้อมูล
- Telegram, Gemini, Google OAuth, NVD ไม่ได้ตั้งค่า (ฟีเจอร์ที่ใช้จะตอบว่าไม่ได้ตั้งค่า)
- ClickHouse เริ่มว่าง มีแค่ traffic ที่เกิดใน sim
- edge-asia จริงอยู่หลัง NAT ของ Azure (172.16.0.4) ที่นี่ใช้ IP สาธารณะตรงๆ
  และแต่ละ edge มี IP เพิ่มอีกหนึ่งตัวในวงของอีก edge เพื่อให้ health check ถึงกัน

## เจอระหว่างสร้าง

- `cdn/edge/entrypoint.d/99-rulesync.sh` อยู่ใน git เป็น 100644 image nginx ข้าม
  สคริปต์ที่ไม่ executable ทำให้ edge ที่ติดตั้งจาก git ตรงๆ ไม่ sync กฎ และ nginx
  ไม่ขึ้น (หาไฟล์ใน `/opt/custom-rules` ไม่เจอ) sim จึง `chmod +x` ในสำเนาของ edge
