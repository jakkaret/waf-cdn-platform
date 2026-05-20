# CDN Build Sheet (SG / JP / TH)

## 1) เป้าหมายที่ทำ
ทำ CDN เพิ่มให้โปรเจกต์เดิมตาม flow:

`Client Request -> CDN Edge (Nginx + WAF + Cache) -> Website Origin (dvwa)`

โดยทำให้ใช้งานร่วมกับโปรเจกต์เดิมได้ผ่าน Docker network เดิม (`waf_project_waf-net`)

---

## 2) สิ่งที่สร้าง/แก้

### สร้างใหม่
- `cdn/docker-compose-cdn.yml`
- `cdn/.env.example`
- `cdn/geodns/server.py`
- `cdn/geodns/requirements.txt`
- `cdn/geodns/Dockerfile`
- `cdn/edge/templates/nginx.conf.template`
- `cdn/edge/templates/conf.d/default.conf.template`
- `cdn/edge/templates/modsecurity.d/setup.conf.template`
- `cdn/edge/templates/modsecurity.d/modsecurity.conf.template`
- `cdn/edge/templates/modsecurity.d/modsecurity-override.conf.template`
- `cdn/purge-api/main.py`
- `cdn/purge-api/requirements.txt`
- `cdn/purge-api/Dockerfile`
- `cdn/scripts/purge-cache.sh`
- `cdn/scripts/smoke-test-cdn.sh`
- `cdn/scripts/test-geodns-routing.sh`
- `cdn/control-api/main.py`
- `cdn/control-api/requirements.txt`
- `cdn/control-api/Dockerfile`
- `cdn/edge/entrypoint.d/99-rulesync.sh`
- `cdn/scripts/phase5-test-all.sh`
- `cdn/scripts/block-ip.sh`
- `cdn/scripts/unblock-ip.sh`
- `Phase 5.md`

### แก้ให้เชื่อมกับระบบเดิม
- `dashboard/backend/main.py`
  - include `api.cdn`
  - เพิ่ม route `/cdn.html`
- `dashboard/backend/api/cdn.py`
  - ปรับ node เป็น `SG/JP/TH` (ports: `8081/8082/8086`)
  - เพิ่ม endpoint `POST /api/cdn/purge`
  - ปรับ URL purge API default เป็น `http://localhost:8090`

---

## 3) สถาปัตยกรรมที่ทำ

### Multi-node CDN
- `edge-sg` -> host port `8081`
- `edge-jp` -> host port `8082`
- `edge-th` -> host port `8086`
- `geodns` -> host DNS port `5533` (UDP/TCP)
- `control-api` -> host API port `8070`

ทุก node มี:
- Nginx reverse proxy
- ModSecurity + OWASP CRS
- `proxy_cache` (volume แยก node)

### Cache System
- `proxy_cache_path` อยู่ที่ `/var/cache/nginx/edge`
- Cache key: `"$request_method|$uri"`
- TTL:
  - dynamic/default: `10m`
  - static asset: `1h`
- Bypass conditions:
  - method ไม่ใช่ GET/HEAD
  - มี Authorization header
  - มี session cookie (`PHPSESSID`, `security=`)
  - `Cache-Control: no-cache/no-store`
  - มี query string
- Header debug:
  - `X-Cache-Status`
  - `X-Edge-Region`

### Cache Purge
- Service: `cdn-purge-api` (FastAPI) port `8090`
- API: `POST /purge?url=...&region=...`
- ใช้ header: `X-Purge-Token`
- Purge โดยคำนวณ md5 จาก cache key แล้วลบ cache files ใน volume ของแต่ละ region

### GeoDNS Simulation
- โดเมนจำลอง: `cdn.local`
- GeoDNS ตอบ A record ไปยัง edge ที่เหมาะสมจาก source IP ของ client
- CIDR mapping:
  - `172.28.11.0/24` -> `SG`
  - `172.28.22.0/24` -> `JP`
  - `172.28.33.0/24` -> `TH`
- fallback เป็น `TH` ถ้าไม่เข้าเงื่อนไข

### Global Block + Rule Sync
- Edge node sync rules จาก `cdn-control-api` ผ่าน `GET /api/sync/bundle`
- Blocklist sync ผ่านไฟล์ `global_blocklist.txt` และ rule `custom-000000-global-blocklist.conf`
- Sync ทำใน entrypoint script `/docker-entrypoint.d/99-rulesync.sh` และ reload อัตโนมัติหลัง `nginx -t`

---

## 4) คำสั่งที่ใช้หลัก ๆ

### เตรียม origin (จากโปรเจกต์เดิม)
```bash
cd /Users/boss/project/waf_project
docker compose up -d dvwa
```

### รัน CDN stack
```bash
cd /Users/boss/project/waf_project/cdn
docker compose -f docker-compose-cdn.yml up -d --build
```

### เช็คสถานะ
```bash
docker compose -f docker-compose-cdn.yml ps
curl http://localhost:8081/healthz
curl http://localhost:8082/healthz
curl http://localhost:8086/healthz
curl http://localhost:8090/healthz
```

### ทดสอบ cache + purge
```bash
./scripts/smoke-test-cdn.sh
./scripts/purge-cache.sh /dvwa/images/login_logo.png ALL
```

### ทดสอบ GeoDNS auto routing
```bash
./scripts/test-geodns-routing.sh
```

### ทดสอบ Phase 5 (ครบทุกฟังก์ชัน)
```bash
./scripts/phase5-test-all.sh
```

---

## 5) ผลทดสอบจริง

### 5.1 Health ทุก node
- SG: `ok`
- JP: `ok`
- TH: `ok`
- purge-api: `{"status":"ok","regions":["SG","JP","TH"]}`

### 5.2 Cache MISS -> HIT
ทดสอบ path `/dvwa/images/login_logo.png`
- SG: first=`MISS`, second=`HIT`
- JP: first=`MISS`, second=`HIT`
- TH: first=`MISS`, second=`HIT`

### 5.3 Purge ทำงานจริง
เรียก:
`POST /purge?url=/dvwa/images/login_logo.png&region=ALL`

ผล: ลบ cache file ได้ครบทั้ง 3 region (`total_removed=3`)

### 5.4 หลัง purge
SG ทดสอบซ้ำได้ first=`MISS`, second=`HIT`

### 5.5 Bypass policy
- query string -> `X-Cache-Status: BYPASS`
- `Cache-Control: no-cache` -> `X-Cache-Status: BYPASS`

### 5.6 WAF ยังทำงาน
ทดสอบ `http://localhost:8086/testattack` ได้ `403 Forbidden`

### 5.7 GeoDNS auto-select ทำงาน
ผลจาก `./scripts/test-geodns-routing.sh`:
- probe SG (`client_ip=172.28.11.10`) -> `X-Edge-Region: SG`
- probe JP (`client_ip=172.28.22.10`) -> `X-Edge-Region: JP`
- probe TH (`client_ip=172.28.33.10`) -> `X-Edge-Region: TH`

---

## 6) วิธีใช้งานร่วมกับ Dashboard เดิม

หลังรัน backend เดิม (`python3 main.py` หรือ `uvicorn main:app --reload`) จะมี API เพิ่ม:
- `GET /api/cdn/nodes`
- `GET /api/cdn/stats`
- `GET /api/cdn/stats/{region}`
- `POST /api/cdn/purge?url=...&region=ALL` (admin)

และหน้า `cdn.html` จะถูกเสิร์ฟจาก backend แล้ว

---

## 7) หมายเหตุสำคัญ
- purge token default ใน stack นี้คือ `cdn-secret-token` ควรเปลี่ยนเป็นค่าที่ปลอดภัยด้วย env `CDN_PURGE_TOKEN`
- network ภายนอกที่ใช้เชื่อม origin ตั้งเป็น `waf_project_waf-net` (override ได้ด้วย `WAF_NETWORK_NAME`)
- หากมี container CDN เก่าชนพอร์ต ให้ down ด้วย:
```bash
docker compose -f docker-compose-cdn.yml down --remove-orphans
```
