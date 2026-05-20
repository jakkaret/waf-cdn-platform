# Phase 5: WAF Global Block + Rule Sync (Edge CDN)

## เป้าหมาย
- ทุก Edge node มี WAF (ModSecurity) + OWASP CRS (ทำงานเหมือนกันทุก node)
- Global blocklist: ถ้า block IP จากจุดเดียว ให้ sync ไปทุก node
- Rule sync: Edge node ดึง custom rules จาก API กลาง และ reload อัตโนมัติ (มี `nginx -t` ก่อน reload)
- มีสคริปต์เทสระบบใหม่ทั้งหมด

## สถาปัตยกรรม
- `cdn-control-api` (port `8070`): API กลาง
  - เก็บ blocklist ใน sqlite (`/data/control.db`)
  - อ่าน custom rules จาก repo `modsecurity/custom-rules` (mount read-only)
  - สร้าง bundle ให้ edge sync ผ่าน `GET /api/sync/bundle`
- Edge nodes: `cdn-edge-sg`, `cdn-edge-jp`, `cdn-edge-th`
  - เปิด ModSecurity + CRS อยู่แล้ว
  - ใช้ `/docker-entrypoint.d/99-rulesync.sh` ดึง bundle และ update `/opt/custom-rules`
  - sync interval จาก env `CDN_SYNC_INTERVAL_SEC`

## API กลาง
- `GET /healthz`
- `GET /api/blocklist`
- `POST /api/blocklist` (ต้องมี `X-Control-Token`)
- `DELETE /api/blocklist/{ip}` (ต้องมี `X-Control-Token`)
- `GET /api/sync/bundle` (gzip tar):
  - `custom-*.conf` จาก `modsecurity/custom-rules`
  - `global_blocklist.txt`
  - `custom-000000-global-blocklist.conf` (autogen: `@ipMatchFromFile`)

## การตั้งค่า
- ดูตัวอย่าง env: `cdn/.env.example`
  - `CDN_CONTROL_TOKEN` ใช้สำหรับเขียน blocklist
  - `CDN_SYNC_INTERVAL_SEC` ตั้งรอบการ sync

## วิธีรัน
```bash
cd cdn
docker compose -f docker-compose-cdn.yml up -d --build
```

## วิธีเทส (ครบทุกฟังก์ชัน)
```bash
cd cdn
./scripts/phase5-test-all.sh
```

## คำสั่งใช้งาน Global Blocklist (manual)
```bash
cd cdn
./scripts/block-ip.sh 203.0.113.10 manual
./scripts/unblock-ip.sh 203.0.113.10
```

## ผลทดสอบที่คาดหวัง
- Edge health = ok
- Cache MISS/HIT ยังทำงาน
- Purge ยังทำงาน
- GeoDNS auto routing ยังทำงาน
- Rule sync ทำงาน: `GET /testattack` ผ่าน edge ได้ `403`
- Global block sync ทำงาน: block IP 1 ตัวแล้วทุก edge ตอบ `403` สำหรับ IP นั้น

## ผลทดสอบล่าสุด
- 2026-05-20 (Asia/Bangkok): รัน `cdn/scripts/phase5-test-all.sh` แล้ว PASS
