# 🛡️ Phase 1: Core CDN — งานริว

ส่วนที่รับผิดชอบ (label **ริว**):
- ✅ **Reverse Proxy + Origin Separation**
- ✅ **Cache policy** (TTL, bypass conditions, static/dynamic)
- ✅ **Cache hit/miss** (X-Cache-Status header + stats API)

---

## 📁 โครงสร้างไฟล์

```
cdn/
├── docker-compose-cdn.yml          ← Compose รวม 5 edge nodes
├── cache-conf/
│   └── cache-policy.conf           ← Cache policy หลัก (ริว)
├── nginx-edge-sg/nginx.conf        ← Edge SG config
├── nginx-edge-jp/nginx.conf        ← Edge JP config
├── nginx-edge-us/nginx.conf        ← Edge US config
├── nginx-edge-de/nginx.conf        ← Edge DE config
├── nginx-edge-ch/nginx.conf        ← Edge CH config
├── scripts/
│   ├── cdn_stats.py                ← Stats collector (ริว)
│   ├── Dockerfile.stats
│   └── purge-cache.sh              ← Purge helper (บอสใช้)
└── dashboard-api/
    ├── cdn.py                      ← FastAPI endpoint (ริว)
    └── cdn.html                    ← Dashboard page (ริว)
```

---

## 🚀 วิธีรัน

```bash
# 1. รัน CDN nodes
cd cdn
docker-compose -f docker-compose-cdn.yml up -d

# 2. ตรวจสอบสถานะ
docker-compose -f docker-compose-cdn.yml ps

# 3. ทดสอบ edge node
curl -I http://localhost:8081/           # SG
curl -I http://localhost:8082/           # JP
curl -I http://localhost:8083/           # US
curl -I http://localhost:8084/           # DE
curl -I http://localhost:8085/           # CH
```

---

## ✅ งาน 1: Reverse Proxy + Origin Separation

แต่ละ edge node ทำหน้าที่:
- **Reverse Proxy** → รับ traffic จาก client แล้วส่งต่อไป DVWA origin
- **Origin Separation** → DVWA ไม่ expose port ตรง client เห็นแค่ edge

```
Client → Edge Node (SG:8081) → DVWA origin:internal:80
```

Config หลักอยู่ใน `nginx-edge-*/nginx.conf`:
```nginx
upstream dvwa_origin {
    server origin.internal:80;
    keepalive 32;
}
```

Origin แยกออกมาอยู่ใน internal network `cdn-net` ไม่ expose port ออก host

---

## ✅ งาน 2: Cache Policy

`cache-conf/cache-policy.conf` กำหนด policy แบ่งเป็น 3 ระดับ:

| Content Type | TTL | เหตุผล |
|---|---|---|
| รูปภาพ (.jpg .png .webp) | **1 ปี** | เปลี่ยนน้อย, immutable |
| CSS / JS / Fonts | **7 วัน** | เปลี่ยนบ้าง |
| HTML pages | **5 นาที** | dynamic content |
| API / Login / Setup | **ไม่ cache** | session-sensitive |

### Bypass Conditions (ไม่ cache ถ้า):
- มี `PHPSESSID` cookie → user login แล้ว
- มี `Authorization` header → API call
- Method ไม่ใช่ GET/HEAD → POST/PUT/DELETE
- Header `Cache-Control: no-cache` → force refresh

---

## ✅ งาน 3: Cache Hit/Miss

### Header ที่ส่งไป client:
```
X-Cache-Status: HIT    ← เสิร์ฟจาก cache
X-Cache-Status: MISS   ← ไปถาม origin
X-Cache-Status: BYPASS ← ข้าม cache (login/api)
X-Cache-Status: EXPIRED← cache หมดอายุ กำลัง refetch
X-Cache-Status: STALE  ← เสิร์ฟของเก่าขณะ refetch
```

ทดสอบ:
```bash
# ครั้งแรก = MISS
curl -I http://localhost:8081/dvwa/images/login_logo.png
# X-Cache-Status: MISS

# ครั้งสอง = HIT
curl -I http://localhost:8081/dvwa/images/login_logo.png
# X-Cache-Status: HIT
```

### Stats API (เพิ่มใน dashboard):
```
GET /api/cdn/stats          → stats ทุก region
GET /api/cdn/stats/SG       → stats เฉพาะ SG
GET /api/cdn/nodes          → node status (online/offline)
```

### Stats Collector:
```bash
# รันแยก (หรือรันผ่าน docker-compose)
python3 scripts/cdn_stats.py

# เรียกดู metrics
curl http://localhost:9090/metrics
```

---

## 🔧 เพิ่ม CDN เข้า Dashboard (main.py)

```python
# dashboard/backend/main.py
from api import cdn
app.include_router(cdn.router)

# เพิ่ม route สำหรับหน้า HTML
@app.get("/cdn.html")
async def serve_cdn():
    return FileResponse(os.path.join(frontend_path, "cdn.html"))
```

แล้ว copy `dashboard-api/cdn.html` → `dashboard/frontend/cdn.html`
และ copy `dashboard-api/cdn.py` → `dashboard/backend/api/cdn.py`

---

## 📊 ตัวอย่าง Log Output (JSON)

```json
{
  "time": "2026-05-06T10:23:14+00:00",
  "region": "SG",
  "remote_addr": "172.30.0.1",
  "method": "GET",
  "uri": "/dvwa/images/login_logo.png",
  "status": "200",
  "cache_status": "HIT",
  "upstream_response_time": "0.000",
  "request_time": "0.001"
}
```

`cache_status = ""` เมื่อ served from cache (upstream ไม่ถูกเรียก)  
`cache_status = "MISS"` เมื่อต้องไปถาม DVWA

---

## 🤝 Handoff ให้บอส (Cache System + Purge)

ส่วนที่บอสต้องทำต่อ:
1. **Cache System (หัวใจ CDN)** — ใช้ `proxy_cache_path` ที่ริวเตรียมไว้แล้ว, เพิ่ม `ngx_cache_purge` module ถ้าต้องการ purge แบบ fine-grained
2. **Cache Purge (Invalidate)** — ใช้ script `scripts/purge-cache.sh` เป็น base, หรือเพิ่ม `PURGE` method ใน nginx config
3. **Multi Node** — container ทั้ง 5 เตรียมไว้ใน `docker-compose-cdn.yml` แล้ว
