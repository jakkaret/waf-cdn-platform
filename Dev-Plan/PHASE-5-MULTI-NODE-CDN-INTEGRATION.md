# ⚡ Phase 5 Dev Plan: Multi-Region CDN & GeoDNS Integration

## 🎯 เป้าหมาย Phase 5
รวมศูนย์สถาปัตยกรรมกระจายโหลดแบบ **Multi-Region CDN Edge Nodes** (SG, JP, TH) ร่วมกับระบบ **GeoDNS Simulation**, **Distributed Cache Purge API**, **Global IP Blocklist Rule Sync** และหน้าจอ **CDN Management Dashboard** เพื่อให้ระบบสมบูรณ์ 100% ตามข้อกำหนดใน `CDN_BUILD_SHEET.md` และ `DESIGN.md`

---

## 🏗️ สถาปัตยกรรมโหนด CDN ใน Phase 5

```
                           [ GeoDNS Server ] (DNS Port 5533)
                                   │
               ┌───────────────────┼───────────────────┐
               ▼                   ▼                   ▼
       [ Edge SG ]         [ Edge JP ]         [ Edge TH ]
       (Port 8081)         (Port 8082)         (Port 8086)
               │                   │                   │
               └───────────────────┼───────────────────┘
                                   │
                                   ▼
                       [ Distributed Purge API ] (Port 8090)
                                   │
                                   ▼
                         [ Target Web Origin ]
```

---

## ⚙️ งานคนที่ A: Infrastructure & Backend

### 5.1 ตรวจสอบและรัน CDN Stack Containers
- **ไฟล์เกี่ยวข้อง**: `cdn/docker-compose-cdn.yml`
- **บริการใน Stack**:
  - `edge-sg`: Nginx Edge Node พอร์ต `8081`
  - `edge-jp`: Nginx Edge Node พอร์ต `8082`
  - `edge-th`: Nginx Edge Node พอร์ต `8086`
  - `geodns`: GeoDNS Server พอร์ต `5533` (UDP/TCP)
  - `cdn-purge-api`: FastAPIPurge Service พอร์ต `8090`
  - `cdn-control-api`: Central Rule Control API พอร์ต `8070`

---

### 5.2 พัฒนา CDN Purge & Control APIs ใน Backend (`api/cdn.py`)
- **ไฟล์ที่ต้องปรับปรุง**: `dashboard/backend/api/cdn.py`
- **Endpoints**:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/cdn/nodes` | ดึงสถานะ Health Status ของ Edge Nodes ทั้ง 3 ตัว (SG, JP, TH) |
| `GET` | `/api/cdn/stats` | ดึงสถิติ Cache Hit / Miss / Bypass รวม |
| `GET` | `/api/cdn/stats/{region}` | ดึงสถิติแยกตาม Region (SG / JP / TH) |
| `POST` | `/api/cdn/purge` | ส่งคำสั่ง Purge Cache (Parameter: `url`, `region`) ไปยัง Purge API Port 8090 |

```python
# snippet จาก api/cdn.py
@router.post("/purge")
async def purge_cdn_cache(
    url: str = Query(..., description="Target URL to purge"),
    region: str = Query("ALL", description="SG, JP, TH or ALL"),
    current_user: dict = Depends(get_current_user)
):
    purge_api_url = os.getenv("CDN_PURGE_API_URL", "http://localhost:8090/purge")
    token = os.getenv("CDN_PURGE_TOKEN", "cdn-secret-token")
    
    async with aiohttp.ClientSession() as session:
        params = {"url": url, "region": region}
        headers = {"X-Purge-Token": token}
        async with session.post(purge_api_url, params=params, headers=headers) as resp:
            data = await resp.json()
            return data
```

---

### 5.3 ตรวจสอบ Cache Policy & Bypass Rules
- **Cache Path**: `/var/cache/nginx/edge`
- **Cache Key**: `"$request_method|$uri"`
- **Default TTL**: Dynamic Assets `10m`, Static Assets (`.jpg`, `.css`, `.js`) `1h`
- **Bypass Conditions**:
  - HTTP Method ไม่ใช่ `GET` / `HEAD`
  - มี Request Header `Authorization`
  - มี Session Cookies (`PHPSESSID`, `security=`)
  - มี Request Header `Cache-Control: no-cache` หรือ `no-store`
  - มี Query String

---

## 💻 งานคนที่ B: Frontend & Integration

### 5.4 หน้าจอ CDN Management Dashboard (`src/pages/CDN.tsx`)
- **ไฟล์ที่ต้องปรับปรุง**: `dashboard/frontend/src/pages/CDN.tsx`
- **องค์ประกอบหน้าจอ**:
  1. **Node Health Grid**: การ์ดแสดงสถานะ Node SG, JP, TH พร้อมบอก Latency และ Port
  2. **Cache Hit Ratio Chart**: กราฟแสดงสัดส่วน Cache Hit vs Miss vs Bypass
  3. **Purge Cache Form**:
     - Input Target Path/URL (เช่น `/dvwa/images/login_logo.png`)
     - Select Region (`ALL`, `SG`, `JP`, `TH`)
     - ปุ่มกด "Purge Cache Now" พร้อมแสดง Alert ผลลัพธ์
  4. **GeoDNS Tester Widget**: เครื่องมือทดสอบยิง Request จำลอง IP ประเทศต่างๆ เพื่อดูว่า GeoDNS สั่งไปหา Region ใด

---

## 🧪 การทดสอบระบบเต็มรูปแบบ Phase 5 (End-to-End Suite)

ในการทดสอบความถูกต้อง ให้รันสคริปต์ทดสอบครบวงจรที่เตรียมไว้:

```bash
# 1. เข้าไปที่โฟลเดอร์ cdn
cd /Ubuntu/home/chirachot/seminar/waf_project/cdn

# 2. สตาร์ท CDN Stack ทั้งหมด
docker compose -f docker-compose-cdn.yml up -d --build

# 3. รันสคริปต์ทดสอบ Phase 5 ทั้งหมด
./scripts/phase5-test-all.sh
```

### 📋 สิ่งที่สคริปต์ `phase5-test-all.sh` จะตรวจสอบ:
1. **Node Health Status**: ตรวจสอบว่า SG (8081), JP (8082), TH (8086) และ Purge API (8090) ขึ้น `ok` ทั้งหมด
2. **Cache MISS -> HIT**: ยิง Request ครั้งแรกต้องขึ้น `X-Cache-Status: MISS` และยิงครั้งที่สองต้องขึ้น `X-Cache-Status: HIT`
3. **Purge Cache Execution**: ส่งคำสั่ง Purge ผ่าน API แล้วเช็คว่าไฟล์ Cache ใน volume ถูกลบสำเร็จ (`total_removed=3`)
4. **Bypass Verification**: ทดสอบ Request ที่มี Query String หรือ Header `no-cache` จะต้องได้ `X-Cache-Status: BYPASS`
5. **WAF Protection**: ยิง Payload การโจมตีไปที่ `/testattack` จะต้องโดน ModSecurity บล็อกด้วย `403 Forbidden`
6. **GeoDNS Auto-Routing**: ทดสอบจำลอง Client IP ย่าน SG, JP, TH แล้วตรวจสอบ `X-Edge-Region` ว่าส่งไปตามภูมิภาคถูกต้อง
