## กฎการทำงาน (อ่านก่อนทุกครั้ง)

กฎการทำงาน:
1. ก่อนเขียนหรือแก้ไขไฟล์ใด ให้อ่านไฟล์นั้นก่อนทุกครั้ง
2. อย่าลบหรือ overwrite config ที่ทำงานอยู่แล้ว — ต่อเพิ่มเข้าไป
3. ให้ implement จริง ไม่ใช่แค่ออกแบบ
4. ทำทีละ task จนเสร็จสมบูรณ์ก่อนไปต่อ
5. อย่า overwrite config ที่ทำงานได้แล้ว
6. บอก path ของทุกไฟล์ที่แก้ไขชัดเจน
7. เขียน test script สำหรับทดสอบระบบที่ทำไปแล้ว (อยู่ใน `cdn/scripts/`)
8. บันทึกสถานะการทำงานลงในไฟล์ Task.md ด้วย 
9. บอกสถานะของ Task ด้วย ✅ 🔄 
10. เมื่อทำ Task เสร็จ ให้รายงานผล แล้วถามฉันก่อนไปต่อ Task ถัดไป และบันทึกสถานะ

## สถานะปัจจุบัน
- Phase 1 ✅ 
- Phase 2: ✅ Rate Limiting per Edge ✅, TLS / HTTPS (Edge SSL) ✅, Static vs Dynamic Routing ✅, Test Scripts ✅ 
- Phase 3: Health Check Endpoint ✅,Failover Logic ใน GeoDNS ✅
- Phase 4: Central Log Collection ✅, Metrics Dashboard ✅, Latency Tracking ✅ 

## Task ที่เสร็จแล้ว

### PHASE 2 
Task: Phase 2 — Rate Limiting per Edge

โครงสร้างที่มีอยู่:
- cdn/edge/templates/ มี Nginx config ของแต่ละ edge node (SG/JP/TH)
- docker-compose-cdn.yml ที่ cdn/

สิ่งที่ต้องทำ:
1. อ่าน cdn/edge/templates/default.conf.template (หรือ config ที่มีอยู่) ก่อน
2. เพิ่ม limit_req_zone ใน Nginx http block
3. เพิ่ม limit_req ใน location / block สำหรับทุก edge node
4. ตั้งค่า rate: 30r/s, burst: 60 (ค่าเริ่มต้น) — ปรับผ่าน ENV ได้
5. ให้ return 429 เมื่อ rate exceeded พร้อม custom error page
6. เพิ่ม header X-RateLimit-Limit ใน response

ข้อกำหนด:
- Rate limit แยกต่อ IP (key=$binary_remote_addr)
- แต่ละ edge node มีค่าได้ต่างกัน (ใช้ ENV variable)
- ไม่กระทบ /healthz endpoint

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

Task: Phase 2 — TLS / HTTPS (Edge SSL)

โครงสร้างที่มีอยู่:
- nginx/templates/conf/server.crt และ server.key (self-signed cert ใช้กับ WAF หลัก)
- cdn/edge/ เป็นที่อยู่ของ edge node config

สิ่งที่ต้องทำ:
1. อ่าน cdn/docker-compose-cdn.yml ก่อน
2. Generate self-signed cert สำหรับ CDN edges (หรือ reuse จาก WAF)
3. เพิ่ม HTTPS server block (port 8441/8442/8446 สำหรับ SG/JP/TH) ใน edge config
4. Configure ssl_protocols TLSv1.2 TLSv1.3 เหมือน WAF หลัก
5. Mount cert ผ่าน Docker volume ใน docker-compose-cdn.yml
6. ให้ HTTP redirect ไป HTTPS (optional ENV flag FORCE_HTTPS=true)

ข้อกำหนด:
- ทำงานร่วมกับ rate limiting จาก Task 2A
- ไม่ทำลาย cache behavior ที่มีอยู่
- บอก port mapping ชัดเจน

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

Task: Phase 2 — Static vs Dynamic Routing

สิ่งที่ต้องทำ:
1. อ่าน edge Nginx config ที่แก้ไขมาแล้วจาก Task 2A และ 2B ก่อน
2. แยก location block เป็น 2 ประเภท:
   - Static: /.+\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|svg)$ → cache 1 ชั่วโมง
   - Dynamic: / (default) → cache 10 นาที หรือ bypass ตาม cookie/header
3. เพิ่ม Cache-Control response header ให้เหมาะสมแต่ละประเภท
4. Static assets ไม่ต้อง rate limit เข้มงวดเท่า API
5. เพิ่ม X-Content-Type ใน static location

ข้อกำหนด:
- ทำงานร่วมกับ Task 2A + 2B
- Cache policy ต้องสอดคล้องกับ Skill.md ส่วนที่ 8

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

### Test Scripts (Phase 2)
สร้าง Test scripts สำหรับทดสอบระบบที่ทำไปแล้วใน Phase 2 (อยู่ใน `cdn/scripts/`)
- `cdn/scripts/requirements.txt`: ไฟล์ dependencies (`requests`, `urllib3`)
- `cdn/scripts/test_rate_limit.py`: ทดสอบการทำงานของ Rate Limiting (ยิง request รัวๆ เพื่อเช็ค 429)
- `cdn/scripts/test_tls_edge.py`: ทดสอบ HTTPS endpoint ของทุก Edge
- `cdn/scripts/test_routing.py`: ทดสอบ headers (Cache-Control, RateLimit) สำหรับ Static และ Dynamic routes

**วิธีรัน Test Scripts:**
1. ติดตั้ง dependencies: `pip install -r cdn/scripts/requirements.txt`
2. รันสคริปต์ที่ต้องการ เช่น:
   - `python cdn/scripts/test_rate_limit.py`
   - `python cdn/scripts/test_tls_edge.py`
   - `python cdn/scripts/test_routing.py`

### PHASE 3
Task: Phase 3A — Health Check Endpoint

สิ่งที่ต้องทำ:
1. ตรวจสอบว่าทุก edge node มี /healthz location block หรือยัง
2. เพิ่ม /healthz endpoint ใน Nginx config ทุก edge node:
   - return 200 "OK"
   - ไม่ log (access_log off)
   - ไม่ cache
   - ไม่ rate limit
3. เพิ่ม /healthz endpoint ใน Purge API (cdn/purge-api/main.py) ด้วย
4. Response ควรมี JSON: {"status": "ok", "region": "SG", "timestamp": ...}
5. เพิ่มใน dashboard backend: GET /api/cdn/nodes ที่ poll health ของทุก node แล้ว return status

อ่านไฟล์เหล่านี้ก่อน:
- cdn/purge-api/main.py
- cdn/edge/templates/ (config ที่แก้ไขมาแล้ว)
- dashboard/backend/api/cdn.py (ถ้ามี)

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข


### PHASE 3

Task: Phase 3B — Failover Logic ใน GeoDNS ✅

สิ่งที่ต้องทำ:
1. อ่าน cdn/geodns/server.py ก่อน (Geo Routing ที่เสร็จแล้ว)
2. เพิ่ม health check loop ที่ poll /healthz ของทุก node ทุก 10 วินาที
3. เก็บ node status ใน dict: {"sg": True, "jp": False, "th": True}
4. Failover logic:
   - ถ้า node ที่ควร route ไป offline → route ไป fallback node ตาม priority: SG→TH, JP→TH, TH→SG
5. Log เมื่อมี failover เกิดขึ้น: "Failover: sg → th (sg is DOWN)"
6. เพิ่ม endpoint /status ใน GeoDNS server (HTTP) แสดง node health status

ข้อกำหนด:
- ไม่ทำลาย routing logic เดิม
- Health check ต้องเป็น async (ใช้ asyncio หรือ threading)

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

### PHASE 4

Task: Phase 4A — Central Log Collection ✅

สิ่งที่ต้องทำ:
1. อ่าน dashboard/backend/services/log_forward.py ก่อน (ระบบ log forward ที่มีอยู่สำหรับ WAF)
2. เพิ่ม log collection สำหรับ CDN edge nodes:
   - แต่ละ edge node มี access log ที่ mount มาที่ logs/cdn/{region}/access.json
   - เพิ่ม cdn_log_forward.py ที่ tail log ของทุก node พร้อมกัน
   - normalize ข้อมูลเพิ่ม field: region, edge_node, cache_status, latency
3. Save รวมไปที่ DynamoDB table "waf_logs" หรือ "cdn_logs" (เพิ่ม field region)
4. เพิ่ม GET /api/cdn/logs?region=ALL&limit=50 ใน dashboard backend

อ่านไฟล์เหล่านี้ก่อน:
- dashboard/backend/services/log_forward.py
- dashboard/backend/services/dynamodb_service.py
- dashboard/backend/main.py

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

Task: Phase 4B — Metrics Dashboard

ส่วน Backend:
1. อ่าน dashboard/backend/api/cdn.py (ถ้ามีอยู่แล้ว)
2. Implement หรือเพิ่มใน /api/cdn/stats:
   - request_count per region
   - cache hit ratio (hit / total)
   - blocked_count (403) per region
   - avg_latency per node
   - top 5 blocked URLs
3. เพิ่ม /api/cdn/stats/{region} สำหรับ drill down

ส่วน Frontend (React):
1. อ่าน dashboard/frontend/src/pages/CDN.tsx (ถ้ามี) หรือ src/App.tsx
2. สร้าง CDN.tsx page ที่แสดง:
   - Node status cards (SG/JP/TH) พร้อม health dot
   - Bar chart: requests per region (Recharts)
   - Doughnut chart: cache hit ratio
   - Table: recent CDN logs
   - Latency metric cards
3. ใช้ React Query poll ทุก 10 วินาที
4. เชื่อม route ใน App.tsx

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

## Task ที่ต้องทำ (ทำตามลำดับ)

### PHASE 4

Task: Phase 4C — Latency Tracking ✅

สิ่งที่ต้องทำ:
1. ตรวจสอบว่า Nginx log format มี $request_time หรือยัง (อ่าน cdn/edge/templates/ ก่อน)
2. เพิ่ม request_time ใน log format ถ้ายังไม่มี
3. ใน cdn_log_forward.py (จาก Task 4A) เพิ่มการ extract และ save latency_ms
4. เพิ่ม API: GET /api/cdn/latency?region=ALL&period=1h
   - return: {region: "SG", avg_ms: 45, p95_ms: 120, p99_ms: 200}
5. เพิ่ม Latency line chart ใน CDN.tsx page (ใช้ LineChart จาก Recharts)
   - X-axis: time, Y-axis: latency ms
   - แยก line ต่อ region

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

### PHASE 5
Task: Phase 5A — ModSecurity on All CDN Edge Nodes

สิ่งที่ต้องทำ:
1. อ่าน docker-compose-cdn.yml และ cdn/edge/templates/ ก่อน
2. เปลี่ยน base image ของ edge nodes จาก nginx:alpine เป็น owasp/modsecurity-crs:nginx
   (เหมือนกับ WAF หลักใน docker-compose.yml)
3. เพิ่ม modsecurity on ใน Nginx config ของทุก edge node
4. Mount OWASP CRS config และ custom rules ไปยังทุก edge
5. Mount shared custom-rules volume: modsecurity/custom-rules → /opt/custom-rules ใน edge node
6. ตั้ง PARANOIA=1, ANOMALY_INBOUND=10 เหมือน WAF หลัก
7. ตรวจสอบว่า health check, rate limit, TLS, cache ยังทำงานได้ปกติ

อ่านไฟล์เหล่านี้ก่อน:
- docker-compose.yml (WAF หลัก — เพื่อ copy pattern)
- cdn/docker-compose-cdn.yml
- cdn/edge/templates/

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

Task: Phase 5B — Custom Rule Sync to All Edge Nodes

สถานการณ์ปัจจุบัน:
- Dashboard สร้าง rule ผ่าน /api/rules/ → เขียนไฟล์ .conf ใน modsecurity/custom-rules/
- WAF หลักใช้ Volume mount ดูได้ rule ทันที
- แต่ edge nodes (SG/JP/TH) ยังไม่ได้รับ rule update

สิ่งที่ต้องทำ:
1. อ่าน dashboard/backend/services/rule_manager.py ก่อน
2. หลัง add/update/delete rule ใน RuleManager ให้เพิ่มการ reload Nginx ในทุก edge node:
   ["docker", "exec", "cdn-edge-sg", "nginx", "-s", "reload"]
   ["docker", "exec", "cdn-edge-jp", "nginx", "-s", "reload"]
   ["docker", "exec", "cdn-edge-th", "nginx", "-s", "reload"]
3. เพิ่ม method reload_all_edges() ใน RuleManager
4. ตรวจสอบว่า Volume mount ของ custom-rules ใน edge nodes ชี้ไปที่ modsecurity/custom-rules/ (shared volume)
5. เพิ่ม API: GET /api/cdn/rule-sync-status → แสดงว่า rule sync สำเร็จหรือไม่ต่อ node

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

Task: Phase 5C — Global Block (IP/CIDR) across All Edges

สิ่งที่ต้องทำ:
1. อ่าน dashboard/backend/api/rules.py และ rule_manager.py ก่อน
2. สร้าง GlobalBlockManager service:
   - เก็บ block list ใน DynamoDB table "waf_blocked_ips"
   - schema: {ip_cidr, reason, blocked_at, blocked_by}
3. เพิ่ม API endpoints:
   - POST /api/security/block → เพิ่ม IP/CIDR เข้า block list
   - DELETE /api/security/block/{ip} → ลบออก
   - GET /api/security/block → list ทั้งหมด
4. เมื่อ block list เปลี่ยนแปลง → generate nginx geo block config:
   - เขียนไฟล์ modsecurity/custom-rules/global-block.conf
   - ใช้ ModSecurity SecRule หรือ Nginx geo module
5. Reload Nginx ทุก node (WAF + ทุก edge)
6. สร้าง Global Block UI ใน React Dashboard:
   - หน้า GlobalBlock.tsx หรือ section ใน CDN.tsx
   - form: ใส่ IP/CIDR + reason → กด Block
   - table: รายการที่ block อยู่ พร้อมปุ่ม Unblock

ทำให้เสร็จสมบูรณ์พร้อมบอก path ทุกไฟล์ที่แก้ไข

## คำสั่ง
เริ่มทำ Task 4C เมื่อเสร็จรายงานผล แล้วถามฉันก่อนไปต่อ Task ถัดไป และบันทึกสถานะการทำงานลงในไฟล์ Task.md ด้วย 