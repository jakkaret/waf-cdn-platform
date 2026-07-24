# 🏥 Phase 4 Dev Plan: Origin Health Checks & Per-Origin WAF Rules

## 🎯 เป้าหมาย Phase 4
พัฒนาระบบตรวจสอบสุขภาพและความพร้อมใช้งานของ Web Origin (Active Origin Health Checking) แบบอัตโนมัติ โดยมี Background Worker คอย Ping ไปยัง IP:Port ของแต่ละ Origin ทุกๆ 60 วินาที หากพบ Origin ล่ม (Offline) ระบบจะทำการส่งการแจ้งเตือนไปยัง **Telegram Bot** ทันที พร้อมทั้งพัฒนาระบบกำหนดค่า **ModSecurity WAF Rules แบบแยกราย Origin** (Per-Origin WAF Configuration) และการกรองสถิติบน Dashboard แยกตาม Origin

---

## ⚙️ งานคนที่ A: Backend & Infrastructure

### 4.1 สร้าง Origin Health Check Worker (`services/health_check_worker.py`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/backend/services/health_check_worker.py`
- **หน้าที่**:
  1. ดึงรายการ Origins ทั้งหมดจากตาราง `waf_origins` ใน DynamoDB
  2. ใช้ Async HTTP / Socket Ping ตรวจสอบ IP:Port ของแต่ละ Origin ทุกๆ 60 วินาที (Timeout: 5 วินาที)
  3. เปรียบเทียบสถานะเดิม:
     - หากเปลี่ยนจาก `online` -> `offline`: อัปเดต `health_status = "offline"` ใน DB และส่ง Telegram Alert
     - หากเปลี่ยนจาก `offline` -> `online`: อัปเดต `health_status = "online"` ใน DB และส่ง Telegram Recovery Notification

```python
import asyncio
import socket
import aiohttp
from datetime import datetime
from services.dynamodb_service import DynamoDBService

db = DynamoDBService()

async def check_origin_health(origin: dict) -> str:
    ip = origin.get("ip")
    port = origin.get("port", 80)
    
    # Socket Connection Check
    try:
        loop = asyncio.get_event_loop()
        conn = loop.create_connection(lambda: asyncio.Protocol(), ip, port)
        await asyncio.wait_for(conn, timeout=5.0)
        return "online"
    except Exception:
        return "offline"

async def run_health_check_loop():
    while True:
        origins = db.scan_all_origins() # Scan or Query active origins
        for origin in origins:
            new_status = await check_origin_health(origin)
            old_status = origin.get("health_status", "unknown")
            
            if new_status != old_status:
                # Update DynamoDB
                db.update_origin(origin["id"], {
                    "health_status": new_status,
                    "last_health_check": datetime.now().isoformat() + "Z"
                })
                # Trigger Telegram Alert
                from services.telegram_listener import send_telegram_alert
                msg = f"🚨 *WAF Alert: Web Origin Down!*\n\n" \
                      f"*Origin:* {origin.get('label')}\n" \
                      f"*IP:Port:* {origin.get('ip')}:{origin.get('port')}\n" \
                      f"*Status:* {old_status} -> {new_status}"
                send_telegram_alert(msg)
                
        await asyncio.sleep(60) # Repeat every 60s
```

---

### 4.2 พัฒนาระบบ Per-Origin WAF Configuration
- **ไฟล์ที่ต้องปรับปรุง**:
  - `dashboard/backend/services/rule_manager.py`
  - `dashboard/backend/api/rules.py`
- **ข้อกำหนด**:
  - ปัจจุบัน WAF Rules ถูกใช้ร่วมกันทั่วทั้งระบบ (Global Rules) ใน Phase 4 ต้องเพิ่มฟิลด์ `origin_id` ใน WAF Rule เพื่อระบุว่า Rule นี้บังคับใช้กับ Origin ใด
  - เพิ่ม Endpoint `GET /api/origins/{origin_id}/rules` และ `POST /api/origins/{origin_id}/rules`
  - สั่ง Write ไฟล์ Rule แยกเป็น `/etc/modsecurity/custom-rules/origin_{origin_id}.conf`

---

### 4.3 กรอง Log และ Statistics แยกตาม Origin ID
- **ไฟล์ที่ต้องปรับปรุง**: `dashboard/backend/services/dynamodb_service.py` และ `api/alerts.py`
- **ข้อกำหนด**:
  - อัปเดต `log_forward_worker` ให้ใส่ฟิลด์ `origin_id` ลงใน Log Item ของ DynamoDB โดย match จาก `Host` header ของ Request
  - เพิ่ม Parameter `origin_id` ใน API `GET /api/stats` และ `GET /api/logs` เพื่อรองรับการกรองข้อมูลราย Origin

---

## 💻 งานคนที่ B: Frontend & Integration

### 4.4 UI Badge แสดงสุขภาพ Origin (`src/components/HealthBadge.tsx`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/frontend/src/components/HealthBadge.tsx`
- **หน้าที่**: แสดงสัญลักษณ์สถานะสุขภาพ:
  - 🟢 `Online` (Pulse Green Animation)
  - 🔴 `Offline` (Red Alert Animation)
  - ⚪ `Unknown`
- แสดงบน Sidebar ข้างชื่อ Origin และในตาราง Origins List

---

### 4.5 เพิ่ม Origin Filter บน Dashboard (`src/pages/Dashboard.tsx`)
- **ไฟล์ที่ต้องปรับปรุง**: `dashboard/frontend/src/pages/Dashboard.tsx`
- **หน้าที่**:
  - เพิ่ม Dropdown Select บนหัวหน้า Dashboard: "All Origins" | "Origin A" | "Origin B"
  - เมื่อผู้ใช้เปลี่ยนค่า Dropdown ให้ส่ง `origin_id` ไปกับการดึง Stats & Charts (Total Requests, Blocked Attacks, Cache Ratio) เพื่อแสดงสถิติตาม Origin ที่เลือก

---

### 4.6 ปรับแต่ง Rules Management Page ให้รองรับ Scope แยก Origin (`src/pages/Rules.tsx`)
- **ไฟล์ที่ต้องปรับปรุง**: `dashboard/frontend/src/pages/Rules.tsx`
- **หน้าที่**:
  - เพิ่มตัวเลือก Scope เมื่อสร้าง Custom Rule: "Apply to All Origins (Global)" หรือ "Apply to Specific Origin"
  - แสดงผล Tag ระบุ Origin บนการ์ดแต่ละ Rule

---

## 🧪 การทดสอบและตรวจสอบความถูกต้อง (Verification)

```bash
# 1. ทดสอบจำลองการปิด Target Origin Service เพื่อให้ Health Check จับได้
docker stop waf_project-dvwa-1

# 2. ตรวจสอบ Log ของ Health Check Worker
# ควรขึ้นว่า Status changed: online -> offline และส่งข้อความเข้า Telegram
python -m services.health_check_worker

# 3. เปิด Target Origin กลับมา
docker start waf_project-dvwa-1
# ควรขึ้นว่า Status changed: offline -> online
```
