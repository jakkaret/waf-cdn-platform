# 🚀 Phase 1 Dev Plan: Multi-Tenant Data Model & Origin Management

## 🎯 เป้าหมาย Phase 1
พัฒนาโครงสร้างพื้นฐานสำหรับ Multi-Tenant Architecture เพื่อให้ User สามารถลงทะเบียนและจัดการ **Web Origin** (เซิร์ฟเวอร์เว็บไซต์ปลายทาง) ของตนเองได้ พร้อมระบบตรวจสอบสิทธิ์การเป็นเจ้าของ (Ownership Verification) และหน้าจอจัดการ UI

---

## ⚙️ งานคนที่ A: Backend & Infrastructure

### 1.1 สร้าง DynamoDB Table `waf_origins`
- **ไฟล์ที่ต้องแก้ไข**: `dashboard/backend/services/dynamodb_service.py`
- **ข้อกำหนด**:
  - สร้างตาราง `waf_origins` บน DynamoDB (ถ้ายังไม่มี)
  - **Partition Key (`PK`)**: `id` (String UUID)
  - **Global Secondary Index (`GSI`)**: `admin_user_id-index`
    - Partition Key ของ GSI: `admin_user_id` (String UUID)
    - ProjectionType: `ALL`

```python
# snippet สำหรับเพิ่มเติมใน init_tables() หรือ script สร้าง table
def create_origins_table(self):
    try:
        table = self.dynamodb.create_table(
            TableName='waf_origins',
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'id', 'AttributeType': 'S'},
                {'AttributeName': 'admin_user_id', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[{
                'IndexName': 'admin_user_id-index',
                'KeySchema': [{'AttributeName': 'admin_user_id', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'},
                'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            }],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )
        table.wait_until_exists()
    except Exception as e:
        print("Table waf_origins already exists or error:", e)
```

---

### 1.2 เพิ่ม Multi-Tenant Ownership Middleware (`verify_origin_ownership`)
- **ไฟล์ที่ต้องแก้ไข**: `dashboard/backend/services/rbac.py`
- **หน้าที่**: ดึง `origin_id` จาก Path Parameter แล้วตรวจสอบว่า `admin_user_id` ของ Origin ตรงกับ `user_id` ของผู้ใช้ที่ล็อกอินผ่าน JWT หรือไม่ (ถ้าเป็น Global Admin ให้ข้ามการตรวจได้)

```python
async def verify_origin_ownership(
    origin_id: str,
    current_user: dict = Depends(get_current_user)
) -> dict:
    from services.origin_service import get_origin
    origin = get_origin(origin_id)
    if not origin:
        raise HTTPException(status_code=404, detail="Web Origin not found")
    
    # อนุญาตถ้าเป็น Super Admin หรือเป็น เจ้าของ Origin นี้
    if current_user.get("role") != "admin" and origin.get("admin_user_id") != current_user.get("user_id"):
        raise HTTPException(status_code=403, detail="Permission denied: You do not own this Origin")
    
    return origin
```

---

### 1.3 พัฒนา Origin Service Logic (`services/origin_service.py`)
- **ไฟล์ที่ต้องปรับปรุง**: `dashboard/backend/services/origin_service.py`
- **ฟังก์ชันที่ต้องมี**:
  1. `validate_ip(ip: str) -> bool`: ตรวจสอบรูปแบบ IPv4 ด้วย Regex `^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$`
  2. `create_origin(admin_user_id, label, ip, port) -> dict`: Validate IP/Port (1-65535), สร้าง UUID, บันทึกลง DynamoDB ตาราง `waf_origins` พร้อม `status: "pending"`, `health_status: "unknown"`
  3. `get_origins_for_user(admin_user_id: str) -> list`: Query ผ่าน GSI `admin_user_id-index`
  4. `get_origin(origin_id: str) -> dict`: ดึงรายละเอียดจาก DynamoDB โดยตรง
  5. `update_origin(origin_id, label, ip, port) -> bool`: อัปเดตข้อมูล และอัปเดต timestamp `updated_at`
  6. `delete_origin(origin_id: str) -> bool`: ลบข้อมูล Origin ออกจาก DynamoDB

---

### 1.4 พัฒนา Origins REST API Router (`api/origins.py`)
- **ไฟล์ที่ต้องปรับปรุง**: `dashboard/backend/api/origins.py`
- **Endpoints**:

| Method | Endpoint | Description | Auth Requirement |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/origins` | สร้าง Web Origin ใหม่ | `get_current_user` |
| `GET` | `/api/origins` | ดึงรายการ Origins ทั้งหมดของผู้ใช้ | `get_current_user` |
| `GET` | `/api/origins/{origin_id}` | ดึงข้อมูลรายละเอียดของ Origin | `verify_origin_ownership` |
| `PUT` | `/api/origins/{origin_id}` | แก้ไข Label, IP, Port | `verify_origin_ownership` |
| `DELETE` | `/api/origins/{origin_id}` | ลบ Origin | `verify_origin_ownership` |

---

## 💻 งานคนที่ B: Frontend & Integration

### 1.5 สร้าง API Client สำหรับ Origins (`src/api/origins.ts`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/frontend/src/api/origins.ts`
- **หน้าที่**: ห่อหุ้ม Axios HTTP Calls เพื่อเรียก Backend API

```typescript
import axios from 'axios';

export interface Origin {
  id: string;
  admin_user_id: string;
  label: string;
  ip: string;
  port: number;
  status: 'pending' | 'active' | 'suspended';
  health_status: 'online' | 'offline' | 'unknown';
  created_at: string;
  updated_at: string;
}

export const fetchOrigins = async (): Promise<Origin[]> => {
  const res = await axios.get('/api/origins');
  return res.data;
};

export const fetchOriginById = async (id: string): Promise<Origin> => {
  const res = await axios.get(`/api/origins/${id}`);
  return res.data;
};

export const createOrigin = async (data: { label: string; ip: string; port: number }): Promise<Origin> => {
  const res = await axios.post('/api/origins', data);
  return res.data;
};

export const updateOrigin = async (id: string, data: Partial<Origin>): Promise<void> => {
  await axios.put(`/api/origins/${id}`, data);
};

export const deleteOrigin = async (id: string): Promise<void> => {
  await axios.delete(`/api/origins/${id}`);
};
```

---

### 1.6 หน้าจอแสดงรายการ Origins (`src/pages/Origins.tsx`)
- **ไฟล์ที่ต้องสร้าง/ปรับปรุง**: `dashboard/frontend/src/pages/Origins.tsx`
- **องค์ประกอบหน้าจอ**:
  - ปุ่ม "+ Add New Origin" สำหรับเปิด Modal
  - ตาราง / Card Grid แสดง: Label, IP:Port, Status Badge (`pending`/`active`), Health Status (`online`/`offline`), Created Date
  - ปุ่ม Action: "Manage / View Details" (ลิงก์ไป `/origins/:id`) และ "Delete"

---

### 1.7 Modal ฟอร์มเพิ่ม Origin (`src/components/AddOriginModal.tsx`)
- **ไฟล์ที่ต้องสร้าง/ปรับปรุง**: `dashboard/frontend/src/components/AddOriginModal.tsx`
- **หน้าที่**:
  - Input: `Label` (ข้อความ เช่น "My Blog Server")
  - Input: `IP Address` (Validate IPv4 format)
  - Input: `Port` (Default 80, Number 1-65535)
  - ส่งข้อมูลผ่าน `createOrigin` API และแสดงผล Error message หาก IP/Port ไม่ถูกต้อง

---

### 1.8 หน้าแสดงรายละเอียด Origin (`src/pages/OriginDetail.tsx`)
- **ไฟล์ที่ต้องสร้าง/ปรับปรุง**: `dashboard/frontend/src/pages/OriginDetail.tsx`
- **หน้าที่**:
  - แสดงข้อมูลสรุปของ Origin (IP, Port, Health, Status)
  - แท็บ/Section สำหรับจัดการ Domain Names (เพื่อเตรียมพร้อมสำหรับ Phase 2)
  - แท็บ/Section สำหรับตั้งค่า WAF & Security Rules

---

## 🧪 การทดสอบและตรวจสอบความถูกต้อง (Verification)

```bash
# 1. ทดสอบ Backend API ด้วย pytest
cd dashboard/backend
python -m pytest test_origins_api.py -v

# 2. ทดสอบด้วย cURL
# สมัครสมาชิก / ล็อกอินเพื่อรับ Cookie JWT
curl -X POST http://localhost:8000/api/origins \
  -H "Content-Type: application/json" \
  -d '{"label": "Test DVWA Origin", "ip": "127.0.0.1", "port": 80}'

# ดึงรายการ Origins
curl http://localhost:8000/api/origins

# 3. ตรวจสอบหน้าจอ Frontend
cd dashboard/frontend
npm run dev
# เปิดเบราว์เซอร์ไปที่ http://localhost:5173/origins และทดสอบกดเพิ่ม Origin
```
