# 🏷️ Phase 2 Dev Plan: Domain Setup & Automated DNS Verification

## 🎯 เป้าหมาย Phase 2
พัฒนาระบบผูกโดเมน (Domain Binding) เข้ากับ Web Origin โดยผู้ใช้สามารถเพิ่มชื่อโดเมนของตนเอง (เช่น `app.example.com`) ระบบจะทำการสร้าง **Verification Token** และคำแนะนำการตั้งค่า DNS ให้ผู้ใช้ไปตั้งค่า CNAME หรือ TXT record ใน DNS Provider (เช่น Cloudflare / Route53) จากนั้นระบบจะรัน **DNS Verification Service** เพื่อตรวจสอบและยืนยันการตั้งค่าอัตโนมัติ

---

## ⚙️ งานคนที่ A: Backend & Infrastructure

### 2.1 สร้าง DynamoDB Table `waf_domains`
- **ไฟล์ที่ต้องแก้ไข**: `dashboard/backend/services/dynamodb_service.py`
- **ข้อกำหนด**:
  - สร้างตาราง `waf_domains` บน DynamoDB
  - **Partition Key (`PK`)**: `id` (String UUID)
  - **Global Secondary Index 1**: `origin_id-index` (PK: `origin_id`)
  - **Global Secondary Index 2**: `domain_name-index` (PK: `domain_name`)

```python
def create_domains_table(self):
    try:
        table = self.dynamodb.create_table(
            TableName='waf_domains',
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'id', 'AttributeType': 'S'},
                {'AttributeName': 'origin_id', 'AttributeType': 'S'},
                {'AttributeName': 'domain_name', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[
                {
                    'IndexName': 'origin_id-index',
                    'KeySchema': [{'AttributeName': 'origin_id', 'KeyType': 'HASH'}],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                },
                {
                    'IndexName': 'domain_name-index',
                    'KeySchema': [{'AttributeName': 'domain_name', 'KeyType': 'HASH'}],
                    'Projection': {'ProjectionType': 'ALL'},
                    'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                }
            ],
            ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
        )
        table.wait_until_exists()
    except Exception as e:
        print("Table waf_domains already exists or error:", e)
```

---

### 2.2 สร้าง DNS Verification Service (`services/dns_service.py`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/backend/services/dns_service.py`
- **Dependencies**: `dnspython` (ระบุใน `requirements.txt`)
- **หน้าที่**:
  1. `generate_verification_token() -> str`: สุ่ม String Token เช่น `waf-verify-a1b2c3d4e5f6`
  2. `check_cname_record(domain: str, expected_target: str) -> bool`: Query DNS `CNAME` record ของโดเมน
  3. `check_txt_record(domain: str, expected_token: str) -> bool`: Query DNS `TXT` record ที่ `_waf-challenge.<domain>`

```python
import dns.resolver
import uuid

def generate_token() -> str:
    return f"waf-challenge-{uuid.uuid4().hex[:12]}"

def verify_dns_records(domain_name: str, verification_token: str, cdn_target_domain: str = "cdn.yourwaf.com") -> dict:
    cname_valid = False
    txt_valid = False
    
    # 1. Check CNAME record
    try:
        answers = dns.resolver.resolve(domain_name, 'CNAME')
        for rdata in answers:
            if cdn_target_domain in str(rdata.target).rstrip('.'):
                cname_valid = True
                break
    except Exception as e:
        cname_valid = False

    # 2. Check TXT record (_waf-challenge.<domain_name>)
    txt_domain = f"_waf-challenge.{domain_name}"
    try:
        answers = dns.resolver.resolve(txt_domain, 'TXT')
        for rdata in answers:
            for txt_string in rdata.strings:
                if verification_token in txt_string.decode('utf-8'):
                    txt_valid = True
                    break
    except Exception as e:
        txt_valid = False

    verified = cname_valid or txt_valid
    return {
        "verified": verified,
        "cname_status": cname_valid,
        "txt_status": txt_valid
    }
```

---

### 2.3 พัฒนา Domain Service Logic (`services/domain_service.py`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/backend/services/domain_service.py`
- **ฟังก์ชันหลัก**:
  - `add_domain_to_origin(origin_id, domain_name)`: สุ่มสร้าง token, เช็คโดเมนซ้ำ, บันทึกลง DynamoDB พร้อม `dns_verified: False`
  - `get_domains_by_origin(origin_id)`: Query รายการโดเมนของ Origin
  - `delete_domain(domain_id)`: ลบโดเมน
  - `verify_domain(domain_id)`: ดึงข้อมูลโดเมน -> เรียก `dns_service.verify_dns_records` -> ถ้าผ่านให้อัปเดต `dns_verified = True`

---

### 2.4 พัฒนา Domain REST API Router (`api/domains.py`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/backend/api/domains.py`
- **Endpoints**:

| Method | Endpoint | Description | Auth Requirement |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/origins/{origin_id}/domains` | เพิ่ม Domain ใหม่ให้ Origin | `verify_origin_ownership` |
| `GET` | `/api/origins/{origin_id}/domains` | ดึงโดเมนทั้งหมดใน Origin นี้ | `verify_origin_ownership` |
| `DELETE` | `/api/domains/{domain_id}` | ลบ Domain ออกจาก Origin | Auth User |
| `POST` | `/api/domains/{domain_id}/verify` | สั่งตรวจสอบ DNS Verification | Auth User |

---

## 💻 งานคนที่ B: Frontend & Integration

### 2.5 สร้าง API Client สำหรับ Domains (`src/api/domains.ts`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/frontend/src/api/domains.ts`

```typescript
import axios from 'axios';

export interface Domain {
  id: string;
  origin_id: string;
  domain_name: string;
  verification_token: string;
  dns_verified: boolean;
  ssl_status: 'none' | 'pending' | 'active' | 'failed';
  created_at: string;
}

export const fetchDomainsByOrigin = async (originId: string): Promise<Domain[]> => {
  const res = await axios.get(`/api/origins/${originId}/domains`);
  return res.data;
};

export const addDomain = async (originId: string, domainName: string): Promise<Domain> => {
  const res = await axios.post(`/api/origins/${originId}/domains`, { domain_name: domainName });
  return res.data;
};

export const verifyDomain = async (domainId: string): Promise<{ verified: boolean; cname_status: boolean; txt_status: boolean }> => {
  const res = await axios.post(`/api/domains/${domainId}/verify`);
  return res.data;
};

export const deleteDomain = async (domainId: string): Promise<void> => {
  await axios.delete(`/api/domains/${domainId}`);
};
```

---

### 2.6 สร้าง Step-by-Step Domain Setup Wizard (`src/components/DomainSetupWizard.tsx`)
- **ไฟล์ที่ต้องสร้าง/ปรับปรุง**: `dashboard/frontend/src/components/DomainSetupWizard.tsx`
- **4 ขั้นตอน (Steps)**:
  1. **Step 1: Input Domain** — กรอกชื่อโดเมน (เช่น `shop.mycompany.com`)
  2. **Step 2: DNS Instructions** — แสดงค่า CNAME และ TXT Record ที่ต้องนำไปวางใน DNS Provider
  3. **Step 3: Verify DNS Button** — ปุ่มกดตรวจสอบสิทธิ์ พร้อมแสดง Spinner Loading
  4. **Step 4: Completion & SSL Waiting** — เมื่อผ่านการ Verify แสดงเครื่องหมายถูกสีเขียว ✅ พร้อมแจ้งเตือนเข้าสู่ขั้นตอนออก SSL Auto-HTTPS

---

### 2.7 UI แสดงคำแนะนำ DNS Record (`src/components/DnsInstructions.tsx`)
- **ไฟล์ที่ต้องสร้าง/ปรับปรุง**: `dashboard/frontend/src/components/DnsInstructions.tsx`
- **องค์ประกอบ**:
  - แสดงตาราง Record Type, Name, Value, TTL พร้อมปุ่ม **Copy to Clipboard**
  - **Option A (Recommended)**: CNAME Record -> `app.example.com` CNAME `cdn.yourwaf.com`
  - **Option B (Alternative)**: TXT Record -> `_waf-challenge.app.example.com` TXT `waf-challenge-abc123xyz`

---

## 🧪 การทดสอบและตรวจสอบความถูกต้อง (Verification)

```bash
# 1. ติดตั้ง dnspython ใน backend
pip install dnspython

# 2. ทดสอบเรียก API สั่งเพิ่มโดเมนและสั่ง Verify
curl -X POST http://localhost:8000/api/origins/<ORIGIN_ID>/domains \
  -H "Content-Type: application/json" \
  -d '{"domain_name": "demo.example.com"}'

# 3. ทดสอบกดสั่ง Verify ผ่าน API
curl -X POST http://localhost:8000/api/domains/<DOMAIN_ID>/verify
```
