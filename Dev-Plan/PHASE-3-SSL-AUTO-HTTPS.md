# 🔒 Phase 3 Dev Plan: SSL / Auto-HTTPS & Nginx Config Generator

## 🎯 เป้าหมาย Phase 3
พัฒนาระบบออกใบรับรองความปลอดภัย **SSL/TLS Certificate** อัตโนมัติด้วย Let's Encrypt / Certbot เมื่อโดเมนผ่านการตรวจสอบ DNS Verified เรียบร้อยแล้ว พร้อมระบบ **Nginx Config Generator** ที่ใช้ Jinja2 Template ในการ render Server Block สำหรับ Reverse Proxy ไปยัง Web Origin แบบายโดเมน และระบบ **Auto-Renew Cron Worker** เพื่อต่ออายุใบรับรองล่วงหน้า 30 วันก่อนหมดอายุ

---

## ⚙️ งานคนที่ A: Backend & Infrastructure

### 3.1 สร้าง DynamoDB Table `waf_ssl_certs`
- **ไฟล์ที่ต้องแก้ไข**: `dashboard/backend/services/dynamodb_service.py`
- **ข้อกำหนด**:
  - **Partition Key (`PK`)**: `id` (String UUID)
  - **Global Secondary Index**: `domain_id-index` (PK: `domain_id`)

---

### 3.2 สร้าง SSL Provisioning Service (`services/ssl_service.py`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/backend/services/ssl_service.py`
- **หน้าที่**:
  1. เรียกใช้คำสั่ง `certbot certonly --webroot` หรือ `--standalone` เพื่อขอ Certificate จาก Let's Encrypt
  2. ในสภาพแวดล้อม Development/Local: รองรับการ Fallback ไปสร้าง Self-Signed Certificate ผ่าน `openssl` หากเรียก Let's Encrypt ไม่สำเร็จ
  3. บันทึกเส้นทางไฟล์ `cert_path` (`fullchain.pem`), `key_path` (`privkey.pem`) และวันหมดอายุ `expires_at` ลงใน DynamoDB ตาราง `waf_ssl_certs`

```python
import subprocess
import os
from datetime import datetime, timedelta

def provision_ssl_certificate(domain_name: str) -> dict:
    cert_dir = f"/etc/letsencrypt/live/{domain_name}"
    fullchain = f"{cert_dir}/fullchain.pem"
    privkey = f"{cert_dir}/privkey.pem"
    
    # ถ้าเปิดโหมด DEV หรือไม่มี certbot ให้สร้าง self-signed แทนเพื่อทดสอบ
    if os.getenv("ENV") == "development" or not os.path.exists("/usr/bin/certbot"):
        os.makedirs(cert_dir, exist_ok=True)
        if not os.path.exists(fullchain):
            cmd = f"openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout {privkey} -out {fullchain} -subj '/CN={domain_name}'"
            subprocess.run(cmd, shell=True, check=True)
        expires_at = (datetime.now() + timedelta(days=365)).isoformat() + "Z"
        issuer = "Development Self-Signed CA"
    else:
        # โหมด Production: เรียก Certbot
        cmd = f"certbot certonly --webroot -w /var/www/certbot -d {domain_name} --non-interactive --agree-tos --register-unsafely-without-email"
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if res.returncode != 0:
            raise Exception(f"Certbot failed: {res.stderr}")
        expires_at = (datetime.now() + timedelta(days=90)).isoformat() + "Z"
        issuer = "Let's Encrypt Authority X3"

    return {
        "domain_name": domain_name,
        "cert_path": fullchain,
        "key_path": privkey,
        "issuer": issuer,
        "expires_at": expires_at
    }
```

---

### 3.3 สร้าง Nginx Dynamic Config Generator (`services/nginx_config_service.py`)
- **ไฟล์ที่ต้องสร้าง**:
  - Template: `dashboard/backend/templates/nginx/origin.conf.j2`
  - Generator Service: `dashboard/backend/services/nginx_config_service.py`
- **หน้าที่**:
  - อ่านข้อมูล Origin IP:Port, Domain Name, และ SSL Cert Paths
  - Render เป็นไฟล์ Nginx config ในโฟลเดอร์ `/etc/nginx/conf.d/origin_{origin_id}.conf`
  - รันคำสั่ง `nginx -t` เพื่อตรวจสอบ Syntax ก่อนสั่ง `nginx -s reload`

```jinja2
# templates/nginx/origin.conf.j2
server {
    listen 80;
    server_name {{ domain_name }};
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name {{ domain_name }};

    ssl_certificate {{ ssl_cert_path }};
    ssl_certificate_key {{ ssl_key_path }};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://{{ origin_ip }}:{{ origin_port }};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```python
# services/nginx_config_service.py
from jinja2 import Environment, FileSystemLoader
import subprocess
import os

env = Environment(loader=FileSystemLoader("templates/nginx"))

def generate_and_apply_nginx_config(origin_id: str, domain_name: str, origin_ip: str, origin_port: int, ssl_cert_path: str, ssl_key_path: str) -> bool:
    template = env.get_template("origin.conf.j2")
    rendered_config = template.render(
        domain_name=domain_name,
        origin_ip=origin_ip,
        origin_port=origin_port,
        ssl_cert_path=ssl_cert_path,
        ssl_key_path=ssl_key_path
    )
    
    target_path = f"/etc/nginx/conf.d/origin_{origin_id}.conf"
    with open(target_path, "w") as f:
        f.write(rendered_config)
        
    # Verify Nginx Config
    test_res = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test_res.returncode != 0:
        print("Nginx config error:", test_res.stderr)
        return False
        
    # Reload Nginx
    subprocess.run(["nginx", "-s", "reload"])
    return True
```

---

### 3.4 สร้าง SSL Auto-Renew Background Worker (`services/ssl_renew_worker.py`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/backend/services/ssl_renew_worker.py`
- **หน้าที่**: รันในรูปแบบ Background Loop/Cron Job ตรวจสอบใบรับรอง SSL ทุกๆ 24 ชั่วโมง หากพบ Certificate ที่มี `expires_at` น้อยกว่า 30 วัน จะสั่ง `certbot renew` และสั่ง `nginx -s reload` อัตโนมัติ

---

## 💻 งานคนที่ B: Frontend & Integration

### 3.5 UI แสดงสถานะ SSL Certificate (`src/components/SslStatusCard.tsx`)
- **ไฟล์ที่ต้องสร้าง/ปรับปรุง**: `dashboard/frontend/src/components/SslStatusCard.tsx`
- **รายละเอียด**:
  - แสดง SSL Status Badge: 🟢 `Active (HTTPS Protected)` | 🟡 `Provisioning...` | 🔴 `Failed`
  - แสดง Issuer (เช่น "Let's Encrypt Authority X3"), วันหมดอายุ (Expiration Date) และ Expiration Countdown
  - Toggle Switch: "Auto Renew Certificate" (เปิด/ปิด)

---

### 3.6 UI Real-Time Provisioning Progress Bar (`src/components/ProvisioningStatus.tsx`)
- **ไฟล์ที่ต้องสร้าง**: `dashboard/frontend/src/components/ProvisioningStatus.tsx`
- **รายละเอียด**:
  - แสดงแถบ Progress Bar 3 ขั้นตอน:
    1. `DNS Verification Completed` ✅
    2. `Provisioning SSL Certificate` 🔄
    3. `Deploying Nginx Host & Active HTTPS` 🚀
  - ใช้ Polling ทุกๆ 5 วินาทีในการดึงสถานะล่าสุดจาก API

---

## 🧪 การทดสอบและตรวจสอบความถูกต้อง (Verification)

```bash
# 1. ทดสอบสร้าง SSL Certificate จำลอง และ รัน Nginx Config Generator
python -c "
from services.ssl_service import provision_ssl_certificate
from services.nginx_config_service import generate_and_apply_nginx_config
res = provision_ssl_certificate('test.local')
print('SSL Created:', res)
"

# 2. ตรวจสอบไฟล์ Nginx Config ที่ถูก Render
cat /etc/nginx/conf.d/origin_*.conf

# 3. ทดสอบยิง HTTPS เข้าหา Nginx Proxy
curl -k -I https://localhost/
```
