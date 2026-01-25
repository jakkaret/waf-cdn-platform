🚀 การติดตั้ง
1️⃣ Clone Repository
bashgit clone <repository-url>
cd waf_project
2️⃣ ติดตั้ง Python Dependencies
bashcd dashboard/backend
pip3 install -r requirements.txt
หรือใช้ Virtual Environment (แนะนำ):
bashcd dashboard/backend
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# หรือ venv\Scripts\activate  # Windows
pip install -r requirements.txt
3️⃣ เริ่มต้น WAF Container
bashcd waf_project
docker-compose up -d
ตรวจสอบสถานะ:
bashdocker-compose ps
4️⃣ เริ่มต้น Dashboard
bashcd dashboard/backend
python3 main.py

📖 การใช้งาน
เข้าใช้งานระบบ
ServiceURLคำอธิบายDashboardhttp://localhost:8000หน้าแรก OverviewAPI Docshttp://localhost:8000/docsSwagger UIWAFhttp://localhost:8080ModSecurity WAFDVWAhttp://localhost:8080Vulnerable Web App (ทดสอบ)
