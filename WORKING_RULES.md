# กฎและมาตรฐานการทำงาน (Standard Operating Procedures & Working Rules)
## โครงการ WAF, CDN & Virtual Patching Platform

> **วิสัยทัศน์หลัก:** เพิ่มความปลอดภัยระดับ Enterprise ให้กับเว็บเก่า/แก้โค้ดไม่ได้ (Legacy Origin) โดย **"ไม่แตะต้องโค้ด Origin แม้แต่บรรทัดเดียว"** และ **"ไม่กระทบผู้ใช้งานปกติและธุรกิจของลูกค้า"**

---

## 1. กฎเหล็กพื้นฐาน 4 ประการ (The 4 Non-Negotiable Rules)

1. **กฎข้อที่ 1: ห้ามแตะต้องโค้ดของ Origin เด็ดขาด (Zero-Touch Origin Principle)**
   * ทุกฟังก์ชันความปลอดภัย (WAF, TLS, Security Headers, Cookie Hardening, Rate Limiting, CAPTCHA, Pre-Login Gate) ต้องทำงานที่ **Edge Proxy / WAF Layer** เท่านั้น
   * เว็บลูกค้าต้องนั่งหลัง Tunnel โดยสมบูรณ์ ไม่มี Public IP ตรง และไม่ต้องลง Agent หรือแก้ Source Code ใดๆ
2. **กฎข้อที่ 2: ห้ามทำทราฟฟิกคนปกติพัง (Zero Customer Disruption)**
   * การเพิ่มความปลอดภัยต้องไม่สร้างความเสียหายต่อข้อมูล เช่น ห้ามดัก Challenge บนคำขอประเภท `POST` จนข้อมูลฟอร์มหาย และต้องไม่ส่ง HTML ไปพังระบบ AJAX / JSON API
   * หน้าเว็บสาธารณะทั่วไปต้องไม่ติด CAPTCHA และไม่กระทบต่อการเก็บข้อมูลของ Search Engine (SEO 100% Safe)
3. **กฎข้อที่ 3: ระบบบวมเป็นบาป (Anti-Bloat & Lean Architecture)**
   * ห้ามสร้าง Microservice ขนาดใหญ่ที่เกินความจำเป็น (เช่น ระบบ SMS OTP ที่ต้องมี Database ผู้ใช้และค่าบริการภายนอก)
   * ให้ใช้เทคโนโลยีที่น้ำหนักเบา คมชัด และ Scoped เฉพาะจุดเสี่ยง (เช่น Pre-Login Gate, OIDC, TOTP, หรือ Telegram Bot Approval)
4. **กฎข้อที่ 4: ความจริงใจต่อลูกค้า (Virtual Patching Reality)**
   * ต้องสื่อสารกับลูกค้าตามความจริงเสมอว่า: **Virtual Patching ≠ การแก้บั๊กในโค้ดถาวร**
   * เป็นการสร้างเกราะป้องกันการโจมตีจากภายนอกเพื่อซื้อเวลาและลดความเสี่ยง แต่ลูกค้ายังต้องมีแผนระยะยาวในการ Migrate หรือปรับปรุงระบบ

---

## 2. ขั้นตอนการ Rollout แบบปลอดภัย (Safe Rollout Protocol)

ทุกฟีเจอร์หรือ WAF Rule ใหม่ ห้ามเปิดใช้งานแบบบล็อกทันที ต้องผ่านกระบวนการ 4 ขั้นตอนนี้เสมอ:

```
[1. Silent / DetectionOnly] ──▶ [2. Tuning & Whitelist] ──▶ [3. Targeted Enforce] ──▶ [4. Full Dashboard Opt-in]
```

1. **ระดับที่ 1: เงียบ (Silent / DetectionOnly)**
   * เปิดระบบตรวจจับ บันทึก Log และคำนวณคะแนน แต่ **ห้ามบล็อกจริง**
   * ทราฟฟิกลูกค้าวิ่งผ่าน 100% ความเสี่ยงเป็นศูนย์
2. **ระดับที่ 2: จูน (Tuning & Telemetry)**
   * วิเคราะห์ Log จริงจาก ClickHouse เพื่อตรวจหา False Positive (การตรวจจับที่ผิดพลาด)
   * เพิ่มข้อยกเว้น (Whitelist / Exception Rules) ให้กับพฤติกรรมเฉพาะของเว็บลูกค้านั้นๆ
3. **ระดับที่ 3: เปิดเฉพาะตัวที่มั่นใจสูง (Targeted Enforcement)**
   * สับสวิตช์เป็น Block เฉพาะ Signature ที่มีอัตราความแม่นยำสูงชัดเจน (เช่น SQLi, RCE, Path Traversal แน่นอน)
   * ในส่วนของบอท ให้เปิดดักเฉพาะทราฟฟิกที่มาจาก Datacenter ASNs (AWS, DigitalOcean, Hetzner) หรือ Tor Exit Nodes ก่อน
4. **ระดับที่ 4: ให้ลูกค้าเป็นผู้ควบคุม (Tenant Dashboard Control)**
   * ทำเป็นตัวเลือกเปิด/ปิด (Toggle) ใน Dashboard ให้ลูกค้าเป็นคนตัดสินใจเปิดใช้ตามความพร้อมของแต่ละ Origin

---

## 3. กฎด้านความปลอดภัยของระบบและการปฏิบัติการบน VPS (Operational Rules)

1. **VPS คือ Single Source of Truth:**
   * เซิร์ฟเวอร์จริง (`178.104.53.123`) คือสภาพแวดล้อมหลักในการรันระบบและเก็บบันทึกไฟล์ล่าสุดเสมอ
2. **สำรองข้อมูลก่อนแตะต้องโครงสร้างสำคัญ (Backup First Policy):**
   * ก่อนทำการแก้ไขไฟล์ระบบ, อัปเกรด Docker Compose, หรือแก้ไข Database Schema จะต้องทำการ Sync สำรองข้อมูลไปยังโฟลเดอร์ Backup เสมอ:
     ```bash
     rsync -a --delete /root/waf_project/ /root/waf_project_backup_safe/
     ```
3. **การแก้ไขคอนฟิกต้องไม่ทำให้เว็บดับ (Zero-Downtime Reload):**
   * การอัปเดตคอนฟิกของ Nginx หรือ Caddy ต้องทดสอบ語法 (Syntax Test) และสั่ง Reload แบบ Graceful เสมอ:
     ```bash
     # สำหรับ Nginx
     nginx -t && nginx -s reload
     # สำหรับ Caddy
     caddy reload --config /etc/caddy/Caddyfile
     ```
4. **นโยบายระบบสำรองล้มเหลวแบบเปิด (Fail-Open Policy):**
   * หากเซอร์วิสภายนอก (เช่น Cloudflare Turnstile API) ขัดข้องหรือ Timeout ระบบ Proxy ต้องยอม **ปล่อยทราฟฟิกผ่านไปยัง WAF ตามปกติ (Fail-Open)** ห้ามทำให้เว็บลูกค้าเข้าไม่ได้เด็ดขาด
   * ต้องมีตัวแปรสวิตช์ฉุกเฉิน (Kill-Switch) เช่น `WAF_CAPTCHA_ENABLED=false` ที่สั่งปิดการทำงานได้ทันที

---

## 4. มาตรฐานการพัฒนาโค้ด (Coding & Architectural Standards)

1. **การจัดการสิทธิ์และคุกกี้ (Cookie & Session Hardening):**
   * คุกกี้ที่ออกจาก Proxy ต้องมี Flag: `Secure; HttpOnly; SameSite=Lax` เสมอ
   * คุกกี้ Clearance (`waf_clearance`) ต้องใช้การคำนวณ HMAC-SHA256 ที่ผูกกับ:
     $$\text{HMAC}(\text{Subnet\_IP (/24)} + \text{UserAgent} + \text{Host} + \text{ExpireTimestamp}, \text{Secret})$$
   * **ต้องผูก Subnet `/24`** เพื่อป้องกันผู้ใช้เน็ตมือถือ (4G/5G CGNAT) ติดลูป Challenge
   * **ต้องผูก Host (Domain)** เพื่อป้องกันการนำคุกกี้ที่แก้ผ่านจากเว็บ A ไปใช้โจมตีเว็บ B (Multi-Tenant Isolation)
2. **การป้องกัน Deadlock ในระบบ:**
   * เส้นทาง Endpoint ของระบบตรวจสอบ เช่น `/cdn-cgi/*` และ `/healthz` **ต้องได้รับการยกเว้นจากการตรวจจับของ WAF 100% (Exempt Safe Zone)** เสมอ
3. **การปกปิดข้อมูลระบบเดิม (Information Disclosure Masking):**
   * ต้อง Strip Header ข้อมูลเวอร์ชันเซิร์ฟเวอร์ (`Server`, `X-Powered-By`) ทิ้งเสมอ
   * ต้องดักจับ Error 500 / 502 จาก Origin แล้วแทนที่ด้วยหน้ากระดาษ Error กลาง เพื่อซ่อน Database Stack Trace จากแฮกเกอร์

---

## 5. แผนผังลำดับความสำคัญในการทำงาน (Feature Priority Matrix)

| ระดับความสำคัญ | ฟังก์ชันงาน | ผลกระทบต่อโค้ด Origin | สถานะปัจจุบัน |
| :---: | :--- | :---: | :---: |
| **P0 (ด่วนที่สุด)** | ปิด Bypass Port 8080 (บังคับผ่าน Tunnel 100%) | ศูนย์ (0%) | รอดำเนินการ |
| **P0 (ด่วนที่สุด)** | Backup โฟลเดอร์ระบบให้ปลอดภัย | ศูนย์ (0%) | ✅ สำเร็จแล้ว |
| **P1 (จำเป็นมาก)** | Security Headers + Cookie Hardening (Secure/HttpOnly) | ศูนย์ (0%) | ✅ Live บางส่วน |
| **P1 (จำเป็นมาก)** | Upload Shield (ห้ามรันโค้ดในโฟลเดอร์อัปโหลด) | ศูนย์ (0%) | แพลนพร้อม |
| **P2 (คุ้มครองสูง)** | Pre-Login Gate (Turnstile Challenge ที่หน้า Login) | ศูนย์ (0%) | แพลนเสร็จสมบูรณ์ |
| **P2 (คุ้มครองสูง)** | Sensitive Files Blacklist (`.git`, `.env`, `.sql`) | ศูนย์ (0%) | แพลนพร้อม |
| **P3 (ฟีเจอร์เสริม)** | Dashboard UI Toggle สำหรับเปิด/ปิดฟังก์ชัน | ศูนย์ (0%) | แพลนพร้อม |
| **P3 (ฟีเจอร์เสริม)** | Weekly OSV Vulnerability Scanner Feed | ศูนย์ (0%) | การ์ดเสริม |
| **P4 (Option เฉพาะ)** | Scoped Admin MFA / 2FA ผ่าน Google/Telegram | ศูนย์ (0%) | รอตกลงสเปก |

---

*เอกสารฉบับนี้ใช้เป็นข้อตกลงและกรอบการทำงานร่วมกันของทีมพัฒนา WAF & CDN Project ทุกคน*
