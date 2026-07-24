# 🛡️ WAF & Multi-Tenant CDN Platform — Comprehensive Dev Plan (Phase 1 - 5)

ตารางแผนการพัฒนา (Dev Plan) นี้จัดทำขึ้นตามข้อกำหนดสถาปัตยกรรมและรายละเอียดใน [Plan/index.html](file:///Ubuntu/home/chirachot/seminar/waf_project/Plan/index.html) (https://waf-cdn-demo-app.surge.sh/devplan) และ `DESIGN.md` ของโปรเจกต์ **WAF Automated**

แผนงานนี้ถูกออกแบบมาให้อ่านง่าย ชัดเจน ละเอียดในระดับ **Prompt / Instruction สำหรับ AI Vibe Coding** (เช่น Gemini / Claude / Cursor / Copilot) เพื่อให้สามารถหยิบแต่ละไฟล์ไปสั่งสั่งพัฒนาและรันระบบได้สมบูรณ์ 100%

---

## 📁 สารบัญไฟล์ในโฟลเดอร์ `Dev-Plan/`

| ไฟล์ | หัวข้อ | รายละเอียด |
| :--- | :--- | :--- |
| 📘 **[00-MASTER-DEV-PLAN.md](file:///Ubuntu/home/chirachot/seminar/waf_project/Dev-Plan/00-MASTER-DEV-PLAN.md)** | **Master Architecture & Overview** | ภาพรวมสถาปัตยกรรม, Data Model, API Specs, Network Flow, Environment & Roles |
| 🚀 **[PHASE-1-ORIGIN-FOUNDATION.md](file:///Ubuntu/home/chirachot/seminar/waf_project/Dev-Plan/PHASE-1-ORIGIN-FOUNDATION.md)** | **Phase 1: Multi-tenant & Origin Management** | DynamoDB Tables, RBAC Middleware, Origin CRUD API, Origins UI & Modal |
| 🏷️ **[PHASE-2-DOMAIN-DNS.md](file:///Ubuntu/home/chirachot/seminar/waf_project/Dev-Plan/PHASE-2-DOMAIN-DNS.md)** | **Phase 2: Domain Setup & DNS Verification** | Domain CRUD API, DNS Challenge Generator, Verification Worker, Setup Wizard UI |
| 🔒 **[PHASE-3-SSL-AUTO-HTTPS.md](file:///Ubuntu/home/chirachot/seminar/waf_project/Dev-Plan/PHASE-3-SSL-AUTO-HTTPS.md)** | **Phase 3: Auto-HTTPS & Nginx Config Gen** | Certbot/ACME Provisioner, Jinja2 Nginx Config Gen, Auto-Renew Cron, SSL UI |
| 🏥 **[PHASE-4-HEALTH-PER-ORIGIN-WAF.md](file:///Ubuntu/home/chirachot/seminar/waf_project/Dev-Plan/PHASE-4-HEALTH-PER-ORIGIN-WAF.md)** | **Phase 4: Origin Health & Per-Origin WAF** | Origin Health Check Worker, Telegram Alert, Per-Origin WAF Rules, Stats Filtering |
| ⚡ **[PHASE-5-MULTI-NODE-CDN-INTEGRATION.md](file:///Ubuntu/home/chirachot/seminar/waf_project/Dev-Plan/PHASE-5-MULTI-NODE-CDN-INTEGRATION.md)** | **Phase 5: Multi-Region CDN & GeoDNS Integration** | SG/JP/TH Edge Nodes, GeoDNS Routing, Cache Purge API, Global IP Sync & Test Suite |

---

## 👥 ภาพรวมการแบ่งงาน (Work Division: Person A vs Person B)

```
+------------------------------------+------------------------------------+
|  ⚙️ คนที่ A (Backend & Infra)       |  💻 คนที่ B (Frontend & Integration) |
+------------------------------------+------------------------------------+
| Phase 1: DynamoDB & Origin API     | Phase 1: Origins List & Modal UI   |
| Phase 2: Domain API & DNS Check    | Phase 2: Domain Wizard & DNS UI    |
| Phase 3: Certbot & Nginx Gen       | Phase 3: SSL Status & Progress UI  |
| Phase 4: Health Check & WAF API    | Phase 4: Per-origin Stats & Badges |
| Phase 5: Multi-Region CDN Stack    | Phase 5: CDN Management Dashboard  |
+------------------------------------+------------------------------------+
```

---

## ⏱️ Timeline โดยประมาณ
- **Phase 1**: ~3-4 วัน
- **Phase 2**: ~3-4 วัน
- **Phase 3**: ~2-3 วัน
- **Phase 4**: ~2-3 วัน
- **Phase 5**: ~3-4 วัน
- **รวมระยะเวลาพัฒนา**: ~12-18 วัน (หากทำควบคู่กัน 2 คน จะใช้เวลาเพียง ~10-14 วัน)
