# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

ผู้ใช้หลักคือผู้ดูแลระบบความปลอดภัย แอดมินระบบ หรือผู้ปฏิบัติงานที่ต้องติดตามและควบคุม WAF, CDN edge, origin servers, access controls, alerts, logs, และ ML-assisted security workflows จาก dashboard เดียว

บริบทของโปรเจกต์ยังรวมการสาธิต/ประเมินผลงาน seminar หรือ lab environment ด้วย ผู้ใช้กลุ่มนี้ต้องเห็นระบบที่รันได้จริง ตรวจสอบ flow ได้ และเข้าใจหลักฐานการทำงานของ WAF/CDN/ML โดยไม่ต้องอ่าน backend code ทั้งหมด

## Product Purpose

ระบบนี้คือ WAF + CDN management dashboard สำหรับจัดการและติดตาม Web Application Firewall ที่ใช้ ModSecurity CRS, reverse proxy/CDN edge infrastructure, authentication/roles, Telegram alerts, traffic logs, custom rules, IP access controls, rate limits, origins/domains, system settings, และ ML-assisted anomaly/rule workflows

ความสำเร็จของ product คือผู้ใช้สามารถเห็นสถานะความปลอดภัยแบบรวมศูนย์ เข้าใจว่า traffic ถูก allow/block เพราะอะไร จัดการ rule หรือ policy ได้อย่างควบคุมสิทธิ์ รับ alert เมื่อมีเหตุการณ์สำคัญ และทดสอบ/อนุมัติ rule จาก ML workflow ได้อย่างตรวจสอบย้อนกลับ

## Positioning

ระบบนี้เป็น **Seminar / Lab / Demo system** สำหรับแสดงผลงานและสาธิตเท่านั้น ไม่ได้มุ่งเน้นการใช้งาน production จริง แต่ออกแบบมาให้รันได้จริง ตรวจสอบ flow ได้ และเข้าใจหลักฐานการทำงานของ WAF/CDN/ML โดยไม่ต้องอ่าน backend code ทั้งหมด

จุดยืนทางเทคนิคคือ control plane แบบรวมศูนย์สำหรับ WAF/CDN ที่เชื่อม real-time security monitoring, edge delivery visibility, policy management, Telegram alerting, และ ML-assisted threat detection เข้าด้วยกัน พร้อม workflow สำหรับสร้างหรือเสนอ ModSecurity SecRule จาก payload/anomaly evidence

ระบบนี้ต่างจาก dashboard monitoring ทั่วไปตรงที่ไม่ได้แค่แสดงกราฟ แต่ผูกการสังเกตเห็นภัยคุกคามเข้ากับการจัดการ rule, access control, origin/domain setup, CDN operations, และ ML rule approval ในพื้นที่เดียวกัน

## Operating Context

โปรเจกต์ทำงานเป็น web dashboard โดยมี React/Vite frontend อยู่ที่ `dashboard/frontend` และ FastAPI backend อยู่ที่ `dashboard/backend`

Infrastructure หลักรันผ่าน Docker Compose โดยมี ModSecurity CRS บน Nginx WAF, DVWA target สำหรับทดสอบ, Caddy SSL termination, Redis, ClickHouse, และ control API สำหรับ CDN/WAF operations

Dashboard รองรับ public auth flow (`/login`, `/register`, `/oauth-success`) และ protected app routes เช่น Security Dashboard, Traffic Logs, Origin Servers, WAF Rules, IP Access List, Rate Limiting, ML Anomaly Rules, AI Security Analyst, Alert Center, CDN Edge Nodes, Access Control, และ System Settings

Backend ให้ API สำหรับ auth, logs, rules, limiter, alerts, CDN, ML, ML rules, analytics, origins, domains, IP rules, rate limits, settings, และ AI summary รวมถึง serve React build ใน production

ML workflow ใช้ Random Forest + Isolation Forest hybrid approach สำหรับ classify/analyze web payloads และช่วยสร้าง/เสนอ WAF rules โดยมี dataset/model artifacts อยู่ใน `ml/`

## Capabilities and Constraints

Confirmed capabilities:

- real-time/protected WAF log monitoring with filtering, pagination, and status/severity/method dimensions
- ModSecurity custom rule management
- IP access list management
- rate limiting management backed by Redis-related infrastructure
- origin server and domain management, including DNS/SSL-oriented provisioning concepts
- CDN edge node, cache, latency, logs, purge, and sync-oriented monitoring/operations
- Telegram alert pairing and alert delivery workflow
- role-based access for admin/viewer users
- ML payload simulation, anomaly scoring, suggested SecRule generation, and pending ML rule review workflows
- system settings and AI/security summary surfaces

Technical constraints and durable implementation facts:

- Frontend stack: React 18, Vite, TypeScript, React Router, TanStack Query, Zustand, Axios, Recharts, lucide-react, TailwindCSS, react-hot-toast
- Backend stack: FastAPI, Uvicorn, python-dotenv, boto3, python-jose, argon2-cffi, slowapi, Redis client, HTTP clients, email validation
- WAF stack: OWASP ModSecurity CRS with Nginx, custom rules mounted from `modsecurity/custom-rules`
- Runtime/infrastructure: Docker Compose lab environment, Caddy, Redis, ClickHouse, control API, DVWA test target
- Data services include ClickHouse for logs/analytics paths and DynamoDB/local-style data flows for auth/alerts/origins depending on environment setup
- Strict Backend Guard: ห้ามแก้ไขโค้ด Python/FastAPI backend, database schemas, หรือ ClickHouse queries ยกเว้นได้รับคำสั่งเฉพาะ เพื่อความเสถียรของระบบ
- Canonical Timezone: ข้อมูล Timestamp ด้านความปลอดภัยทั้งหมด (Traffic Logs, Alert Center, CSV Exports) ต้องแสดงผลในเวลาประเทศไทย `Asia/Bangkok (UTC+7)`
- Development & Deployment Workflow: ทุกการแก้ไขต้องทำใน WSL Ubuntu ก่อนเสมอ ทดสอบ Build (`npm run build`) ให้ผ่าน 100% แสดงผลและสรุปให้ผู้ใช้ตรวจสอบ และจะ Deploy ขึ้น VPS (`178.104.53.123`) ต่อเมื่อได้รับคำสั่งอนุมัติเท่านั้น

Resolved decisions:

- Product positioning: **Seminar / Lab / Demo system** สำหรับแสดงผลงานและสาธิตเท่านั้น
- ML metric authoritative source: **`ml/models/model_metadata.json`** (Accuracy 80.47%, ROC-AUC 0.8847) ตัวเลขใน README (93.40%) ต้องอัปเดตให้ตรง
- Timezone standard: **Asia/Bangkok (UTC+7)** สำหรับทุก User-facing Timestamps

Open decisions:

- Which deployment target and data-store mode should be treated as canonical outside the local/lab setup

## Brand Commitments

Existing product names and labels include "WAF Automated - Web Application Firewall & CDN Management System", "WAF Security Dashboard", "Firewall WAF", and "EDGE"

The current app uses security-operations terminology such as WAF, ModSecurity CRS, CDN Edge Nodes, Traffic Logs, Origin Servers, Access Control, ML Anomaly Rules, AI Security Analyst, and Alert Center. Future work should preserve this operational vocabulary unless the product is intentionally renamed

Existing asset evidence includes `dashboard/frontend/src/assets/firewall.png` and public usage as `/firewall.png`

## Evidence on Hand

Repository evidence:

- `README.md` describes the product, setup, features, service URLs, and ML guide links
- `DESIGN.md` documents the existing frontend design system, route/page expectations, API mapping, auth flow, permission matrix, and build/deployment notes
- `dashboard/frontend/package.json` confirms the React/Vite/TypeScript frontend stack and scripts
- `dashboard/frontend/src/App.tsx` confirms the current route structure and protected/admin route behavior
- `dashboard/frontend/src/components/layout/Sidebar.tsx` confirms the current user-facing navigation groups and product labels
- `dashboard/frontend/src/types/index.ts` confirms durable domain models for users, WAF logs/rules/alerts, CDN, origins/domains/SSL, IP blocks, and ML pending rules
- `dashboard/backend/main.py` confirms FastAPI app setup, CORS, protected system/log endpoints, routers, startup workers, health endpoint, and production React serving behavior
- `dashboard/backend/requirements.txt` confirms backend package dependencies, including FastAPI, auth/security libraries, slowapi, and redis
- `docker-compose.yml` confirms WAF, DVWA, Caddy, Redis, ClickHouse, control API, networks, volumes, and local lab runtime
- `ml/models/model_metadata.json` and `ml/models/eval_results.json` provide checked-in ML model metrics and dataset/model metadata

Conflicting evidence (resolved):

- `README.md` claims ML Accuracy 93.40% and ROC-AUC 0.9895
- checked-in `ml/models/model_metadata.json` and `ml/models/eval_results.json` report accuracy 0.8047 and ROC-AUC 0.8847
- **Resolved:** ใช้ตัวเลขจาก `metadata.json` (80.47%) เป็น authoritative source เพราะเป็น checked-in artifact จริง — ตัวเลขใน README ต้องอัปเดตให้ตรงกัน

Evidence not on hand:

- No confirmed customer names, testimonials, commercial pricing, production SLA, compliance certification, or external audit evidence was found
- `Skill.md` and `Task.md` have been created at the repo root and are up to date as of August 2026

## Product Principles

1. Show operational truth first: prioritize live status, actionable evidence, and clear cause/effect over decorative presentation
2. Keep security controls accountable: policy changes, generated rules, and destructive actions should show context, permissions, and review/confirmation paths
3. Connect detection to response: logs, ML findings, alerts, rules, and edge behavior should help the operator move from signal to decision without losing traceability
4. Preserve lab/demo clarity while avoiding fake production claims: make the system easy to evaluate, but do not invent proof beyond repo evidence
5. Treat roles as product behavior, not just UI decoration: admin/viewer differences must remain visible, consistent, and enforced
6. Strict Backend Guard: Protect Backend stability by isolating UI/UX improvements to the frontend layer only unless backend changes are explicitly requested
7. Build-First Verification: Validate all TypeScript/Vite builds in local WSL environment prior to requesting remote VPS deployment

## Accessibility & Inclusion

Target standard: **WCAG 2.1 AA** เป็นอย่างน้อย (และมุ่งสู่ WCAG AAA ใน Core Dashboards)

Future UI work should preserve keyboard-accessible controls, accessible landmarks (`role="region"`, `role="tablist"`), readable status/severity distinctions that do not rely on color alone, clear Thai/English copy where used, and non-visual cues for alerts, loading, errors, and destructive actions. All interactive elements must be keyboard-navigable with visible focus indicators, and color contrast ratios must meet 4.5:1 for normal text and 3:1 for large text per WCAG 2.1 AA requirements across both Light and Dark themes.
