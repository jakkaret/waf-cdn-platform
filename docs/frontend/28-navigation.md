---
title: "บทที่ 28 — การนำทางในแอป"
chapter: 28
part: "Part VI — Frontend"
status: VERIFIED
---

# บทที่ 28 — การนำทางในแอป (Application Navigation)

## 28.1 เมนูด้านซ้าย (Sidebar)

| กลุ่ม | เมนู | Path | Role ที่เห็นเมนู |
|---|---|---|---|
| Monitoring & Core | Security Dashboard | `/` | admin, viewer |
| | Traffic Logs | `/logs` | admin, viewer |
| | Origin Servers | `/origins` (+ `/origins/:id`) | admin, viewer |
| Protection Rules | WAF Rules | `/rules` | admin, viewer |
| | API Security (BOLA) | `/bola` | admin, viewer |
| | IP Access List | `/ip-rules` | admin, viewer |
| | Rate Limiting | `/rate-limits` | admin, viewer |
| | ML Anomaly Rules | `/ml-rules` | admin |
| Detection & Response | AI Security Analyst | `/ml-analyst` | admin, viewer |
| | Tuning Proposals | `/threshold-proposals` | admin, viewer |
| | Alert Center | `/alerts` | admin, viewer |
| Edge & Delivery | CDN Edge Nodes | `/cdn` | admin, viewer |
| | Zero Trust Tunnels | `/tunnels` | admin, viewer |
| Administration & System | Access Control | `/users` | admin |
| | System Settings | `/settings` | admin, viewer |
| | Concepts (preview) | `/concepts` (+ 13 หน้าย่อย) | admin |

## 28.2 หน้าที่ไม่อยู่ในเมนู

| Path | ใช้ทำอะไร | ต้อง login |
|---|---|---|
| `/login`, `/register` | เข้าสู่ระบบ / สมัคร | ไม่ |
| `/oauth-success` | รับผลจาก Google OAuth | ไม่ |
| `/onboarding` | ขั้นตอนเริ่มต้นใช้งาน | ใช่ |
| `/status` | สถานะสาธารณะของ edge | ไม่ |

## 28.3 การป้องกัน route

- ทุกหน้าภายในห่อด้วย `ProtectedRoute` → ไม่ได้ login ไป `/login`
- `requireAdmin` ใช้กับ `/users` เท่านั้น หน้าอื่นที่เป็นของ admin (เช่น `/ml-rules`, `/concepts`) ซ่อนจากเมนูแต่ **สิทธิ์จริงถูกตรวจที่ backend** (`require_admin`)
- เมนูกรองตาม role ใน `Sidebar.tsx`

## แหล่งอ้างอิง (Evidence)
- `components/layout/Sidebar.tsx`, `App.tsx` (54–64, 336–342)
