---
title: "บทที่ 18 — Nginx"
chapter: 18
part: "Part IV — WAF"
status: VERIFIED
---

# บทที่ 18 — Nginx

## 18.1 บทบาทของ nginx ในระบบ

nginx อยู่ในสองตำแหน่ง ทั้งคู่ใช้ image `owasp/modsecurity-crs:nginx` (nginx 1.30.4)

| ตำแหน่ง | Container | หน้าที่หลัก |
|---|---|---|
| Edge | `cdn-edge-node` | WAF ชั้นนอก, rate limit, proxy cache, ส่งต่อไป Main |
| Main | `waf-nginx` | WAF ชั้นใน, routing ไป origin/tunnel, challenge, rate limit ต่อ path, deception |

Config ทั้งหมดเป็น **template** ที่ render ด้วย `envsubst` ตอน container เริ่ม

## 18.2 Upstream บน Main

| Upstream | ปลายทาง | ใช้กับ |
|---|---|---|
| `frp_tunnel_router` | `172.18.0.1:8085` (vhost ของ frps) | server `_` (default) และโดเมนที่ต่อผ่าน FRP |
| `cloudwaf_tunnel` | `172.18.0.1:8060` (vhost ของ cloudwaf-tunnel) | VAmPI และ origin ที่ใช้ CloudWAF tunnel |
| `dvwa_backend` | `dvwa:80` | แล็บ DVWA |
| `host.docker.internal:8000` | FastAPI | `/api/limiter/check`, `@deception`, captcha/OTP includes |

## 18.3 Server blocks บน Main (`nginx/templates/conf.d/default.conf.template`)

| server_name | ปลายทาง | หมายเหตุ |
|---|---|---|
| `_` (default_server, :8080) | `frp_tunnel_router` | โดเมนลูกค้าทั้งหมดที่ไม่ใช่แล็บ |
| `juice.waf-it-kku.online` | FRP | แล็บ |
| `dvwa.waf-it-kku.online` | FRP | แล็บ (มี telemetry mirror สำหรับ ML) |
| `vampi.waf-it-kku.online` | `cloudwaf_tunnel` | แล็บผ่าน CloudWAF tunnel |
| `bwapp.waf-it-kku.online` | FRP | แล็บ |

ทุก server เปิด `modsecurity on`, `modsecurity_transaction_id "$request_id"`, include `captcha_server.conf`/`otp_server.conf`, `error_page 403 /403.html`, `error_page 418 = @deception` และ location static assets แยก (ไม่ผ่าน rate limit)

## 18.4 Header และ request ID

- `X-Request-ID $request_id` ถูกส่งไป upstream และใช้เป็น transaction ID ของ ModSecurity เพื่อโยง access log กับ audit log
- `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, `Host` ถูกส่งต่อ
- **ไม่ได้ตั้ง** `set_real_ip_from` จึงเห็น IP ของ edge เป็นผู้เรียกสำหรับ traffic ผ่าน edge

## 18.5 Access log

รูปแบบ `json_combined` (`nginx/nginx.conf.template`) มีฟิลด์: `time_local`, `request_id`, `remote_addr`, `remote_user`, `request`, `host`, `status`, `body_bytes_sent`, `http_referer`, `http_user_agent`, `request_time`, `ssl_protocol`, `ssl_cipher` เขียนที่ `logs/nginx/access.json`

## 18.6 Rate limit และ challenge ต่อ path (Main)

- `auth_request /internal-shield-check` (captcha/OTP ของ origin) และ `/internal-rate-limit` → FastAPI `/api/limiter/check`
- `error_page 401 =429 @rate_limit_exceeded` ตอบ 429 พร้อม `Retry-After`

## แหล่งอ้างอิง (Evidence)
- `nginx/nginx.conf.template`, `nginx/templates/conf.d/default.conf.template`, `nginx/includes/*.conf`, `docker exec waf-nginx nginx -v`
