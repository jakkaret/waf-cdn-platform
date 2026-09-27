---
title: "Database Reference"
part: "Reference"
status: VERIFIED
---

# Database Reference

## ClickHouse `default.access_logs`

| คอลัมน์ | ชนิด | ความหมาย |
|---|---|---|
| `id` | UUID | จาก `request_id` ถ้าเป็น UUID ไม่เช่นนั้นสุ่ม |
| `timestamp` | DateTime | เวลาคำขอ (UTC) |
| `client_ip` | String | IP ผู้เรียก (ที่ Main อาจเป็น IP ของ edge) |
| `method` | String | HTTP method |
| `url` | String | path + query |
| `status_code` | UInt16 | status ที่ตอบ |
| `request_time_ms` | Float32 | เวลาประมวลผล |
| `user_agent` | String | User-Agent |
| `country` | String | ISO-2 จาก DB-IP (ว่างถ้าเป็น IP ภายใน) |
| `edge_node` | String | `edge-th`, `edge-asia`, main … |
| `alert` | UInt8 | 1 = ถูกบล็อก/น่าสงสัย |
| `attack_type` | String | ประเภทการโจมตี / `Deception: ...` |
| `rule_id` | String | ModSecurity rule ID |
| `request_id` | String | `$request_id` ของ nginx |
| `http_referer` | String | Referer |
| `body_bytes_sent` | UInt32 | ขนาด response |
| `host` | String | Host header (ใช้แยก tenant) |
| `cache_status` | String | สถานะ cache จาก edge |

Engine `MergeTree`, `ORDER BY (timestamp, client_ip)`, `TTL timestamp + 30 DAY`

## ClickHouse `default.security_audit_logs`

`id`, `timestamp`, `client_ip`, `rule_id`, `message`, `severity`, `action`, `edge_node` — Engine `MergeTree`, `ORDER BY (timestamp, rule_id)`

## DynamoDB

| ตาราง | Partition key | Sort key | GSI |
|---|---|---|---|
| `waf_users` | `user_id` | – | `EmailIndex` (email), `ProviderIndex` |
| `waf_origins` | `id` | – | `admin_user_id-index` |
| `waf_domains` | `id` | – | `origin_id-index`, `domain_name-index` |
| `waf_alerts_v2` | `origin_id` | `alert_id` | – |
| `waf_alerts` (DEPRECATED) | `user_id` | `alert_id` | – |
| `waf_pending_rules` | `rule_id` | `created_at` | `status-index` (status, created_at) |
| `waf_ssl_certs` | `id` | – | – |
| `waf_logs` | `user_id` (จาก `save_log`) | `log_id` | UNKNOWN |
| `waf_rules`, `waf_threat_patterns`, `waf_status_history`, `waf_audit_log`, `waf_postmortems`, `waf_threshold_proposals` | UNKNOWN (ไม่มีสคริปต์สร้างใน repo) | – | – |

## SQLite / ไฟล์

`dashboard/backend/data/ip_rules.db`, `rate_limits.db`, `system_settings.json`, `geoip/*.mmdb`

## แหล่งอ้างอิง (Evidence)
- `services/clickhouse_service.py:110–190`, `scripts/create_*.py`, `scripts/migrate_alerts_to_origin_key.py`, `services/dynamodb_service.py`
