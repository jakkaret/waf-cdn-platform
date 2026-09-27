---
title: "API Reference"
part: "Reference"
status: VERIFIED
---

# API Reference

สร้างอัตโนมัติจากซอร์สโค้ด `dashboard/backend/api/*.py` ด้วยการอ่านโครงสร้างโค้ด (AST) ไม่ได้ import แอปจริง ช่อง **Auth** มาจาก dependency ที่ประกาศใน decorator/พารามิเตอร์ของ handler: `admin` = `require_admin`, `viewer+` = `require_viewer_or_above`, `login` = `get_current_user`, `internal key` = header ภายในจาก nginx, `origin owner/read/edit` = `verify_origin_*` (ต้อง login และมีสิทธิ์ต่อ origin นั้น), `public` = ไม่พบ dependency ด้านการยืนยันตัวตน (บาง handler อาจตรวจสิทธิ์เองในโค้ด ให้ดูไฟล์ประกอบ)

พบทั้งหมด **123 endpoints** ใน **23 ไฟล์** — router ที่ `main.py` ลงทะเบียน (`include_router`) มี 24 รายการ

## `api/ai_summary.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/ai/notifications/feed` | `get_notification_feed` | login | Get persistent notification feed with AI explanations for Dashboard |
| POST | `/api/ai/notifications/mark-read` | `mark_notifications_read` | login | Mark one alert read (alert_id given), or ALL alerts read when alert_id |
| POST | `/api/ai/postmortems/{origin_id}` | `create_postmortem` | login, origin owner |  |
| GET | `/api/ai/postmortems/{origin_id}` | `list_postmortems` | origin owner | No range key on waf_postmortems (HASH=id only) -- scan + filter + |
| GET | `/api/ai/postmortems/{origin_id}/{postmortem_id}` | `get_postmortem` | origin owner |  |
| POST | `/api/ai/summarize-range` | `summarize_threat_range` | login | Summarize WAF attacks for a given time range or natural language text query. |

## `api/alerts.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| DELETE | `/api/alerts/connect` | `connect_disconnect` | login |  |
| GET | `/api/alerts/connect/poll` | `connect_poll` | login |  |
| POST | `/api/alerts/connect/start` | `connect_start` | login |  |
| GET | `/api/alerts/connect/status` | `connect_status` | login |  |
| GET | `/api/alerts/recent` | `get_recent_alerts` | login |  |

## `api/analytics.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/analytics/summary` | `get_analytics_summary` | viewer+ | Returns real-time analytics aggregates from ClickHouse database, |

## `api/auth.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/auth/google` | `google_login` | public |  |
| GET | `/api/auth/google/callback` | `google_callback` | public |  |
| POST | `/api/auth/login` | `login` | public |  |
| POST | `/api/auth/logout` | `logout` | public |  |
| GET | `/api/auth/me` | `me` | login |  |
| POST | `/api/auth/register` | `register` | public |  |
| POST | `/api/auth/telegram` | `telegram_login` | public |  |
| POST | `/api/auth/tunnel/verify` | `verify_tunnel` | public |  |
| GET | `/api/auth/users` | `list_users` | admin |  |
| DELETE | `/api/auth/users/{user_id}` | `delete_user` | admin |  |
| PUT | `/api/auth/users/{user_id}/role` | `update_user_role` | admin |  |

## `api/cdn.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/cdn/latency` | `cdn_latency` | viewer+ |  |
| GET | `/api/cdn/logs` | `cdn_logs` | viewer+ |  |
| POST | `/api/cdn/logs/ingest` | `ingest_cdn_logs` | public |  |
| GET | `/api/cdn/nodes` | `cdn_nodes` | viewer+ | Check live operational health status of configured CDN POPs |
| POST | `/api/cdn/purge` | `cdn_purge` | admin |  |
| GET | `/api/cdn/stats` | `cdn_stats` | viewer+ | Aggregate real-time CDN stats from ClickHouse, strictly isolated per tenant. |

## `api/copilot.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/copilot/chat` | `copilot_chat` | viewer+ | Real-time AI SecOps Assistant with live ClickHouse context and user scoping. |

## `api/deception.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS | `/api/deception/respond` | `respond_deception` | internal key | Internal honeypot responder triggered by Nginx error_page 418 redirect. |
| POST | `/api/deception/simulate` | `simulate_deception` | admin | Dry-run simulation endpoint allowing administrators to test classification |
| GET | `/api/deception/templates` | `list_deception_templates` | admin | Returns catalog of registered deception templates for admin dashboard. |

## `api/domains.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/domains` | `create_domain` | login |  |
| GET | `/api/domains/check-ssl-allowed` | `check_ssl_allowed` | public |  |
| GET | `/api/domains/origin/{origin_id}` | `list_domains_by_origin` | login |  |
| DELETE | `/api/domains/{domain_id}` | `delete_domain` | login |  |
| POST | `/api/domains/{domain_id}/verify` | `verify_domain_now` | login |  |
| GET | `/api/origins/{origin_id}/domains` | `list_domains_by_origin` | login |  |
| POST | `/api/origins/{origin_id}/domains` | `create_domain_under_origin` | login |  |
| DELETE | `/api/origins/{origin_id}/domains/{domain_id}` | `delete_domain_under_origin` | login |  |
| POST | `/api/origins/{origin_id}/domains/{domain_id}/verify` | `verify_domain_now_under_origin` | login |  |

## `api/ip_rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/ip-rules/` | `get_ip_rules` | viewer+ |  |
| POST | `/api/ip-rules/` | `add_ip_rule` | admin |  |
| POST | `/api/ip-rules/bulk-delete` | `bulk_delete_rules` | admin |  |
| DELETE | `/api/ip-rules/{ip:path}` | `delete_ip_rule` | admin |  |

## `api/limiter.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET,POST,PUT,DELETE,PATCH,HEAD,OPTIONS | `/api/limiter/check` | `check_rate_limit` | public |  |

## `api/logs.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/logs` | `get_logs` | viewer+ | Retrieve structured audit logs from ClickHouse with strict tenant isolation |
| GET | `/api/logs/` | `get_logs` | viewer+ | Retrieve structured audit logs from ClickHouse with strict tenant isolation |
| POST | `/api/logs/explain` | `explain_payload` | viewer+ | Real-time Explainable WAF Token Attribution analyzer for arbitrary request/payload |
| GET | `/api/logs/explain/{log_id}` | `explain_log_by_id` | viewer+ | Retrieve deep token attribution and explainability for a specific log by ID |
| GET | `/api/logs/filters` | `get_filter_options` | viewer+ |  |
| POST | `/api/logs/mask-preview` | `preview_masking` | viewer+ | Test and preview Zero-Knowledge PII Masking & Salted Hash on any string |
| GET | `/api/logs/recent` | `fetch_recent_logs` | viewer+ | Fetch recent logs for Dashboard table view scoped to tenant origin |

## `api/ml.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/ml/capture` | `capture_telemetry_relay` | public | Docker-to-loopback relay for privacy-scoped lab telemetry. |
| POST | `/api/ml/predict` | `predict_anomaly` | viewer+ |  |
| POST | `/api/ml/predict-and-suggest` | `predict_and_suggest` | viewer+ |  |
| GET | `/api/ml/shadow/decision` | `shadow_decision` | public | Internal Docker-to-loopback relay for the Nginx shadow hook. |

## `api/ml_rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/ml-rules/` | `list_ml_rules` | admin | Admin-only (2026-09-22, diagnosing-bugs skill applied to the tenant- |
| POST | `/api/ml-rules/cve-scan` | `run_cve_scan` | admin | CVE Auto-Patch (2026-09-22). Admin-triggered, deliberately NOT a |
| GET | `/api/ml-rules/{rule_id}` | `get_ml_rule` | admin | Admin-only -- see list_ml_rules above for why. |
| DELETE | `/api/ml-rules/{rule_id}` | `delete_ml_rule` | admin |  |
| POST | `/api/ml-rules/{rule_id}/approve` | `approve_ml_rule` | admin |  |
| POST | `/api/ml-rules/{rule_id}/reject` | `reject_ml_rule` | admin |  |

## `api/onboarding.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/onboarding/status` | `get_onboarding_status` | login |  |

## `api/origins.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/origins` | `create_origin` | login |  |
| GET | `/api/origins` | `list_origins` | login |  |
| GET | `/api/origins/quota` | `get_quota` | login | Return quota usage for the current user (origins used / max). |
| GET | `/api/origins/{origin_id}` | `get_origin` | origin read |  |
| PUT | `/api/origins/{origin_id}` | `update_origin` | login, origin edit |  |
| DELETE | `/api/origins/{origin_id}` | `delete_origin` | origin owner |  |
| GET | `/api/origins/{origin_id}/audit-log` | `get_origin_audit_log` | origin read | Team Workspace (2026-09-22): owner, editor, or viewer may read the |
| GET | `/api/origins/{origin_id}/captcha` | `get_captcha_config` | origin edit |  |
| PUT | `/api/origins/{origin_id}/captcha` | `update_captcha_config` | origin edit |  |
| GET | `/api/origins/{origin_id}/editors` | `get_origin_editors` | origin owner |  |
| POST | `/api/origins/{origin_id}/editors` | `add_origin_editor` | login, origin owner |  |
| DELETE | `/api/origins/{origin_id}/editors/{editor_user_id}` | `remove_origin_editor` | login, origin owner |  |
| GET | `/api/origins/{origin_id}/otp` | `get_otp_config` | origin edit |  |
| PUT | `/api/origins/{origin_id}/otp` | `update_otp_config` | origin edit |  |
| POST | `/api/origins/{origin_id}/restore` | `restore_origin` | login |  |
| GET | `/api/origins/{origin_id}/viewers` | `get_origin_viewers` | origin owner |  |
| POST | `/api/origins/{origin_id}/viewers` | `add_origin_viewer` | login, origin owner |  |
| DELETE | `/api/origins/{origin_id}/viewers/{viewer_user_id}` | `remove_origin_viewer` | login, origin owner |  |

## `api/public_status.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/status/public` | `get_public_status` | public | No auth -- this is meant to be reachable by anyone, the same as |
| GET | `/api/status/public/history` | `get_public_status_history` | public |  |

## `api/rate_limits.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/rate-limits/reset-client` | `reset_client` | admin |  |
| GET | `/api/rate-limits/rules` | `list_rate_rules` | viewer+ |  |
| POST | `/api/rate-limits/rules` | `create_rate_rule` | admin |  |
| PUT | `/api/rate-limits/rules/{rule_id}` | `update_rate_rule` | admin |  |
| DELETE | `/api/rate-limits/rules/{rule_id}` | `delete_rate_rule` | admin |  |
| GET | `/api/rate-limits/throttled` | `get_throttled_clients` | viewer+ |  |

## `api/rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/rules/` | `get_rules` | viewer+ |  |
| POST | `/api/rules/` | `create_rule` | admin |  |
| POST | `/api/rules/blast-radius` | `simulate_blast_radius` | viewer+ | Replays historical traffic against candidate rule to estimate false positives and blast ra |
| POST | `/api/rules/blast-radius/export` | `export_blast_radius_audit` | viewer+ | Generates and exports an Enterprise SecOps Compliance Audit Report for the simulated rule. |
| POST | `/api/rules/bola/inspect` | `inspect_request_bola` | viewer+ | Test/Inspect a request path and headers against BOLA guard engine. |
| GET | `/api/rules/bola/policies` | `get_bola_policies` | viewer+ | List active BOLA protection policies. |
| POST | `/api/rules/bola/policies` | `create_bola_policy` | admin | Add or update a BOLA protection policy. |
| PUT | `/api/rules/bola/policies/{policy_id}` | `update_bola_policy` | admin | Update an existing BOLA protection policy. |
| DELETE | `/api/rules/bola/policies/{policy_id}` | `delete_bola_policy` | admin | Delete a BOLA protection policy. |
| POST | `/api/rules/mitigate-candidate` | `generate_mitigation_candidate_rule` | viewer+ | Analyzes an attack log or token and returns an auto-generated, ReDoS-safe candidate ModSec |
| POST | `/api/rules/sync` | `sync_rules_to_edges` | admin | Trigger sync of WAF rules from this API to all CDN edge nodes. |
| DELETE | `/api/rules/{rule_id}` | `delete_rule` | admin |  |
| PUT | `/api/rules/{rule_id}` | `update_rule` | admin |  |

## `api/settings.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/settings/` | `get_settings` | viewer+ |  |
| POST | `/api/settings/` | `update_settings` | admin |  |
| POST | `/api/settings/test-notification` | `send_test_alert` | admin |  |

## `api/threat_intel.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| PATCH | `/api/threat-intel/opt-in` | `set_opt_in` | login | Per-user, not global (unlike api/settings.py's system-wide config) -- |
| GET | `/api/threat-intel/trending` | `get_trending` | login | Reciprocity gate lives in services/threat_intel.py itself: only a |

## `api/threshold_proposals.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/threshold-proposals/` | `list_proposals` | viewer+ |  |
| POST | `/api/threshold-proposals/generate` | `generate_proposal` | admin | Analyzes recent ClickHouse block-rate evidence and, if it clears the |
| GET | `/api/threshold-proposals/{proposal_id}` | `get_proposal` | viewer+ |  |
| POST | `/api/threshold-proposals/{proposal_id}/approve` | `approve_proposal` | admin |  |
| POST | `/api/threshold-proposals/{proposal_id}/reject` | `reject_proposal` | admin |  |
| POST | `/api/threshold-proposals/{proposal_id}/rollback` | `rollback_proposal` | admin | Reverts an approved proposal's threshold change back to whatever was |

## `api/tunnel.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/tunnel/issue-token` | `issue_agent_token` | admin | Mint a fresh agent credential for one origin, invalidating the previous one. |
| GET | `/api/tunnel/status` | `tunnel_status` | login | Real tunnel state, straight from what the tunnel server last published. |
| POST | `/api/tunnel/verify-agent` | `verify_agent` | public | Called by the tunnel server while an agent authenticates. |

## `api/tunnels.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/tunnels/config-generator` | `get_tunnel_config` | login | Generate personalized one-liner commands with user-specific signed Tunnel Token. |
| POST | `/api/tunnels/frp-hook` | `frp_webhook_gatekeeper` | public | FRP v0.61.1 HTTP Plugin Webhook Gatekeeper. |
| GET | `/api/tunnels/status` | `get_tunnels_status` | login | Query FRP daemon with multi-tenant isolation and 3-second caching. |
| POST | `/api/tunnels/token` | `create_tunnel_token` | login | Generate a cryptographic signed JWT Tunnel Token tied to the user and domain. |
| DELETE | `/api/tunnels/{target_identifier}` | `deregister_tunnel` | login |  |
