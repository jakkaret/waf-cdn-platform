---
title: "API Reference"
part: "Reference"
status: VERIFIED
---

# API Reference

สร้างอัตโนมัติจากซอร์สโค้ด `dashboard/backend/api/*.py` ด้วย `scripts/gen_api_reference.py` (อ่าน AST ไม่ได้ import แอปจริง) แก้ไฟล์นี้ด้วยมือไม่ได้ ให้รันสคริปต์ใหม่แทน ช่อง **Auth** มาจาก dependency ที่ประกาศใน decorator/พารามิเตอร์ของ handler: `admin` = `require_admin`, `viewer+` = `require_viewer_or_above`, `login` = `get_current_user`, `bearer token` = `bearer_scheme`, `internal key` = header ภายในจาก nginx, `origin owner/read/edit` = `verify_origin_*` (ต้อง login และมีสิทธิ์ต่อ origin นั้น), `public` = ไม่พบ dependency ด้านการยืนยันตัวตน (บาง handler อาจตรวจสิทธิ์เองในโค้ด ให้ดูไฟล์ประกอบ)

Route ที่ประกาศใน `main.py` เอง (`/api/health`, `/api/system/*`, ไฟล์ static) อยู่นอกขอบเขตของไฟล์นี้

พบทั้งหมด **189 endpoints** ใน **30 ไฟล์** — router ที่ `main.py` ลงทะเบียน (`include_router`) มี 31 รายการ

## `api/ai_summary.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/ai/notifications/feed` | `get_notification_feed` | login | Get persistent notification feed with AI explanations for Dashboard |
| POST | `/api/ai/notifications/mark-read` | `mark_notifications_read` | login | Mark one alert read (alert_id given), or ALL alerts read when alert_id |
| GET | `/api/ai/postmortems/{origin_id}` | `list_postmortems` | origin read | This origin's reports, newest first. |
| POST | `/api/ai/postmortems/{origin_id}` | `create_postmortem` | origin edit, login |  |
| GET | `/api/ai/postmortems/{origin_id}/{postmortem_id}` | `get_postmortem` | origin read, login |  |
| POST | `/api/ai/summarize-range` | `summarize_threat_range` | login | Summarize WAF attacks for a given time range or natural language text query. |

## `api/alerts.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| DELETE | `/api/alerts/connect` | `connect_disconnect` | login |  |
| GET | `/api/alerts/connect/poll` | `connect_poll` | login |  |
| POST | `/api/alerts/connect/start` | `connect_start` | login |  |
| GET | `/api/alerts/connect/status` | `connect_status` | login |  |
| GET | `/api/alerts/incidents` | `get_incidents` | login |  |
| GET | `/api/alerts/preferences` | `get_preferences` | login |  |
| PUT | `/api/alerts/preferences/{origin_id}` | `put_preferences` | login |  |
| GET | `/api/alerts/recent` | `get_recent_alerts` | login |  |
| PUT | `/api/alerts/sensitivity/{origin_id}` | `put_sensitivity` | login |  |
| POST | `/api/alerts/test` | `send_test` | login |  |

## `api/analytics.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/analytics/summary` | `get_analytics_summary` | viewer+ | Returns real-time analytics aggregates from ClickHouse database, |

## `api/auth.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/auth/google` | `google_login` | public | Start Google sign-in. link=true attaches Google to the account that is |
| GET | `/api/auth/google/callback` | `google_callback` | public |  |
| POST | `/api/auth/login` | `login` | public |  |
| POST | `/api/auth/logout` | `logout` | bearer token |  |
| POST | `/api/auth/logout-all` | `logout_all` | login | Sign out on every device of this account (all sessions and tokens). |
| GET | `/api/auth/me` | `me` | login |  |
| POST | `/api/auth/password/forgot` | `forgot_password` | public | Same answer whether or not the address has an account (no enumeration); |
| POST | `/api/auth/password/reset` | `reset_password` | public |  |
| POST | `/api/auth/register` | `register` | public |  |
| GET | `/api/auth/sessions` | `list_my_sessions` | bearer token, login | Devices signed in to this account, newest activity first. |
| DELETE | `/api/auth/sessions/{session_id}` | `revoke_my_session` | bearer token, login | Sign one device out. Only the account's own sessions can be revoked; |
| POST | `/api/auth/telegram` | `telegram_login` | public |  |
| GET | `/api/auth/users` | `list_users` | admin |  |
| DELETE | `/api/auth/users/{user_id}` | `delete_user` | admin |  |
| PUT | `/api/auth/users/{user_id}/role` | `update_user_role` | admin |  |
| POST | `/api/auth/verify-email/confirm` | `confirm_verification_code` | login |  |
| POST | `/api/auth/verify-email/send` | `send_verification_code` | login |  |

## `api/cdn.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/cdn/latency` | `cdn_latency` | viewer+ |  |
| GET | `/api/cdn/logs` | `cdn_logs` | viewer+ |  |
| POST | `/api/cdn/logs/ingest` | `ingest_cdn_logs` | public |  |
| GET | `/api/cdn/nodes` | `cdn_nodes` | viewer+ | Check live operational health status of configured CDN POPs |
| POST | `/api/cdn/purge` | `cdn_purge` | login | Queue a cache purge for one of the caller's sites. Every edge picks it |
| GET | `/api/cdn/purge/{job_id}` | `cdn_purge_status` | login | Which edges have applied purge `job_id` (edges poll every few seconds). |
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
| DELETE | `/api/domains/admin/{domain_id}/release` | `release_unverified_domain` | admin | P3.5: an admin frees a name held by an unverified row (a squatter, or |
| GET | `/api/domains/check-ssl-allowed` | `check_ssl_allowed` | public |  |
| GET | `/api/domains/origin/{origin_id}` | `list_domains_by_origin` | login |  |
| DELETE | `/api/domains/{domain_id}` | `delete_domain` | login |  |
| POST | `/api/domains/{domain_id}/verify` | `verify_domain_now` | login |  |
| GET | `/api/origins/{origin_id}/domains` | `list_domains_under_origin` | login |  |
| POST | `/api/origins/{origin_id}/domains` | `create_domain_under_origin` | login |  |
| DELETE | `/api/origins/{origin_id}/domains/{domain_id}` | `delete_domain_under_origin` | login |  |
| POST | `/api/origins/{origin_id}/domains/{domain_id}/verify` | `verify_domain_now_under_origin` | login |  |

## `api/honeypot.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/origins/{origin_id}/honeypot/decoys/{key}/probe` | `honeypot_decoy_probe` | origin edit |  |
| GET | `/api/origins/{origin_id}/honeypot/sessions` | `honeypot_sessions` | origin edit |  |
| GET | `/api/origins/{origin_id}/honeypot/sessions/{sid}` | `honeypot_session` | origin edit |  |
| POST | `/api/origins/{origin_id}/honeypot/sessions/{sid}/block` | `honeypot_block_session` | origin edit, login |  |
| POST | `/api/origins/{origin_id}/honeypot/sessions/{sid}/story` | `honeypot_story` | origin edit |  |
| GET | `/api/origins/{origin_id}/honeypot/summary` | `honeypot_summary` | origin edit |  |

## `api/invites.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/invites/accept` | `accept_invite` | login | Grant the invited role to the signed-in user who holds the emailed link |

## `api/ip_rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/ip-rules/` | `get_ip_rules` | admin |  |
| POST | `/api/ip-rules/` | `add_ip_rule` | admin |  |
| POST | `/api/ip-rules/bulk-delete` | `bulk_delete_rules` | admin |  |
| DELETE | `/api/ip-rules/{ip:path}` | `delete_ip_rule` | admin |  |

## `api/logs.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/logs` | `get_logs` | viewer+ | Retrieve structured audit logs from ClickHouse with strict tenant isolation |
| GET | `/api/logs/` | `get_logs` | viewer+ | Retrieve structured audit logs from ClickHouse with strict tenant isolation |
| POST | `/api/logs/explain` | `explain_payload` | viewer+ | Real-time Explainable WAF Token Attribution analyzer for arbitrary request/payload |
| GET | `/api/logs/explain/{log_id}` | `explain_log_by_id` | viewer+ | Retrieve deep token attribution and explainability for a specific log by ID |
| GET | `/api/logs/filters` | `get_filter_options` | viewer+ |  |
| GET | `/api/logs/histogram` | `logs_histogram` | viewer+ | Counts per time bucket for the filter bar chart (total + blocked). |
| POST | `/api/logs/mask-preview` | `preview_masking` | viewer+ | Test and preview Zero-Knowledge PII Masking & Salted Hash on any string |
| GET | `/api/logs/recent` | `fetch_recent_logs` | viewer+ | Fetch recent logs for Dashboard table view scoped to tenant origin |
| GET | `/api/logs/stream` | `stream_logs` | viewer+ | Keyset-paginated log stream (filter-first, 'load more'). Replaces deep |

## `api/managed_rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/managed-rules/catalog` | `get_catalog` | admin | Every published version and rule -- platform admin only (spans every |
| PUT | `/api/managed-rules/origins/{origin_id}/mode` | `set_mode` | origin edit |  |
| GET | `/api/managed-rules/origins/{origin_id}/status` | `get_status` | origin read |  |
| POST | `/api/managed-rules/origins/{origin_id}/update` | `update_to_latest` | origin edit | Manual mode: the origin's Admin presses Update to jump to the latest |
| POST | `/api/managed-rules/publish` | `publish_now` | admin | Check modsecurity/managed-rules/ for a change and publish a new |

## `api/ml.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/ml/capture` | `capture_telemetry_relay` | public | Docker-to-loopback relay for privacy-scoped lab telemetry. |
| POST | `/api/ml/gate` | `gate_relay` | public | Inline gate of an origin in enforce mode (nginx/njs/mlgate.js): scores |
| GET | `/api/ml/insights` | `ml_insights` | viewer+ | Gen 3 scores of the caller's real traffic (shadow, nothing blocked): |
| POST | `/api/ml/predict` | `predict_anomaly` | viewer+ |  |
| POST | `/api/ml/predict-and-suggest` | `predict_and_suggest` | viewer+ | Score a request with Gen 3 and queue rule proposals for review (an origin's Owner/Editors, or the platform admin). |
| GET | `/api/ml/shadow/decision` | `shadow_decision` | public | Internal Docker-to-loopback relay for the Nginx shadow hook. |

## `api/ml_protection.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/origins/{origin_id}/ml-protection` | `get_ml_protection` | origin read |  |
| PUT | `/api/origins/{origin_id}/ml-protection` | `put_ml_protection` | origin edit, login |  |
| GET | `/api/origins/{origin_id}/ml-protection/preview` | `preview_ml_protection` | origin read |  |
| GET | `/api/origins/{origin_id}/ml-verdicts/{request_id}` | `get_ml_verdict` | origin edit | One of this origin's scored requests with its masked body sample |
| POST | `/api/origins/{origin_id}/ml-verdicts/{request_id}/suggest-rule` | `suggest_rule_from_verdict` | origin edit, login | Ask Gen 3 for a rule from one flagged request of this origin, rescored |

## `api/ml_rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/ml-rules/` | `list_ml_rules` | viewer+ | Platform admin: every rule. Anyone else: the rules of origins they are Owner, Editor or Viewer of. |
| POST | `/api/ml-rules/cve-scan` | `run_cve_scan` | viewer+ | CVE Auto-Patch (2026-09-22). Admin-triggered, deliberately NOT a |
| POST | `/api/ml-rules/reject-legacy` | `reject_legacy_ml_rules` | admin | Reject every pending "rf-regex" rule in one call (the queue's ~268 RF leftovers). |
| DELETE | `/api/ml-rules/{rule_id}` | `delete_ml_rule` | admin | Delete a rule (and its ml-<id>.conf when deployed). Platform admin only. |
| GET | `/api/ml-rules/{rule_id}` | `get_ml_rule` | viewer+ | Platform admin, or a member of the rule's origin; anyone else gets 404 (see list_ml_rules). |
| POST | `/api/ml-rules/{rule_id}/approve` | `approve_ml_rule` | viewer+ | Approve and deploy: platform admin, or Owner/Editor of the rule's origin (deployed for that origin only). |
| POST | `/api/ml-rules/{rule_id}/backtest` | `backtest_ml_rule` | viewer+ | How many requests the WAF let through in the last `days` this rule would |
| POST | `/api/ml-rules/{rule_id}/reject` | `reject_ml_rule` | viewer+ | Reject: platform admin, or Owner/Editor of the rule's origin. |
| POST | `/api/ml-rules/{rule_id}/revoke` | `revoke_ml_rule` | viewer+ | Take an approved rule out of the WAF (its ml-<id>.conf is removed, the row stays). |

## `api/onboarding.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/onboarding/connect` | `connect_site` | login |  |
| POST | `/api/onboarding/inspect` | `inspect_domain` | login |  |
| GET | `/api/onboarding/progress/{origin_id}` | `get_progress` | login | Read access (viewers included) sees the status. Only someone who can |
| GET | `/api/onboarding/status` | `get_onboarding_status` | login |  |

## `api/origins.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/origins` | `list_origins` | login |  |
| POST | `/api/origins` | `create_origin` | login |  |
| GET | `/api/origins/overview` | `get_origins_overview` | login | Summary columns for the Origins list: 24 h requests/blocked, the five |
| GET | `/api/origins/quota` | `get_quota` | login | Return quota usage for the current user (origins used / max). |
| DELETE | `/api/origins/{origin_id}` | `delete_origin` | origin owner |  |
| GET | `/api/origins/{origin_id}` | `get_origin` | origin read, login |  |
| PUT | `/api/origins/{origin_id}` | `update_origin` | origin edit, login |  |
| GET | `/api/origins/{origin_id}/audit-log` | `get_origin_audit_log` | origin read | Team Workspace (2026-09-22): owner, editor, or viewer may read the |
| GET | `/api/origins/{origin_id}/captcha` | `get_captcha_config` | origin edit |  |
| PUT | `/api/origins/{origin_id}/captcha` | `update_captcha_config` | origin edit |  |
| GET | `/api/origins/{origin_id}/cves` | `get_origin_cves` | origin read | CVEs from the NVD feed matching this origin's tech_stack_tags. |
| GET | `/api/origins/{origin_id}/editors` | `get_origin_editors` | origin owner |  |
| POST | `/api/origins/{origin_id}/editors` | `add_origin_editor` | origin owner, login |  |
| DELETE | `/api/origins/{origin_id}/editors/{editor_user_id}` | `remove_origin_editor` | origin owner, login |  |
| GET | `/api/origins/{origin_id}/invites` | `list_origin_invites` | origin owner |  |
| DELETE | `/api/origins/{origin_id}/invites/{invite_id}` | `cancel_origin_invite` | origin owner, login |  |
| GET | `/api/origins/{origin_id}/otp` | `get_otp_config` | origin edit |  |
| PUT | `/api/origins/{origin_id}/otp` | `update_otp_config` | origin edit |  |
| POST | `/api/origins/{origin_id}/restore` | `restore_origin` | login |  |
| GET | `/api/origins/{origin_id}/viewers` | `get_origin_viewers` | origin owner |  |
| POST | `/api/origins/{origin_id}/viewers` | `add_origin_viewer` | origin owner, login |  |
| DELETE | `/api/origins/{origin_id}/viewers/{viewer_user_id}` | `remove_origin_viewer` | origin owner, login |  |

## `api/public_status.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/status/public` | `get_public_status` | public | No auth -- this is meant to be reachable by anyone, the same as |
| GET | `/api/status/public/history` | `get_public_status_history` | public |  |

## `api/quick_tunnels.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/tunnels/quick` | `list_quick_tunnels` | login |  |
| POST | `/api/tunnels/quick` | `create_quick_tunnel` | login |  |
| DELETE | `/api/tunnels/quick/{origin_id}` | `delete_quick_tunnel` | login | The owner removes their own; an admin removes anyone's (abuse). Anything |

## `api/rate_limits.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| POST | `/api/rate-limits/reset-client` | `reset_client` | admin |  |
| GET | `/api/rate-limits/rules` | `list_rate_rules` | admin |  |
| POST | `/api/rate-limits/rules` | `create_rate_rule` | admin |  |
| DELETE | `/api/rate-limits/rules/{rule_id}` | `delete_rate_rule` | admin |  |
| PUT | `/api/rate-limits/rules/{rule_id}` | `update_rate_rule` | admin |  |
| GET | `/api/rate-limits/throttled` | `get_throttled_clients` | admin | Every bucket is per site host and client IP. The operator sees the IPs |

## `api/rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/rules/` | `get_rules` | admin |  |
| POST | `/api/rules/` | `create_rule` | admin |  |
| POST | `/api/rules/blast-radius` | `simulate_blast_radius` | admin | Replays historical traffic against candidate rule to estimate false positives and blast radius. |
| POST | `/api/rules/blast-radius/export` | `export_blast_radius_audit` | admin | Generates and exports an Enterprise SecOps Compliance Audit Report for the simulated rule. |
| POST | `/api/rules/mitigate-candidate` | `generate_mitigation_candidate_rule` | viewer+ | Analyzes an attack log or token and returns an auto-generated, ReDoS-safe candidate ModSecurity SecRule. |
| POST | `/api/rules/sync` | `sync_rules_to_edges` | admin | Disabled (F-034). This ran scripts/sync_waf_rules.py, which wrote a |
| DELETE | `/api/rules/{rule_id}` | `delete_rule` | admin |  |
| PUT | `/api/rules/{rule_id}` | `update_rule` | admin |  |

## `api/settings.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/settings/` | `get_settings` | viewer+ |  |
| POST | `/api/settings/` | `update_settings` | admin |  |

## `api/shield_events.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/origins/{origin_id}/shield-events` | `get_shield_events` | origin read |  |
| POST | `/api/origins/{origin_id}/shield-events/preview` | `preview_shield` | origin edit | Before an Admin saves CAPTCHA/OTP settings: how much of this origin's |

## `api/site_access.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/origins/{origin_id}/ip-rules` | `list_site_ip_rules` | origin read |  |
| POST | `/api/origins/{origin_id}/ip-rules` | `add_site_ip_rule` | origin edit, login |  |
| DELETE | `/api/origins/{origin_id}/ip-rules/{rule_id}` | `delete_site_ip_rule` | origin edit, login |  |
| GET | `/api/origins/{origin_id}/rate-limits` | `list_site_rate_limits` | origin read |  |
| POST | `/api/origins/{origin_id}/rate-limits` | `add_site_rate_limit` | origin edit, login |  |
| GET | `/api/origins/{origin_id}/rate-limits/throttled` | `site_throttled_clients` | origin read | Clients counted against any rule on this site's hosts right now. |
| DELETE | `/api/origins/{origin_id}/rate-limits/{rule_id}` | `delete_site_rate_limit` | origin edit, login |  |
| PUT | `/api/origins/{origin_id}/rate-limits/{rule_id}` | `update_site_rate_limit` | origin edit, login |  |

## `api/support.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/support/origins` | `my_origins` | login | Origins the caller can open a ticket for (those they are an Admin of). |
| GET | `/api/support/tickets` | `list_tickets` | login |  |
| POST | `/api/support/tickets` | `open_ticket` | login |  |
| GET | `/api/support/tickets/{ticket_id}` | `ticket_detail` | login |  |
| POST | `/api/support/tickets/{ticket_id}/close` | `close` | login |  |
| DELETE | `/api/support/tickets/{ticket_id}/grant` | `revoke` | login |  |
| POST | `/api/support/tickets/{ticket_id}/grant` | `grant` | login |  |
| POST | `/api/support/tickets/{ticket_id}/messages` | `reply` | login |  |

## `api/tenant_rules.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/origins/{origin_id}/waf-rules/` | `list_rules` | origin read |  |
| POST | `/api/origins/{origin_id}/waf-rules/` | `create_rule` | origin edit, login |  |
| GET | `/api/origins/{origin_id}/waf-rules/decoys` | `list_decoys` | origin read | The decoy-path catalog with each entry's on/off state for this origin, |
| POST | `/api/origins/{origin_id}/waf-rules/decoys/apply-recommended` | `apply_recommended_decoys` | origin edit, login | Turn on every decoy recommended for this origin's declared stack that is |
| PUT | `/api/origins/{origin_id}/waf-rules/decoys/{key}` | `set_decoy` | origin edit, login |  |
| GET | `/api/origins/{origin_id}/waf-rules/options` | `get_options` | origin read | Fixed choices the rule builder UI renders -- nothing here is free text |
| DELETE | `/api/origins/{origin_id}/waf-rules/{rule_id}` | `delete_rule` | origin edit |  |
| PUT | `/api/origins/{origin_id}/waf-rules/{rule_id}` | `update_rule` | origin edit, login |  |

## `api/threshold_proposals.py`

สถานะการลงทะเบียน: ลงทะเบียนใน main.py

| Method | Path | Handler | Auth | คำอธิบาย (docstring) |
|---|---|---|---|---|
| GET | `/api/threshold-proposals/` | `list_proposals` | viewer+ |  |
| POST | `/api/threshold-proposals/generate` | `generate_proposal` | viewer+ | Owner of the origin only: analyses its own block rate and, if it clears the bar (see |
| GET | `/api/threshold-proposals/origins` | `list_tunable_origins` | viewer+ | Origins the caller belongs to, with the threshold the WAF applies to each. |
| GET | `/api/threshold-proposals/{proposal_id}` | `get_proposal` | viewer+ |  |
| POST | `/api/threshold-proposals/{proposal_id}/approve` | `approve_proposal` | viewer+ | Owner of the proposal's origin only: applies the threshold to that origin. |
| POST | `/api/threshold-proposals/{proposal_id}/reject` | `reject_proposal` | viewer+ | Owner of the proposal's origin only. |
| POST | `/api/threshold-proposals/{proposal_id}/rollback` | `rollback_proposal` | viewer+ | Owner of the proposal's origin only: puts back the origin's threshold |

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
| GET | `/api/tunnels/agent-bootstrap` | `agent_bootstrap` | public | Hand the frps connection secret only to a holder of a valid, unexpired |
| GET | `/api/tunnels/config-generator` | `get_tunnel_config` | login | Generate personalized one-liner commands with user-specific signed Tunnel Token. |
| POST | `/api/tunnels/frp-hook/{hook_key}` | `frp_hook` | public | P3.1 (N1/H66): only frps on this host may call the gatekeeper -- the |
| GET | `/api/tunnels/status` | `get_tunnels_status` | login | Query FRP daemon with multi-tenant isolation and 3-second caching. |
| POST | `/api/tunnels/token` | `create_tunnel_token` | login | Generate a cryptographic signed JWT Tunnel Token tied to the user and domain. |
| DELETE | `/api/tunnels/{target_identifier}` | `deregister_tunnel` | login | P3.7 (H73): deregister exactly one origin, named by its id. The owner |
