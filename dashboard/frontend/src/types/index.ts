// ─── TypeScript Types ─── (from DESIGN.md section 6)

export interface User {
  user_id: string
  email: string
  username: string
  role: 'admin' | 'viewer'
  avatar_url?: string
  auth_provider: 'local' | 'google' | 'telegram'
  created_at: string
  last_login: string
  // Confirmed the emailed code (or signed up with Google). Until then adding
  // sites, team invitations, agent tokens and AI are refused (lib/emailGate.ts).
  email_verified?: boolean
}

export interface WafLog {
  log_id?: string
  user_id: string
  request_id?: string
  ip: string
  method: string
  url: string
  status: number
  user_agent?: string
  datetime: string
  timestamp: number
  source: 'nginx' | 'modsec' | 'merged'
  rule_id?: string | null
  severity?: string | null
  attack_type?: string | null
  alert: boolean
  is_suspicious_path?: boolean
  has_query?: boolean
  body_bytes_sent?: number
  http_referer?: string
}

export interface WafRule {
  id: string
  variable: 'REQUEST_URI' | 'ARGS' | 'REQUEST_HEADERS' | 'REQUEST_BODY'
  operator: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  message: string
  action?: 'BLOCK' | 'CHALLENGE' | 'DECEIVE'
  deception_template?: 'auto' | 'path_traversal' | 'sqli'
}

export interface WafAlert {
  user_id: string
  alert_id: string
  ip: string
  url: string
  status: string
  message: string
  timestamp: string
  rule_id?: string | null
  severity?: string | null
  /** Telegram dispatch outcome; not yet provided by backend. */
  dispatch_status?: string | null
  dispatched?: boolean | null
  /** Origin the alert's Host resolved to at write time; empty when unattributed. */
  origin_id?: string | null
  domain?: string | null
}

export interface CdnNode {
  region: string
  name?: string
  flag?: string
  city?: string
  ip?: string
  port?: number
  status?: string
  online?: boolean
  latency_ms?: number
  uptime_pct?: number
  cache_hit_ratio?: number
  avg_latency_ms?: number
}

export interface CdnStats {
  region: string
  request_count: number
  cache_hit: number
  cache_miss: number
  cache_bypass: number
  blocked_count: number
  avg_latency: number
}

export interface CdnLatency {
  region: string
  avg_ms: number
  p95_ms: number
  p99_ms: number
  datapoints: { time: string; latency_ms: number }[]
}

export interface CdnLog {
  region: string
  ip: string
  url: string
  method: string
  status: number
  cache_status: 'HIT' | 'MISS' | 'BYPASS'
  latency_ms: number
  datetime: string
}

export interface BlockedIP {
  ip_cidr: string
  reason: string
  blocked_at: string
  blocked_by: string
}

export interface RuleSyncStatus {
  node: string
  status: 'synced' | 'failed' | 'pending'
  last_sync: string
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
export type CacheStatus = 'HIT' | 'MISS' | 'BYPASS'
export type NodeRegion = 'SG' | 'JP' | 'TH'
export type UserRole = 'admin' | 'viewer'

export interface Origin {
  origin_id: string
  admin_user_id: string
  // Additional origin Admins (the stored field keeps its old "editor" name).
  // Same rights as the creator except the creator can't be removed.
  editor_user_ids?: string[]
  viewer_user_ids?: string[]
  label: string
  ip: string
  port: number
  status: 'active' | 'inactive' | 'error' | 'pending' | 'archived'
  health: 'up' | 'down' | 'unknown'
  created_at: string
  updated_at: string
  is_tunnel?: boolean
  // Read-time computed field, separate from `status` (CRUD lifecycle
  // state): whether the underlying FRP tunnel is connected right now. null
  // for non-tunnel origins, where the question doesn't apply.
  live_connected?: boolean | null
  // CVE Auto-Patch (2026-09-22): self-declared, admin-set -- no real
  // fingerprinting. Feeds POST /api/ml-rules/cve-scan's matching.
  tech_stack_tags?: string[]
  // Set by the connect flow. A direct connection proxies to
  // origin_scheme://ip:port; an agent one goes through the tunnel.
  connection_mode?: 'direct' | 'agent' | null
  origin_scheme?: 'http' | 'https' | null
}

// GET /api/origins/overview (services/origin_overview.py): the Origins
// list's summary columns. null = that store could not be read.
export interface OriginOverview {
  origin_id: string
  requests_24h: number | null
  blocked_24h: number | null
  protection: {
    waf: { custom_rules: number | null; decoys: number | null }
    ml: { mode: 'log' | 'enforce' | string; challenge_score: number | null; block_score: number | null } | null
    ip: { block: number; allow: number } | null
    rate: { rules: number; enabled: number } | null
    shield: { captcha: boolean | null; otp: boolean | null }
  }
  domains: { total: number; verified: number }
}

// The backend changed what was asked for: a server that answers http:80 with
// a redirect to https on the same domain is moved to https:443 (it would
// otherwise redirect forever behind the WAF).
export interface OriginAdjusted {
  scheme: 'http' | 'https'
  port: number
  reason: 'origin_forces_https'
  status: number | null
}

export interface OriginViewer {
  user_id: string
  username: string
  email: string
}

export interface OriginEditor {
  user_id: string
  username: string
  email: string
}

// Team Workspace (2026-09-22): audit trail for origin/domain/editor/viewer
// changes -- services/audit_log.py's write_audit_event() shape.
export interface AuditEvent {
  scope_id: string
  event_id: string
  timestamp: string
  actor_user_id: string
  actor_username: string
  action: string
  summary: string
  details: Record<string, any>
}

// AI Incident Postmortem (2026-09-22)
export interface PostmortemStats {
  total_requests: number
  total_alerts: number
  top_attack_types: { type: string; count: number }[]
  // Decoy sessions in the window and how many got at least this far
  // (services/honeypot.py day_counts). Missing on reports made before 2026-10-28.
  honeypot?: { sessions: number; ips: number; loot: number; exploit: number; credential_use: number; persistence: number }
}

export interface PostmortemBucket {
  hour: string
  requests: number
  alerts: number
}

export interface PostmortemAuditEvent extends AuditEvent {
  scope: 'origin' | 'global'
}

export interface PostmortemSummary {
  id: string
  origin_id: string
  origin_label: string
  created_by_username: string
  created_at: string
  start_time: string
  end_time: string
  stats: PostmortemStats
  has_ai_narrative: boolean
}

export interface Postmortem extends PostmortemSummary {
  hourly_buckets: PostmortemBucket[]
  audit_events: PostmortemAuditEvent[]
  ai_narrative: string | null
  ai_narrative_degraded: boolean
}

export interface Domain {
  domain_id: string
  origin_id: string
  domain_name: string
  verification_status: 'pending' | 'verified' | 'failed'
  dns_verification_token: string
  cname_target: string
  ssl_status: 'none' | 'pending' | 'active' | 'error'
  ssl_expires_at?: string
  // Real cert data from services/ssl_cert_monitor.py's periodic probe
  // (waf_ssl_certs), surfaced by api/domains.py's format_domain(). Absent
  // (not just falsy) until the worker has probed this domain at least once.
  ssl_issuer?: string
  ssl_days_remaining?: number | null
  ssl_checked_at?: string
  created_at: string
}

export interface SslCert {
  cert_id: string
  domain_id: string
  issuer: string
  expires_at: string
  auto_renew: boolean
  status: 'active' | 'expired' | 'pending'
}

export interface DnsInstructions {
  cname_record: { type: 'CNAME'; name: string; value: string }
  // Fallback only: the CNAME alone verifies the domain (api/domains.py's
  // dns_instructions_for); TXT is for names that cannot hold a CNAME.
  txt_record: { type: 'TXT'; name: string; value: string }
  required?: Array<'cname_record' | 'txt_record'>
}

export interface CaptchaShieldConfig {
  origin_id?: string
  enabled: boolean
  engine: 'native' | 'turnstile'
  login_paths: string[]
  clearance_ttl: number
  bypass_ips: string[]
  pow_difficulty: number
  image_captcha?: boolean
  mode: 'enforce' | 'log_only'
  exclude_paths: string[]
  updated_at?: string
}

export interface OtpShieldConfig {
  origin_id?: string
  enabled: boolean
  login_paths: string[]
  clearance_ttl: number
  bypass_ips: string[]
  code_length: number
  code_ttl: number
  // Only "email" is implemented server-side today (cdn/control-api/email_sender.py).
  channel: 'email'
  mode: 'enforce' | 'log_only'
  exclude_paths: string[]
  // 'open': anyone who receives the code; 'allowlist': only allowed_emails
  // (exact addresses or '@domain' entries).
  access_mode: 'open' | 'allowlist'
  allowed_emails: string[]
  updated_at?: string
}

export type ProvisioningStep =
  | 'dns_verify'
  | 'ssl_provision'
  | 'nginx_reload'
  | 'done'
  | 'failed'

export interface MLPendingRule {
  rule_id: string
  pattern: string
  variable: string
  attack_type: string
  severity: string
  secrule_template: string
  source_url: string
  source_method: string
  // 'revoked' (2026-10-27): was approved, then taken out of the WAF.
  status: 'pending' | 'approved' | 'rejected' | 'revoked'
  created_at: string
  reviewed_by?: string
  reviewed_at?: string
  reject_reason?: string
  revoked_by?: string
  revoked_at?: string
  revoke_reason?: string
  deployed_rule_id?: number
  // 2026-10-13: Gen3-rules, queue de-duplication and backtest
  // (dashboard/backend/services/ml_rule_service.py, rule_backtest.py)
  created_by?: string
  generator?: MLRuleGenerator
  detector?: string
  dedup_key?: string
  hit_count?: number
  examples?: { url: string; method: string; seen_at: string; requested_by?: string }[]
  last_seen_at?: string
  backtest?: MLRuleBacktest
  cve_id?: string
  // Per-origin review (2026-10-26, api/ml_rules.py): "" means a platform-wide
  // rule that only a platform admin sees. The can_* flags are per caller.
  origin_id?: string
  origin_label?: string
  deploy_scope?: MLRuleDeployScope
  can_review?: boolean
  can_backtest?: boolean
  can_revoke?: boolean
}

export type MLRuleDeployScope = 'origin' | 'global'

export interface MLRuleQueue {
  rules: MLPendingRule[]
  is_admin?: boolean
}

export type MLRuleGenerator = 'gen3-detector' | 'rf-regex' | 'cve'

export interface MLRuleBacktest {
  window_days: number
  scanned: number
  matched: number
  example_paths: string[]
  sample_limit: number
  ran_at: string
}


export interface OriginCve {
  cve_id: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN'
  cvss_score: number | null
  matched_tag: string
  description: string
  published: string | null
  last_modified: string | null
}

export interface OriginCveReport {
  cves: OriginCve[]
  total: number
  keywords_searched: string[]
  keywords_skipped: string[]
  window_days: number
}
