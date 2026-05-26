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
}

export interface WafAlert {
  user_id: string
  alert_id: string
  ip: string
  url: string
  status: string
  message: string
  timestamp: string
}

export interface CdnNode {
  region: 'SG' | 'JP' | 'TH'
  name?: string
  flag?: string
  port: number
  status: 'online' | 'offline' | 'degraded'
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
