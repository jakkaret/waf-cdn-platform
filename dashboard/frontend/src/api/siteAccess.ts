import { api } from './axios'

// A site's own IP access list and rate limits (backend api/site_access.py).

export interface SiteIpRule {
  id: number
  ip: string
  action: 'block' | 'allow'
  note: string
  expires_at: string | null
  created_by: string
  created_at: string
}

export interface SiteIpRuleInput {
  ip: string
  action: 'block' | 'allow'
  note?: string
  hours?: number | null
}

export interface SiteRateRule {
  id: string
  name: string
  path_pattern: string
  method: string
  limit_count: number
  window_seconds: number
  enabled: number
  origin_id: string | null
}

export type SiteRateRuleInput = Pick<SiteRateRule, 'name' | 'path_pattern' | 'method' | 'limit_count' | 'window_seconds'>

export interface ThrottledClient {
  ip: string
  host: string
  rule_id: string
  request_count: number
  ttl_seconds: number
  status: 'throttled' | 'active'
}

export const getSiteIpRules = (originId: string) =>
  api.get<{ rules: SiteIpRule[] }>(`/origins/${originId}/ip-rules`).then((r) => r.data.rules)

export const addSiteIpRule = (originId: string, body: SiteIpRuleInput) =>
  api.post<{ rule: SiteIpRule }>(`/origins/${originId}/ip-rules`, body).then((r) => r.data.rule)

export const deleteSiteIpRule = (originId: string, ruleId: number) =>
  api.delete(`/origins/${originId}/ip-rules/${ruleId}`)

export const getSiteRateRules = (originId: string) =>
  api.get<{ rules: SiteRateRule[] }>(`/origins/${originId}/rate-limits`).then((r) => r.data.rules)

export const addSiteRateRule = (originId: string, body: SiteRateRuleInput) =>
  api.post<{ rule: SiteRateRule }>(`/origins/${originId}/rate-limits`, body).then((r) => r.data.rule)

export const updateSiteRateRule = (originId: string, ruleId: string, body: Partial<SiteRateRuleInput> & { enabled?: boolean }) =>
  api.put<{ rule: SiteRateRule }>(`/origins/${originId}/rate-limits/${ruleId}`, body).then((r) => r.data.rule)

export const deleteSiteRateRule = (originId: string, ruleId: string) =>
  api.delete(`/origins/${originId}/rate-limits/${ruleId}`)

export const getSiteThrottled = (originId: string) =>
  api.get<{ throttled_clients: ThrottledClient[] }>(`/origins/${originId}/rate-limits/throttled`).then((r) => r.data.throttled_clients)
