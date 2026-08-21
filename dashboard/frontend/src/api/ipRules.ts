import { api } from './axios'

export interface IPRule {
  id: number
  ip: string
  rule_type: 'block' | 'allow'
  reason: string
  added_by: string
  created_at: number
  expires_at: number | null
  remaining_seconds: number | null
  hits: number
  source: string
}

export interface IPRulesResponse {
  rules: IPRule[]
  stats: {
    total_blocked: number
    total_allowed: number
    temp_banned: number
    permanent_blocked: number
  }
}

export const ipRulesApi = {
  getRules: async (ruleType: string = 'all', search?: string): Promise<IPRulesResponse> => {
    const params = new URLSearchParams()
    if (ruleType && ruleType !== 'all') params.append('rule_type', ruleType)
    if (search) params.append('search', search)
    const res = await api.get<IPRulesResponse>(`/ip-rules/?${params.toString()}`)
    return res.data
  },

  addRule: async (data: {
    ip: string
    rule_type: 'block' | 'allow'
    reason: string
    duration_seconds?: number | null
    source?: string
  }) => {
    const res = await api.post('/ip-rules/', data)
    return res.data
  },

  deleteRule: async (ip: string) => {
    const res = await api.delete(`/ip-rules/${encodeURIComponent(ip)}`)
    return res.data
  },

  bulkDelete: async (ips: string[]) => {
    const res = await api.post('/ip-rules/bulk-delete', { ips })
    return res.data
  },
}
