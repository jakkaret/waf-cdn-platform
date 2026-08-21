import { api } from './axios'

export interface RateRule {
  id: string
  name: string
  path_pattern: string
  method: string
  limit_count: number
  window_seconds: number
  burst: number
  action: string
  enabled: number
  created_at: number
}

export interface ThrottledClient {
  ip: string
  request_count: number
  ttl_seconds: number
  status: string
  window_sample: string
}

export const rateLimitsApi = {
  getRules: async (): Promise<RateRule[]> => {
    const res = await api.get<{ rules: RateRule[] }>('/rate-limits/rules')
    return res.data.rules
  },

  createRule: async (data: Omit<RateRule, 'id' | 'created_at' | 'enabled'> & { burst?: number }) => {
    const res = await api.post('/rate-limits/rules', data)
    return res.data
  },

  updateRule: async (ruleId: string, data: Partial<RateRule>) => {
    const res = await api.put(`/rate-limits/rules/${ruleId}`, data)
    return res.data
  },

  deleteRule: async (ruleId: string) => {
    const res = await api.delete(`/rate-limits/rules/${ruleId}`)
    return res.data
  },

  getThrottledClients: async (): Promise<ThrottledClient[]> => {
    const res = await api.get<{ throttled_clients: ThrottledClient[] }>('/rate-limits/throttled')
    return res.data.throttled_clients
  },

  resetClient: async (ip: string) => {
    const res = await api.post('/rate-limits/reset-client', { ip })
    return res.data
  },
}
