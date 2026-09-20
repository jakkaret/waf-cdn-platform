import { api } from './axios'

export interface TrendingPattern {
  rule_id: string
  attack_type: string | null
  total_hits: number
  distinct_tenants: number
  window_hours: number
}

export const threatIntelApi = {
  setOptIn: async (enabled: boolean): Promise<{ share_threat_intel: boolean }> => {
    const res = await api.patch<{ share_threat_intel: boolean }>('/threat-intel/opt-in', { enabled })
    return res.data
  },

  // 403 when the current user has not opted in -- callers should catch
  // that and show "opt in to see this" rather than treating it as a
  // generic error.
  getTrending: async (): Promise<TrendingPattern[]> => {
    const res = await api.get<{ patterns: TrendingPattern[] }>('/threat-intel/trending')
    return res.data.patterns
  },
}
