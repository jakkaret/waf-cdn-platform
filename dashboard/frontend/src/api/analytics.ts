import { api } from './axios'

export interface SuspiciousIp {
  ip: string
  total: number
  blocked: number
}

export interface AnalyticsSummary {
  source: string
  total_requests: number
  allowed_requests: number
  blocked_requests: number
  average_latency_ms: number
  attack_types: Record<string, number>
  suspicious_ips: SuspiciousIp[]
  ai_summary: string
}

export const analyticsApi = {
  getSummary: async () => {
    const res = await api.get<AnalyticsSummary>('/analytics/summary')
    return res.data
  }
}
