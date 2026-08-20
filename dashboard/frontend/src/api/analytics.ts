import { api } from './axios'

export interface SuspiciousIp {
  ip: string
  total: number
  blocked: number
}

export interface TopCountry {
  country: string
  name?: string
  flag?: string
  total: number
  blocked: number
}

export interface AnalyticsSummary {
  source: string
  total_requests: number
  allowed_requests: number
  blocked_requests: number
  unique_ips?: number
  average_latency_ms: number
  attack_types: Record<string, number>
  suspicious_ips: SuspiciousIp[]
  top_countries?: TopCountry[]
  ai_summary: string
}

export const analyticsApi = {
  getSummary: async () => {
    const res = await api.get<AnalyticsSummary>('/analytics/summary')
    return res.data
  }
}
