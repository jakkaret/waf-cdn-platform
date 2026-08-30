import { api } from './axios'
import { CdnNode, CdnStats, CdnLog } from '../types'

export const cdnApi = {
  getNodes: async () => {
    const res = await api.get<CdnNode[]>('/cdn/nodes')
    return res.data
  },

  getStats: async () => {
    const res = await api.get<CdnStats[]>('/cdn/stats')
    return res.data
  },

  getRegionStats: async (region: string) => {
    const res = await api.get<{ stats: CdnStats; latency_chart: any[]; top_blocked: any[] }>(`/cdn/stats/${region}`)
    return res.data
  },

  getLogs: async (region: string = 'all', limit: number = 50) => {
    const res = await api.get<{ logs: CdnLog[] }>('/cdn/logs', {
      params: { region, limit }
    })
    return res.data.logs
  },

  // The backend holds the purge token and attaches it upstream itself, so the
  // caller only supplies what to purge. It reads url/region as query params.
  purgeCache: async (url_pattern: string = '/*', region: string = 'ALL') => {
    const res = await api.post('/cdn/purge', null, {
      params: { url: url_pattern, region },
    })
    return res.data
  },

  getLatency: async (region: string = 'ALL', period: string = '1h') => {
    const res = await api.get<{
      summary: { region: string; avg_ms: number; p95_ms: number; p99_ms: number }[];
      timeseries: { time: string; SG: number; JP: number; TH: number }[];
    }>('/cdn/latency', {
      params: { region, period }
    })
    return res.data
  }
}
