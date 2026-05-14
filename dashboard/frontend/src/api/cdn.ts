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

  purgeCache: async (token: string, url_pattern: string = '/*') => {
    const res = await api.post('/cdn/purge', { url_pattern }, {
      headers: {
        'Authorization': `Bearer ${token}` // Typically the CDN secret token
      }
    })
    return res.data
  }
}
