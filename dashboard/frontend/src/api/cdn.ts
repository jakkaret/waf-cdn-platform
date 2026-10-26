import { api } from './axios'
import { CdnNode, CdnStats, CdnLog } from '../types'

export const cdnApi = {
  getNodes: async () => {
    const res = await api.get<CdnNode[]>('/cdn/nodes')
    return res.data
  },

  // Backend returns one aggregate object (with a `regional_breakdown` map
  // inside it), never an array -- CdnStats[] here was never the real shape.
  // CDN.tsx already defends against this at the call site (Array.isArray
  // check), so this just makes the declared type stop lying about it too.
  getStats: async () => {
    const res = await api.get<Record<string, any>>('/cdn/stats')
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

  // Queues a purge of one of the caller's verified sites; every edge applies
  // it within a few seconds (services/cdn_purge.py). path: "/page" exact,
  // "/static/*" prefix, "/*" whole site.
  purgeCache: async (host: string, path: string = '/*') => {
    const res = await api.post<{ job_id: number; host: string; path: string }>('/cdn/purge', { host, path })
    return res.data
  },

  getPurgeStatus: async (jobId: number) => {
    const res = await api.get<{ job_id: number; edges: Record<string, PurgeEdgeStatus> }>(`/cdn/purge/${jobId}`)
    return res.data
  },

  // 2026-09-20: this type never matched what the backend actually returns
  // (a flat array of real, measured per-edge round-trip times) -- it
  // described a summary/timeseries shape with fake "SG"/"JP" region keys
  // that don't correspond to any real edge. Fixed to match the real
  // response shape (see api/cdn.py's cdn_latency).
  getLatency: async (region: string = 'ALL', period: string = '1h') => {
    const res = await api.get<
      {
        client_region: string
        edge_ms: number | null
        origin_ms: number
        online: boolean
        status: string
      }[]
    >('/cdn/latency', {
      params: { region, period }
    })
    return res.data
  }
}

// One edge's progress on a purge job: applied it, and whether it is polling
// control-api at all (an edge that is down applies the job when it is back).
export interface PurgeEdgeStatus {
  applied: boolean
  last_poll: number | null
  polling: boolean
}
