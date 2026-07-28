import { api } from './axios'

export interface SystemStatusData {
  db: {
    status: 'online' | 'offline'
    detail: string
  }
  services: Record<string, {
    status: 'online' | 'offline'
    port: number
    desc: string
  }>
  cdn_nodes: Array<{
    region: string
    status: 'online' | 'offline'
    port: number
    latency_ms: number
    health: Record<string, any>
  }>
  workers: Record<string, {
    status: 'running' | 'stopped'
    desc: string
  }>
  system: {
    disk_total_gb: number
    disk_used_gb: number
    disk_free_gb: number
    disk_used_percent: number
    load_average: [number, number, number]
  }
}

export const systemApi = {
  getSystemStatus: async (): Promise<SystemStatusData> => {
    const response = await api.get<SystemStatusData>('/system/status')
    return response.data
  }
}
