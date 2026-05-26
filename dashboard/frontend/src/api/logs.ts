import { api } from './axios'
import { WafLog } from '../types'

export const logsApi = {
  getRecentLogs: async (limit: number = 100) => {
    const res = await api.get<{ logs: WafLog[] }>('/logs/recent', {
      params: { limit }
    })
    return res.data.logs
  }
}
