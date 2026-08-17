import { api } from './axios'
import { MLPendingRule } from '../types'

export const mlRulesApi = {
  listRules: async (status?: string) => {
    const params = status ? { status } : {}
    const res = await api.get<{ rules: MLPendingRule[] }>('/ml-rules/', { params })
    return res.data.rules
  },

  getRule: async (id: string) => {
    const res = await api.get<MLPendingRule>(`/ml-rules/${id}`)
    return res.data
  },

  approveRule: async (id: string) => {
    const res = await api.post(`/ml-rules/${id}/approve`)
    return res.data
  },

  rejectRule: async (id: string, reason?: string) => {
    const res = await api.post(`/ml-rules/${id}/reject`, { reason })
    return res.data
  },

  deleteRule: async (id: string) => {
    const res = await api.delete(`/ml-rules/${id}`)
    return res.data
  }
}
