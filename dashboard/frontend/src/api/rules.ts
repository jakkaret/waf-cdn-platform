import { api } from './axios'
import { WafRule } from '../types'

export const rulesApi = {
  getRules: async () => {
    const res = await api.get<{ rules: WafRule[] }>('/rules/')
    return res.data.rules
  },

  createRule: async (rule: Omit<WafRule, 'id'> & { id?: string }) => {
    const res = await api.post('/rules/', rule)
    return res.data
  },

  updateRule: async (id: string, rule: Partial<WafRule>) => {
    const res = await api.put(`/rules/${id}`, rule)
    return res.data
  },

  deleteRule: async (id: string) => {
    const res = await api.delete(`/rules/${id}`)
    return res.data
  }
}
