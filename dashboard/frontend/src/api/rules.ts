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
  },

  syncRules: async () => {
    const res = await api.post('/rules/sync')
    return res.data
  },

  blastRadius: async (payload: { variable: string; operator: string; severity: string }): Promise<any> => {
    const res = await api.post('/rules/blast-radius', payload)
    return res.data
  },

  getBolaPolicies: async () => {
    // GET lists; POST on the same path creates a policy (admin-only).
    const res = await api.get('/rules/bola/policies')
    return res.data
  }
}
