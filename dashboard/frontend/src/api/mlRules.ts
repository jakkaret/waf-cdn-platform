import { api } from './axios'
import { MLPendingRule, MLRuleBacktest, MLRuleQueue } from '../types'

// A platform admin gets every rule; anyone else only the rules of origins
// they are Owner, Editor or Viewer of.
const listQueue = async (status?: string): Promise<MLRuleQueue> => {
  const params = status ? { status } : {}
  const res = await api.get<MLRuleQueue>('/ml-rules/', { params })
  return res.data
}

export const mlRulesApi = {
  listQueue,

  listRules: async (status?: string): Promise<MLPendingRule[]> => (await listQueue(status)).rules,

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

  // Read-only: how much recent allowed traffic the rule would also match.
  backtestRule: async (id: string, days?: number) => {
    const res = await api.post<{ rule_id: string; backtest: MLRuleBacktest }>(`/ml-rules/${id}/backtest`, undefined, {
      params: days ? { days } : undefined,
    })
    return res.data.backtest
  },

  // Rejects every pending rule from the retired RandomForest path in one call.
  rejectLegacy: async () => {
    const res = await api.post<{ rejected: number; skipped: number }>('/ml-rules/reject-legacy')
    return res.data
  },

  deleteRule: async (id: string) => {
    const res = await api.delete(`/ml-rules/${id}`)
    return res.data
  },

  // CVE Auto-Patch (2026-09-22): admin-triggered, real outbound call to
  // NVD -- never scheduled/background, so this stays a deliberate click.
  runCveScan: async (days?: number) => {
    const res = await api.post('/ml-rules/cve-scan', undefined, {
      params: days ? { days } : undefined,
    })
    return res.data
  },
}
