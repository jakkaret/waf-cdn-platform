import { api } from './axios'

// Mirrors api/threshold_proposals.py: a proposal changes the inbound anomaly
// threshold of ONE origin, and only that origin's Owner may generate, approve,
// reject or roll it back (can_review). Status lifecycle:
// pending -> approved | rejected, approved -> rolled_back.
export type ThresholdProposalStatus = 'pending' | 'approved' | 'rejected' | 'rolled_back'

export interface ThresholdProposal {
  proposal_id: string
  origin_id: string
  status: ThresholdProposalStatus
  current_threshold: number
  proposed_threshold: number
  reason: string
  can_review: boolean
  lookback_hours?: number
  created_at?: string
  previous_threshold?: number
  reject_reason?: string
  evidence?: { hosts?: string[]; total_requests?: number; blocked_requests?: number; block_rate_pct?: number }
}

export interface TunableOrigin {
  origin_id: string
  label: string
  role: 'owner' | 'editor' | 'viewer'
  hosts: string[]
  // null: the origin uses the platform threshold
  anomaly_threshold: number | null
  effective_threshold: number
}

export const thresholdProposalsApi = {
  getOrigins: async (): Promise<{ platform_threshold: number; origins: TunableOrigin[] }> => {
    const res = await api.get('/threshold-proposals/origins')
    return res.data
  },
  getProposals: async (originId: string): Promise<ThresholdProposal[]> => {
    const res = await api.get<{ proposals: ThresholdProposal[] }>('/threshold-proposals/', { params: { origin_id: originId } })
    return res.data.proposals
  },
  // Returns at most one proposal; null (with the reason) when there is nothing to propose.
  generateProposal: async (originId: string): Promise<{ proposal: ThresholdProposal | null; message?: string }> => {
    const res = await api.post('/threshold-proposals/generate', null, { params: { origin_id: originId } })
    return res.data
  },
  approveProposal: async (id: string): Promise<any> => {
    const res = await api.post(`/threshold-proposals/${id}/approve`)
    return res.data
  },
  // The endpoint requires a JSON body (RejectRequest); reason may be empty.
  rejectProposal: async (id: string, reason = ''): Promise<any> => {
    const res = await api.post(`/threshold-proposals/${id}/reject`, { reason })
    return res.data
  },
  rollbackProposal: async (id: string): Promise<any> => {
    const res = await api.post(`/threshold-proposals/${id}/rollback`)
    return res.data
  },
}
