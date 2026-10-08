import { api } from './axios'

// Mirrors services/threshold_proposal_service.py: a proposal is a change to
// the global inbound anomaly threshold, keyed by proposal_id, with a lowercase
// status lifecycle pending -> approved | rejected, approved -> rolled_back.
export type ThresholdProposalStatus = 'pending' | 'approved' | 'rejected' | 'rolled_back'

export interface ThresholdProposal {
  proposal_id: string
  status: ThresholdProposalStatus
  current_threshold: number
  proposed_threshold: number
  reason: string
  lookback_hours?: number
  created_at?: string
  previous_threshold?: number
  reject_reason?: string
}

export const thresholdProposalsApi = {
  getProposals: async (): Promise<ThresholdProposal[]> => {
    const res = await api.get<{ proposals: ThresholdProposal[] }>('/threshold-proposals/')
    return res.data.proposals
  },
  // Returns at most one proposal; null (with a message) when no safe change exists.
  generateProposal: async (): Promise<{ proposal: ThresholdProposal | null; message?: string }> => {
    const res = await api.post('/threshold-proposals/generate')
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
