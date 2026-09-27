import { api } from './axios'

export interface ThresholdProposal {
  id: string
  rule_id: string
  current_threshold: number
  proposed_threshold: number
  reason: string
  status: 'PENDING' | 'APPROVED' | 'REJECTED'
}

export const thresholdProposalsApi = {
  getProposals: async (): Promise<ThresholdProposal[]> => {
    // There is no explicit GET in the list above, let's assume it exists or generate triggers it
    const res = await api.get<{ proposals: ThresholdProposal[] }>('/threshold-proposals/')
    return res.data.proposals
  },
  generateProposals: async (): Promise<{ proposals: ThresholdProposal[] }> => {
    const res = await api.post('/threshold-proposals/generate')
    return res.data
  },
  approveProposal: async (id: string): Promise<any> => {
    const res = await api.post(`/threshold-proposals/${id}/approve`)
    return res.data
  },
  rejectProposal: async (id: string): Promise<any> => {
    const res = await api.post(`/threshold-proposals/${id}/reject`)
    return res.data
  }
}
