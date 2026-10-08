// F-026: the client must match api/threshold_proposals.py -- reject carries a
// JSON body, ids are proposal_id, generate returns { proposal }.
import { describe, it, expect, vi, beforeEach } from 'vitest'

const post = vi.fn()
const get = vi.fn()
vi.mock('./axios', () => ({ api: { post: (...a: unknown[]) => post(...a), get: (...a: unknown[]) => get(...a) } }))

import { thresholdProposalsApi } from './thresholdProposals'

beforeEach(() => {
  post.mockReset()
  get.mockReset()
})

describe('thresholdProposalsApi', () => {
  it('sends the reject reason as a JSON body (the endpoint requires one)', async () => {
    post.mockResolvedValue({ data: {} })
    await thresholdProposalsApi.rejectProposal('p-1')
    expect(post).toHaveBeenCalledWith('/threshold-proposals/p-1/reject', { reason: '' })
  })

  it('returns the single proposal from generate', async () => {
    post.mockResolvedValue({ data: { proposal: { proposal_id: 'p-2', status: 'pending' } } })
    const res = await thresholdProposalsApi.generateProposal()
    expect(res.proposal?.proposal_id).toBe('p-2')
  })

  it('exposes rollback for approved proposals', async () => {
    post.mockResolvedValue({ data: {} })
    await thresholdProposalsApi.rollbackProposal('p-3')
    expect(post).toHaveBeenCalledWith('/threshold-proposals/p-3/rollback')
  })
})
