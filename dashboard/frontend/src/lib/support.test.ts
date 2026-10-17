import { describe, expect, it } from 'vitest'
import { activeGrant, grantSummary, remainingText, type SupportGrant } from './support'

const now = new Date('2026-10-17T10:00:00Z')
const g = (over: Partial<SupportGrant>): SupportGrant => ({
  grant_id: 'g', level: 'viewer', created_at: '2026-10-17T09:00:00Z',
  expires_at: '2026-10-17T13:20:00Z', revoked_at: null, active: true, ...over,
})

describe('remainingText', () => {
  it('formats hours and minutes', () => {
    expect(remainingText('2026-10-17T13:20:00Z', now)).toBe('3h 20m left')
    expect(remainingText('2026-10-17T12:00:00Z', now)).toBe('2h left')
    expect(remainingText('2026-10-17T10:45:00Z', now)).toBe('45m left')
  })
  it('says expired once past', () => {
    expect(remainingText('2026-10-17T09:59:00Z', now)).toBe('expired')
  })
})

describe('grantSummary', () => {
  it('describes no access', () => {
    expect(grantSummary([g({ active: false })], now)).toBe('Support has no access to this origin')
  })
  it('describes the active grant', () => {
    expect(grantSummary([g({ level: 'editor' })], now)).toBe('Support access: can edit (3h 20m left)')
    expect(activeGrant([g({ active: false }), g({ grant_id: 'b' })])?.grant_id).toBe('b')
  })
})
