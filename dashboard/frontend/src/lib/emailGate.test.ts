import { describe, expect, it } from 'vitest'
import { GATE_COPY, formatCountdown, normalizeOtp, parseEmailGate } from './emailGate'

describe('email gate', () => {
  it('recognises the backend 403 for an unverified address', () => {
    const err = { response: { status: 403, data: { detail: { code: 'email_unverified', action: 'invite', message: 'm' } } } }
    expect(parseEmailGate(err)).toEqual({ action: 'invite', message: 'm' })
  })

  it('ignores other errors, including other 403s', () => {
    expect(parseEmailGate({ response: { status: 403, data: { detail: 'Admin access required' } } })).toBeNull()
    expect(parseEmailGate({ response: { status: 400, data: { detail: { code: 'email_unverified' } } } })).toBeNull()
    expect(parseEmailGate(new Error('network'))).toBeNull()
  })

  it('keeps an unknown action as a general gate', () => {
    const err = { response: { status: 403, data: { detail: { code: 'email_unverified', action: 'later_feature' } } } }
    expect(parseEmailGate(err)?.action).toBeNull()
  })

  it('explains every action the backend can block', () => {
    for (const action of ['create_origin', 'add_domain', 'invite', 'accept_invite', 'agent_token', 'ai', 'link_google'] as const) {
      expect(GATE_COPY[action].reasons.length).toBeGreaterThan(0)
    }
  })

  it('saves the amber warning for actions that touch a live site or other people', () => {
    const caution = Object.entries(GATE_COPY).filter(([, c]) => c.level === 'caution').map(([a]) => a).sort()
    expect(caution).toEqual(['add_domain', 'agent_token', 'create_origin', 'invite'])
  })
})

describe('otp helpers', () => {
  it('keeps six digits from typed or pasted text', () => {
    expect(normalizeOtp('123 456')).toBe('123456')
    expect(normalizeOtp('12-34-56-78')).toBe('123456')
    expect(normalizeOtp('abc')).toBe('')
  })

  it('formats the resend countdown', () => {
    expect(formatCountdown(59)).toBe('0:59')
    expect(formatCountdown(61)).toBe('1:01')
    expect(formatCountdown(-3)).toBe('0:00')
  })
})
