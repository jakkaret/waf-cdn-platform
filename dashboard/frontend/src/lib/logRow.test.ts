import { describe, expect, it } from 'vitest'
import { isMlAction, logOutcome, realRuleId } from './logRow'

describe('logOutcome', () => {
  it('names what the WAF did, not a threat level', () => {
    expect(logOutcome(403)).toBe('blocked')
    expect(logOutcome(429)).toBe('rate_limited')
    expect(logOutcome(502)).toBe('error')
    expect(logOutcome(404)).toBe('allowed')
    expect(logOutcome(301)).toBe('allowed')
  })
})

describe('realRuleId', () => {
  it('keeps a real rule id', () => {
    expect(realRuleId('920270')).toBe('920270')
  })

  it('drops the generic placeholder and empty values', () => {
    expect(realRuleId('WAF-CRS')).toBeNull()
    expect(realRuleId('')).toBeNull()
    expect(realRuleId(null)).toBeNull()
  })

  it('never shows the ML gate as a ModSecurity rule', () => {
    expect(realRuleId('ML-GEN3')).toBeNull()
  })
})

describe('isMlAction', () => {
  it('is only the ML gate marker', () => {
    expect(isMlAction('ML-GEN3')).toBe(true)
    expect(isMlAction(' ML-GEN3 ')).toBe(true)
    expect(isMlAction('WAF-CRS')).toBe(false)
    expect(isMlAction('920420')).toBe(false)
    expect(isMlAction(null)).toBe(false)
  })
})
