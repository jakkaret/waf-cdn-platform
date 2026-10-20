import { describe, expect, it } from 'vitest'
import { confidenceLabel, toLogExplanation } from './logExplanation'

describe('toLogExplanation', () => {
  it('reads the structured explanation the API returns', () => {
    const r = toLogExplanation({
      log_id: 'x',
      explanation: {
        matched_token: "' OR '1'='1",
        category: 'SQL Injection',
        root_cause_explanation: 'Tautology in the id parameter',
        remediation_hint: 'Use parameterised queries',
        confidence_score: 0.92,
        explain_summary: 'SQL injection attempt blocked',
      },
    })
    expect(r).toEqual({
      summary: 'SQL injection attempt blocked',
      category: 'SQL Injection',
      matchedToken: "' OR '1'='1",
      rootCause: 'Tautology in the id parameter',
      remediation: 'Use parameterised queries',
      confidence: 0.92,
    })
  })

  it('never hands an object to JSX: every field is a string or a number', () => {
    const r = toLogExplanation({ explanation: { explain_summary: 'x', matched_token: '', confidence_score: 'n/a' } })
    for (const v of Object.values(r).filter((v) => v !== undefined)) expect(['string', 'number']).toContain(typeof v)
    expect(r.matchedToken).toBeUndefined()
    expect(r.confidence).toBeUndefined()
  })

  it('falls back to the root cause, then to a fixed text', () => {
    expect(toLogExplanation({ explanation: { root_cause_explanation: 'why' } }).summary).toBe('why')
    expect(toLogExplanation({ explanation: {} }).summary).toBe('No explanation available')
    expect(toLogExplanation(null).summary).toBe('No explanation available')
  })

  it('keeps a plain-text explanation or analysis as the summary', () => {
    expect(toLogExplanation({ explanation: 'plain' })).toEqual({ summary: 'plain' })
    expect(toLogExplanation({ analysis: 'from analysis' })).toEqual({ summary: 'from analysis' })
  })

  it('clamps the confidence to 0..1', () => {
    expect(toLogExplanation({ explanation: { explain_summary: 's', confidence_score: 7 } }).confidence).toBe(1)
    expect(confidenceLabel(0.856)).toBe('86%')
    expect(confidenceLabel(undefined)).toBeUndefined()
  })
})
