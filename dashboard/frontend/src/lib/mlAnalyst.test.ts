import { describe, expect, it } from 'vitest'
import { detectorNote, formatPercent, scoreBar, verdictView } from './mlAnalyst'

const gen3Attack = {
  attack_probability: 1,
  is_attack: true,
  threshold: 0.8749,
  detectors: [{ detector: 'v_sqli_libinjection', attack_type: 'SQL Injection', severity: 'CRITICAL' }],
}
const gen3Clean = { attack_probability: 0.12, is_attack: false, threshold: 0.8749, detectors: [] }

describe('verdictView', () => {
  it('shows the Gen 3 verdict, score and threshold', () => {
    expect(verdictView(gen3Attack)).toMatchObject({ isAttack: true, score: 1, threshold: 0.8749 })
    expect(verdictView(gen3Clean)).toMatchObject({ isAttack: false, title: 'ดูเป็น request ปกติ' })
  })

  it('returns null without a Gen 3 answer', () => {
    expect(verdictView(null)).toBeNull()
    expect(verdictView({ attack_probability: 1 } as never)).toBeNull()
  })
})

describe('scoreBar', () => {
  it('clamps to the bar and keeps the threshold marker', () => {
    expect(scoreBar(1.2, 0.8749)).toEqual({ score: 100, threshold: 87.49 })
    expect(scoreBar(0.3, null)).toEqual({ score: 30, threshold: null })
    expect(scoreBar(null, 0.5)).toBeNull()
  })
})

describe('detectorNote', () => {
  it('explains a verdict reached on structure alone', () => {
    expect(detectorNote({ ...gen3Attack, detectors: [] })).toContain('ไม่เสนอกฎ')
  })

  it('explains a detector hit below the threshold', () => {
    expect(detectorNote({ ...gen3Clean, detectors: gen3Attack.detectors })).toContain('ต่ำกว่าเกณฑ์')
  })

  it('says when an older ML host sent no detectors', () => {
    expect(detectorNote({ attack_probability: 1, is_attack: true, threshold: 0.8 })).toContain('ยังไม่ส่ง')
  })

  it('is empty without Gen 3', () => {
    expect(detectorNote(null)).toBe('')
  })
})

describe('formatPercent', () => {
  it('never renders NaN', () => {
    expect(formatPercent(Number.NaN)).toBe('N/A')
    expect(formatPercent(0.87491)).toBe('87.49%')
  })
})
