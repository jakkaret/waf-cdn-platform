import { describe, expect, it } from 'vitest'
import {
  detectorLabel, emptyReason, flaggedShare, histogramBars, proposeHint, requestTarget, scorePoints, statusView, suggestReasonText,
} from './mlInsights'

describe('proposeHint', () => {
  it('explains a missing propose button to an Owner/Editor only', () => {
    expect(proposeHint({ can_edit: true, can_propose: true, action: null, is_attack: true })).toBe('')
    expect(proposeHint({ can_edit: true, can_propose: false, action: 'block', is_attack: true })).toMatch(/บล็อก/)
    expect(proposeHint({ can_edit: true, can_propose: false, action: null, is_attack: false })).toMatch(/ต่ำกว่าเกณฑ์/)
    expect(proposeHint({ can_edit: false, can_propose: false, action: null, is_attack: true })).toBe('')
  })

  it('names why nothing was proposed', () => {
    expect(suggestReasonText('gen3_no_detector')).toMatch(/detector/)
    expect(suggestReasonText('')).toBe('')
  })
})

const summary = { total: 2000, flagged: 3, watch: 10, hosts: 1, last_seen: null, threshold: 0.8749, feature_set: null }

describe('scorePoints', () => {
  it('shows a score as points out of 100', () => {
    expect(scorePoints(0.99318)).toBe('99.3')
    expect(scorePoints(1.2)).toBe('100.0')
    expect(scorePoints(null)).toBe('-')
  })
})

describe('flaggedShare', () => {
  it('keeps a tiny share visible instead of rounding to zero', () => {
    expect(flaggedShare({ ...summary, flagged: 1 })).toBe('<0.1%')
    expect(flaggedShare(summary)).toBe('0.1%')
    expect(flaggedShare({ ...summary, total: 0, flagged: 0 })).toBe('0%')
    expect(flaggedShare({ ...summary, total: 10, flagged: 5 })).toBe('50%')
  })
})

describe('histogramBars', () => {
  it('marks the bins that reach the model threshold', () => {
    const bins = [
      { from: 0.8, to: 0.85, count: 4, flagged: 0 },
      { from: 0.85, to: 0.9, count: 2, flagged: 1 },
      { from: 0.95, to: 1, count: 1, flagged: 1 },
    ]
    expect(histogramBars(bins, 0.8749).map((b) => [b.label, b.atOrAbove])).toEqual([
      ['80-85', false], ['85-90', true], ['95-100', true],
    ])
    expect(histogramBars(bins, null).every((b) => !b.atOrAbove)).toBe(true)
  })
})

describe('statusView', () => {
  it('says what the WAF answered, or that the log row is not there yet', () => {
    expect(statusView(403)).toEqual({ text: '403 ถูกบล็อก', tone: 'blocked' })
    expect(statusView(200)).toEqual({ text: '200', tone: 'ok' })
    expect(statusView(null).tone).toBe('unknown')
  })

  it('names the inline gate as the one that blocked or challenged', () => {
    expect(statusView(403, 'block')).toEqual({ text: '403 ML บล็อก', tone: 'blocked' })
    expect(statusView(null, 'challenge').text).toBe('ML ส่ง challenge')
    expect(statusView(200, 'pass')).toEqual({ text: '200', tone: 'ok' })
    expect(statusView(200, null)).toEqual({ text: '200', tone: 'ok' })
  })
})

describe('labels', () => {
  it('names known detectors and passes unknown ones through', () => {
    expect(detectorLabel('v_sqli_libinjection')).toBe('SQL Injection')
    expect(detectorLabel('v_new_detector')).toBe('v_new_detector')
  })

  it('joins path and redacted query', () => {
    expect(requestTarget({ path: '/a', query: 'q=1' })).toBe('/a?q=1')
    expect(requestTarget({ path: '/a', query: '' })).toBe('/a')
  })

  it('explains an empty view', () => {
    expect(emptyReason({ ...summary, total: 0 }, false, false)).toContain('origin')
    expect(emptyReason({ ...summary, total: 0 }, true, false)).toContain('traffic')
    expect(emptyReason(summary, true, false)).toBe('')
  })
})
