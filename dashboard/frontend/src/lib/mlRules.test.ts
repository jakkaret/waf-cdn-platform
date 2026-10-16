import { describe, expect, it } from 'vitest'
import type { MLPendingRule } from '../types'
import {
  approveWarning,
  backtestView,
  canBacktest,
  describeSuggestion,
  legacyPendingCount,
  filterAndSortRules,
  generatorOf,
  renderSecRule,
  timeAgo,
  type RuleFilters,
} from './mlRules'

const rule = (over: Partial<MLPendingRule>): MLPendingRule => ({
  rule_id: 'r', pattern: '@detectSQLi', variable: 'ARGS', attack_type: 'SQL Injection', severity: 'CRITICAL',
  secrule_template: '', source_url: '/', source_method: 'GET', status: 'pending', created_at: '2026-10-01T00:00:00Z',
  ...over,
})

const bt = (matched: number, scanned: number) => ({
  window_days: 7, scanned, matched, example_paths: [], sample_limit: 5000, ran_at: '2026-10-13T00:00:00Z',
})

describe('generatorOf', () => {
  it('uses the stored generator', () => {
    expect(generatorOf({ generator: 'gen3-detector' })).toBe('gen3-detector')
  })
  it('infers old rows from created_by', () => {
    expect(generatorOf({ created_by: 'cve-auto' })).toBe('cve')
    expect(generatorOf({ created_by: 'ml-auto' })).toBe('rf-regex')
    expect(generatorOf({})).toBe('rf-regex')
  })
  it('never backtests CVE patches', () => {
    expect(canBacktest({ created_by: 'cve-auto' })).toBe(false)
    expect(canBacktest({ generator: 'rf-regex' })).toBe(true)
  })
})

describe('backtestView', () => {
  it('asks for a test when there is none', () => {
    expect(backtestView(undefined).tone).toBe('none')
  })
  it('is clean only with zero matches on real traffic', () => {
    expect(backtestView(bt(0, 4000)).tone).toBe('clean')
    expect(backtestView(bt(0, 0)).tone).toBe('warn')
  })
  it('separates a few matches from a real share of traffic', () => {
    expect(backtestView(bt(3, 4000)).tone).toBe('warn')
    expect(backtestView(bt(40, 4000)).tone).toBe('danger')
    expect(backtestView(bt(40, 4000)).label).toContain('40')
  })
})

describe('approveWarning', () => {
  it('warns when untested or matching, not when clean', () => {
    expect(approveWarning(rule({ generator: 'gen3-detector' }))).toMatch(/ยังไม่ได้ทดสอบ/)
    expect(approveWarning(rule({ generator: 'gen3-detector', backtest: bt(5, 100) }))).toMatch(/403/)
    expect(approveWarning(rule({ generator: 'gen3-detector', backtest: bt(0, 100) }))).toBeNull()
  })
  it('has nothing to say for CVE patches', () => {
    expect(approveWarning(rule({ created_by: 'cve-auto' }))).toBeNull()
  })
})

describe('filterAndSortRules', () => {
  const base: RuleFilters = { status: 'all', generator: 'all', attackType: 'all', search: '', sort: 'hits' }
  const rules = [
    rule({ rule_id: 'a', hit_count: 2, generator: 'gen3-detector', created_at: '2026-10-01T00:00:00Z' }),
    rule({ rule_id: 'b', hit_count: 9, generator: 'gen3-detector', attack_type: 'Cross-Site Scripting', created_at: '2026-09-01T00:00:00Z' }),
    rule({ rule_id: 'c', status: 'rejected', created_by: 'cve-auto', cve_id: 'CVE-2026-1', created_at: '2026-10-05T00:00:00Z' }),
    rule({ rule_id: 'd', created_at: '2026-10-09T00:00:00Z' }),
  ]
  const ids = (f: Partial<RuleFilters>) => filterAndSortRules(rules, { ...base, ...f }).map((r) => r.rule_id)

  it('sorts by hits, then newest', () => {
    expect(ids({})).toEqual(['b', 'a', 'd', 'c'])
    expect(ids({ sort: 'newest' })).toEqual(['d', 'c', 'a', 'b'])
  })
  it('filters by status, generator and attack type', () => {
    expect(ids({ status: 'rejected' })).toEqual(['c'])
    expect(ids({ generator: 'rf-regex' })).toEqual(['d'])
    expect(ids({ attackType: 'Cross-Site Scripting' })).toEqual(['b'])
  })
  it('searches ids, patterns and CVE ids', () => {
    expect(ids({ search: 'cve-2026' })).toEqual(['c'])
    expect(ids({ search: '  B ' })).toEqual(['b'])
  })
})

describe('timeAgo', () => {
  const now = Date.parse('2026-10-13T12:00:00Z')
  it('picks the largest whole unit', () => {
    expect(timeAgo('2026-10-13T09:00:00Z', now)).toBe(new Intl.RelativeTimeFormat('th', { numeric: 'auto' }).format(-3, 'hour'))
    expect(timeAgo('2026-10-13T11:59:30Z', now)).toBe(new Intl.RelativeTimeFormat('th', { numeric: 'auto' }).format(0, 'minute'))
  })
  it('is empty for missing or bad input', () => {
    expect(timeAgo(undefined, now)).toBe('')
    expect(timeAgo('not a date', now)).toBe('')
  })
})

describe('describeSuggestion', () => {
  it('reports what was queued', () => {
    expect(describeSuggestion({ engine: 'gen3', created: 1, merged: 2, reason: '' })).toEqual({
      queued: true,
      text: 'เสนอกฎใหม่ 1 ข้อ และ เพิ่มหลักฐานให้กฎที่รออนุมัติ 2 ข้อ',
    })
  })
  it('explains why nothing was queued', () => {
    expect(describeSuggestion({ engine: 'gen3', created: 0, merged: 0, reason: 'gen3_no_detector' }).text).toMatch(/detector/)
    expect(describeSuggestion({ engine: 'gen3', created: 0, merged: 0, reason: 'something_new' }).text).toBe('ไม่มีกฎที่เสนอ')
    expect(describeSuggestion(undefined).queued).toBe(false)
  })
})

describe('legacyPendingCount', () => {
  it('counts only pending rules from the RandomForest path, old rows included', () => {
    expect(
      legacyPendingCount([
        { status: 'pending', generator: 'rf-regex' },
        { status: 'pending', created_by: 'ml-auto' },
        { status: 'rejected', generator: 'rf-regex' },
        { status: 'pending', generator: 'gen3-detector' },
        { status: 'pending', created_by: 'cve-auto' },
      ]),
    ).toBe(2)
  })
})

describe('renderSecRule (H55)', () => {
  it('fills every {RULE_ID}, like the backend does on approve', () => {
    const tpl = 'SecRule ARGS "@rx x" "id:{RULE_ID},deny,msg:\'rule {RULE_ID}\'"'
    expect(renderSecRule({ secrule_template: tpl, deployed_rule_id: 1000501 })).toBe(
      'SecRule ARGS "@rx x" "id:1000501,deny,msg:\'rule 1000501\'"',
    )
  })
  it('uses PENDING_ID before approval', () => {
    expect(renderSecRule({ secrule_template: 'id:{RULE_ID} {RULE_ID}' })).toBe('id:PENDING_ID PENDING_ID')
  })
})
