import { describe, expect, it } from 'vitest'
import type { MLPendingRule, Origin } from '../types'
import {
  GLOBAL_SCOPE_LABEL,
  analystOriginChoices,
  approveScope,
  approveWarning,
  backtestView,
  canBacktest,
  canBacktestRule,
  canReviewRule,
  canRevokeRule,
  cveScanOriginChoices,
  defaultAnalystOrigin,
  deployScopeOf,
  describeSuggestion,
  ruleOriginLabel,
  ruleOriginOptions,
  legacyPendingCount,
  filterAndSortRules,
  generatorOf,
  renderSecRule,
  revokeScope,
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
  it('filters by origin, "" being the global rules', () => {
    const mixed = [
      rule({ rule_id: 'g' }),
      rule({ rule_id: 'o1', origin_id: 'o1', origin_label: 'shop.example.com' }),
      rule({ rule_id: 'o2', origin_id: 'o2', origin_label: 'blog.example.com' }),
    ]
    const by = (origin?: string) => filterAndSortRules(mixed, { ...base, origin }).map((r) => r.rule_id).sort()
    expect(by(undefined)).toEqual(['g', 'o1', 'o2'])
    expect(by('all')).toEqual(['g', 'o1', 'o2'])
    expect(by('o1')).toEqual(['o1'])
    expect(by('')).toEqual(['g'])
    expect(filterAndSortRules(mixed, { ...base, search: 'blog.' }).map((r) => r.rule_id)).toEqual(['o2'])
  })
})

describe('deploy scope', () => {
  it('uses deploy_scope, else infers it from origin_id', () => {
    expect(deployScopeOf({ deploy_scope: 'global', origin_id: 'o1' })).toBe('global')
    expect(deployScopeOf({ origin_id: 'o1' })).toBe('origin')
    expect(deployScopeOf({ origin_id: '' })).toBe('global')
    expect(deployScopeOf({})).toBe('global')
  })
  it('labels the origin, or the platform for global rules', () => {
    expect(ruleOriginLabel({ origin_id: 'o1', origin_label: 'shop.example.com' })).toBe('shop.example.com')
    expect(ruleOriginLabel({ origin_id: 'o1' })).toBe('o1')
    expect(ruleOriginLabel({ origin_id: '', origin_label: 'ignored' })).toBe(GLOBAL_SCOPE_LABEL)
  })
})

describe('approveScope', () => {
  const shop = { origin_id: 'o1', origin_label: 'shop.example.com', deploy_scope: 'origin' as const }
  const blog = { origin_id: 'o2', origin_label: 'blog.example.com', deploy_scope: 'origin' as const }
  const global = { origin_id: '', deploy_scope: 'global' as const }
  it('names the one origin an origin rule affects', () => {
    expect(approveScope([shop])).toBe('กฎนี้จะมีผลเฉพาะ shop.example.com')
    expect(approveScope([shop, shop])).toBe('กฎ 2 ข้อจะมีผลเฉพาะ shop.example.com')
  })
  it('says a global rule affects every origin', () => {
    expect(approveScope([global])).toMatch(/^กฎนี้จะมีผลกับ ModSecurity ของทุก origin/)
    expect(approveScope([global, global])).toMatch(/^กฎ 2 ข้อจะมีผลกับ ModSecurity ของทุก origin/)
  })
  it('lists the origins of a mixed selection', () => {
    expect(approveScope([shop, blog])).toContain('shop.example.com, blog.example.com')
    const mixed = approveScope([global, shop])
    expect(mixed).toContain('1 ข้อมีผลกับทุก origin')
    expect(mixed).toContain('shop.example.com')
  })
})

describe('canReviewRule / canBacktestRule', () => {
  it('follows the per-rule flags', () => {
    expect(canReviewRule({ status: 'pending', can_review: true }, false)).toBe(true)
    expect(canReviewRule({ status: 'pending', can_review: false }, true)).toBe(false)
    expect(canReviewRule({ status: 'approved', can_review: true }, true)).toBe(false)
    expect(canBacktestRule({ generator: 'gen3-detector', can_backtest: true }, false)).toBe(true)
    expect(canBacktestRule({ generator: 'gen3-detector', can_backtest: false }, true)).toBe(false)
  })
  it('falls back to admin-only without the flags, and never backtests CVE patches', () => {
    expect(canReviewRule({ status: 'pending' }, true)).toBe(true)
    expect(canReviewRule({ status: 'pending' }, false)).toBe(false)
    expect(canBacktestRule({ generator: 'gen3-detector' }, false)).toBe(false)
    expect(canBacktestRule({ created_by: 'cve-auto', can_backtest: true }, true)).toBe(false)
  })
})

describe('ruleOriginOptions', () => {
  it('lists each origin once, sorted by label, global as ""', () => {
    expect(
      ruleOriginOptions([
        { origin_id: 'o2', origin_label: 'shop' },
        { origin_id: '' },
        { origin_id: 'o1', origin_label: 'blog' },
        { origin_id: 'o2', origin_label: 'shop' },
      ]),
    ).toEqual([
      { id: 'o1', label: 'blog' },
      { id: '', label: GLOBAL_SCOPE_LABEL },
      { id: 'o2', label: 'shop' },
    ])
  })
})

describe('analystOriginChoices / defaultAnalystOrigin', () => {
  const origin = (origin_id: string, over: Partial<Origin> = {}) => ({
    origin_id, label: `${origin_id}.example.com`, status: 'active' as Origin['status'], admin_user_id: 'owner',
    editor_user_ids: ['editor'], viewer_user_ids: ['viewer'], ...over,
  })
  it('keeps origins the user owns or edits, not viewed or archived ones', () => {
    const origins = [origin('a'), origin('b', { status: 'archived' }), origin('c', { admin_user_id: 'other', editor_user_ids: [] })]
    expect(analystOriginChoices(origins, 'owner').map((c) => c.id)).toEqual(['a'])
    expect(analystOriginChoices(origins, 'editor').map((c) => c.id)).toEqual(['a'])
    expect(analystOriginChoices(origins, 'viewer')).toEqual([])
    expect(analystOriginChoices(origins, undefined)).toEqual([])
  })
  it('starts an admin on global and anyone else on their first origin', () => {
    const choices = [{ id: 'a', label: 'a' }, { id: 'b', label: 'b' }]
    expect(defaultAnalystOrigin(choices, true)).toBe('')
    expect(defaultAnalystOrigin(choices, false)).toBe('a')
    expect(defaultAnalystOrigin([], false)).toBe('')
  })
  it('lists CVE-scan origins with whether they have tech stack tags', () => {
    const origins = [origin('a', { tech_stack_tags: ['nginx'] }), origin('b'), origin('c', { status: 'archived', tech_stack_tags: ['php'] })]
    expect(cveScanOriginChoices(origins, 'editor')).toEqual([
      { id: 'a', label: 'a.example.com', hasTags: true },
      { id: 'b', label: 'b.example.com', hasTags: false },
    ])
    expect(cveScanOriginChoices(origins, 'viewer')).toEqual([])
  })
})

describe('canRevokeRule / revokeScope', () => {
  it('needs an approved rule the backend lets the caller revoke', () => {
    expect(canRevokeRule(rule({ status: 'approved', can_revoke: true }))).toBe(true)
    expect(canRevokeRule(rule({ status: 'approved', can_revoke: false }))).toBe(false)
    expect(canRevokeRule(rule({ status: 'approved' }))).toBe(false)
    expect(canRevokeRule(rule({ status: 'revoked', can_revoke: true }))).toBe(false)
  })
  it('says where the rule stops', () => {
    expect(revokeScope(rule({ origin_id: 'o1', origin_label: 'shop', deploy_scope: 'origin' }))).toBe('กฎนี้จะหยุดทำงานกับ shop ทันที')
    expect(revokeScope(rule({ origin_id: 'o1', origin_label: 'shop', deploy_scope: 'global' }))).toBe('กฎนี้จะหยุดทำงานกับทุก origin ทันที')
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
  it('says where a queued proposal went', () => {
    const s = { engine: 'gen3' as const, created: 1, merged: 0, reason: '' }
    expect(describeSuggestion(s, 'shop.example.com').text).toBe('เสนอกฎใหม่ 1 ข้อ สำหรับ shop.example.com')
    expect(describeSuggestion(s, null).text).toBe('เสนอกฎใหม่ 1 ข้อ ในคิวของผู้ดูแลแพลตฟอร์ม')
    expect(describeSuggestion({ ...s, created: 0 }, 'shop.example.com').text).toBe('ไม่มีกฎที่เสนอ')
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
