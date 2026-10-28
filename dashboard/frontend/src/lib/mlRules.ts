// Pure helpers behind the ML anomaly rules page and the AI analyst's
// suggestion toast. Kept out of the components so every branch is unit-tested.
import type { MLPendingRule, MLRuleBacktest, MLRuleGenerator, Origin } from '../types'
import { canEditOrigin, originRoleOf } from './roles'

// Text helpers take the UI language last; Thai is the default because the
// copy was written (and is tested) in Thai first.
type Lang = 'en' | 'th'
const L = (lang: Lang, th: string, en: string) => (lang === 'th' ? th : en)

export const GENERATOR_LABEL: Record<MLRuleGenerator, string> = {
  'gen3-detector': 'Gen3 detector',
  'rf-regex': 'แบบเก่า',
  cve: 'CVE patch',
}

export const GENERATOR_LABEL_EN: Record<MLRuleGenerator, string> = {
  'gen3-detector': 'Gen3 detector',
  'rf-regex': 'Legacy',
  cve: 'CVE patch',
}

export const GENERATOR_HINT_EN: Record<MLRuleGenerator, string> = {
  'gen3-detector': 'A broad rule from a Gen 3 detector; it applies to every request with the same pattern.',
  'rf-regex': 'A legacy rule from before Gen 3: a stock regex or the first 40 characters of the source request, which usually matches only that request. No new rule of this kind is created.',
  cve: 'A virtual patch for a CVE that matches the origin’s tech stack.',
}

export const generatorLabel = (g: MLRuleGenerator, lang: Lang = 'th') => (lang === 'th' ? GENERATOR_LABEL[g] : GENERATOR_LABEL_EN[g])
export const generatorHint = (g: MLRuleGenerator, lang: Lang = 'th') => (lang === 'th' ? GENERATOR_HINT[g] : GENERATOR_HINT_EN[g])

export const GENERATOR_HINT: Record<MLRuleGenerator, string> = {
  'gen3-detector': 'กฎกว้างจาก detector ของ Gen 3 ใช้กับทุก request ที่มีรูปแบบเดียวกัน',
  // Written by the RandomForest path, retired 2026-10-13: no new rule of this kind is created.
  'rf-regex': 'กฎแบบเก่าก่อนเปลี่ยนมาใช้ Gen 3: regex สำเร็จรูป หรือข้อความ 40 ตัวแรกของ request ต้นทาง มักตรงแค่ request นั้น ระบบไม่สร้างกฎแบบนี้แล้ว',
  cve: 'virtual patch จาก CVE ที่ตรงกับ tech stack ของ origin',
}

export function generatorOf(rule: Pick<MLPendingRule, 'generator' | 'created_by'>): MLRuleGenerator {
  if (rule.generator === 'gen3-detector' || rule.generator === 'rf-regex' || rule.generator === 'cve') {
    return rule.generator
  }
  return rule.created_by === 'cve-auto' ? 'cve' : 'rf-regex'
}

// Pending rules from the retired RandomForest path ("แบบเก่า"), for the bulk reject.
export function legacyPendingCount(rules: Pick<MLPendingRule, 'status' | 'generator' | 'created_by'>[]): number {
  return rules.filter((r) => r.status === 'pending' && generatorOf(r) === 'rf-regex').length
}

export function canBacktest(rule: Pick<MLPendingRule, 'generator' | 'created_by'>): boolean {
  return generatorOf(rule) !== 'cve'
}

export type BacktestTone = 'none' | 'clean' | 'warn' | 'danger'

export interface BacktestView {
  tone: BacktestTone
  label: string
  detail: string
}

// Share of allowed traffic a rule may match before it is shown as a real
// risk rather than a few odd requests.
const DANGER_RATIO = 0.01

export function backtestView(backtest?: MLRuleBacktest | null, lang: Lang = 'th'): BacktestView {
  if (!backtest) {
    return {
      tone: 'none',
      label: L(lang, 'ยังไม่ได้ทดสอบ', 'Not tested yet'),
      detail: L(lang, 'กดทดสอบเพื่อดูว่ากฎนี้จะบล็อก traffic ปกติหรือไม่', 'Run a test to see whether this rule would block normal traffic.'),
    }
  }
  const { matched, scanned, window_days: days } = backtest
  if (scanned === 0) {
    return {
      tone: 'warn',
      label: L(lang, 'ไม่มี traffic ให้ทดสอบ', 'No traffic to test'),
      detail: L(lang, `ไม่พบ request ที่ผ่าน WAF ใน ${days} วันล่าสุด`, `No request passed the WAF in the last ${days} days.`),
    }
  }
  const sample = L(
    lang,
    `${scanned.toLocaleString()} request ที่ผ่าน WAF ใน ${days} วันล่าสุด`,
    `${scanned.toLocaleString()} requests that passed the WAF in the last ${days} days`,
  )
  if (matched === 0) {
    return {
      tone: 'clean',
      label: L(lang, 'ไม่ชน traffic ปกติ', 'No normal traffic matched'),
      detail: L(lang, `ไม่ match เลยใน ${sample}`, `No match in ${sample}.`),
    }
  }
  const tone: BacktestTone = matched / scanned >= DANGER_RATIO ? 'danger' : 'warn'
  return {
    tone,
    label: L(lang, `ชน ${matched.toLocaleString()} request`, `Matches ${matched.toLocaleString()} requests`),
    detail: L(lang, `match ${matched.toLocaleString()} จาก ${sample}`, `Matched ${matched.toLocaleString()} of ${sample}.`),
  }
}

// The risk a reviewer confirms before deploying, or null when no warning is
// needed. Where the rule takes effect is approveScope's job.
export function approveWarning(rule: Pick<MLPendingRule, 'backtest' | 'generator' | 'created_by'>, lang: Lang = 'th'): string | null {
  if (!canBacktest(rule)) return null
  const view = backtestView(rule.backtest, lang)
  if (view.tone === 'none') return L(lang, 'กฎนี้ยังไม่ได้ทดสอบกับ traffic จริง', 'This rule has not been tested against real traffic.')
  if (view.tone === 'warn' || view.tone === 'danger') {
    return L(lang, `${view.detail} ถ้าอนุมัติ request แบบนี้จะถูกบล็อก (403)`, `${view.detail} If you approve it, requests like these are blocked (403).`)
  }
  return null
}

type ScopeFields = Pick<MLPendingRule, 'origin_id' | 'origin_label' | 'deploy_scope'>

export const GLOBAL_SCOPE_LABEL = 'Global (platform)'

// A rule with an origin_id is deployed for that origin only (the backend
// guards it on TX:waf_origin_id); one without is platform-wide.
export function deployScopeOf(rule: ScopeFields): 'origin' | 'global' {
  if (rule.deploy_scope === 'origin' || rule.deploy_scope === 'global') return rule.deploy_scope
  return rule.origin_id ? 'origin' : 'global'
}

export function ruleOriginLabel(rule: ScopeFields): string {
  if (deployScopeOf(rule) === 'global') return GLOBAL_SCOPE_LABEL
  return rule.origin_label || rule.origin_id || 'origin'
}

// Where approving these rules takes effect, for the confirm dialog.
export function approveScope(rules: ScopeFields[], lang: Lang = 'th'): string {
  const n = rules.length
  const global = rules.filter((r) => deployScopeOf(r) === 'global').length
  const labels = Array.from(new Set(rules.filter((r) => deployScopeOf(r) === 'origin').map((r) => ruleOriginLabel(r))))
  if (lang === 'en') {
    const subject = n === 1 ? 'This rule' : `These ${n} rules`
    const s = n === 1 ? 's' : ''
    if (global === n) return `${subject} take${s} effect in ModSecurity for every origin at once.`
    if (global === 0) {
      return labels.length === 1
        ? `${subject} appl${n === 1 ? 'ies' : 'y'} only to ${labels[0]}.`
        : `${subject} apply only to each rule’s own origin (${labels.join(', ')}).`
    }
    return `${subject}: ${global} apply to every origin, the rest only to ${labels.join(', ')}.`
  }
  const subject = n === 1 ? 'กฎนี้' : `กฎ ${n} ข้อ`
  if (global === n) return `${subject}จะมีผลกับ ModSecurity ของทุก origin ทันที`
  if (global === 0) {
    return labels.length === 1
      ? `${subject}จะมีผลเฉพาะ ${labels[0]}`
      : `${subject}จะมีผลเฉพาะ origin ของแต่ละกฎ (${labels.join(', ')})`
  }
  return `${subject}: ${global} ข้อมีผลกับทุก origin ส่วนที่เหลือมีผลเฉพาะ ${labels.join(', ')}`
}

// Approve/reject and backtest rights come from the backend per rule. A
// backend without the flags (before per-origin review) meant admin only.
export function canReviewRule(rule: Pick<MLPendingRule, 'status' | 'can_review'>, isAdmin: boolean): boolean {
  return rule.status === 'pending' && (rule.can_review ?? isAdmin)
}

// Revoke (2026-10-27): an approved rule, when the backend says the caller may
// (admin: any; Owner/Editor: one that runs for their origin only).
export function canRevokeRule(rule: Pick<MLPendingRule, 'status' | 'can_revoke'>): boolean {
  return rule.status === 'approved' && rule.can_revoke === true
}

// What the revoke dialog says will stop.
export function revokeScope(rule: ScopeFields, lang: Lang = 'th'): string {
  return deployScopeOf(rule) === 'global'
    ? L(lang, 'กฎนี้จะหยุดทำงานกับทุก origin ทันที', 'This rule stops for every origin at once')
    : L(lang, `กฎนี้จะหยุดทำงานกับ ${ruleOriginLabel(rule)} ทันที`, `This rule stops for ${ruleOriginLabel(rule)} at once`)
}

export function canBacktestRule(
  rule: Pick<MLPendingRule, 'generator' | 'created_by' | 'can_backtest'>,
  isAdmin: boolean,
): boolean {
  return canBacktest(rule) && (rule.can_backtest ?? isAdmin)
}

export interface OriginOption {
  id: string
  label: string
}

// The origins present in a queue, for the origin filter. Global rules use id "".
export function ruleOriginOptions(rules: ScopeFields[]): OriginOption[] {
  const byId = new Map<string, string>()
  for (const r of rules) {
    const id = deployScopeOf(r) === 'global' ? '' : r.origin_id || ''
    if (!byId.has(id)) byId.set(id, ruleOriginLabel(r))
  }
  return Array.from(byId, ([id, label]) => ({ id, label })).sort((a, b) => a.label.localeCompare(b.label))
}

type AnalystOrigin = Pick<Origin, 'origin_id' | 'label' | 'status' | 'admin_user_id' | 'editor_user_ids' | 'viewer_user_ids'>

// Origins the AI analyst may file proposals for: the caller is Owner or
// Editor, and the origin is not archived.
export function analystOriginChoices(origins: AnalystOrigin[], userId: string | undefined): OriginOption[] {
  return origins
    .filter((o) => o.status !== 'archived' && canEditOrigin(originRoleOf(o, userId)))
    .map((o) => ({ id: o.origin_id, label: o.label || o.origin_id }))
}

export interface ScanOriginOption extends OriginOption {
  hasTags: boolean
}

// Origins the caller may run a CVE scan for (Owner/Editor, not archived).
// A scan only searches the origin's tech stack tags, so one without tags is
// listed but cannot be scanned yet.
export function cveScanOriginChoices(
  origins: (AnalystOrigin & Pick<Origin, 'tech_stack_tags'>)[],
  userId: string | undefined,
): ScanOriginOption[] {
  return origins
    .filter((o) => o.status !== 'archived' && canEditOrigin(originRoleOf(o, userId)))
    .map((o) => ({ id: o.origin_id, label: o.label || o.origin_id, hasTags: (o.tech_stack_tags ?? []).length > 0 }))
}

// "" = no origin (platform admin queue). An admin starts there as before;
// anyone else starts on their first editable origin.
export function defaultAnalystOrigin(choices: OriginOption[], isAdmin: boolean): string {
  if (isAdmin) return ''
  return choices[0]?.id ?? ''
}

export type RuleSort = 'hits' | 'newest'

export interface RuleFilters {
  status: 'pending' | 'approved' | 'rejected' | 'revoked' | 'all'
  generator: MLRuleGenerator | 'all'
  attackType: string
  search: string
  sort: RuleSort
  // An OriginOption id ("" = global); 'all' or absent = every origin.
  origin?: string
}

export function filterAndSortRules(rules: MLPendingRule[], f: RuleFilters): MLPendingRule[] {
  const q = f.search.trim().toLowerCase()
  const out = rules.filter((r) => {
    if (f.status !== 'all' && r.status !== f.status) return false
    if (f.generator !== 'all' && generatorOf(r) !== f.generator) return false
    if (f.attackType !== 'all' && r.attack_type !== f.attackType) return false
    if (f.origin !== undefined && f.origin !== 'all') {
      const id = deployScopeOf(r) === 'global' ? '' : r.origin_id || ''
      if (id !== f.origin) return false
    }
    if (!q) return true
    return [r.rule_id, r.attack_type, r.pattern, r.source_url, r.detector, r.reject_reason, r.cve_id, r.origin_label,
      r.deployed_rule_id != null ? String(r.deployed_rule_id) : '']
      .some((v) => (v || '').toLowerCase().includes(q))
  })
  const newest = (r: MLPendingRule) => r.last_seen_at || r.created_at || ''
  return out.sort((a, b) =>
    f.sort === 'hits' && (b.hit_count ?? 1) !== (a.hit_count ?? 1)
      ? (b.hit_count ?? 1) - (a.hit_count ?? 1)
      : newest(b).localeCompare(newest(a)),
  )
}

// "5 นาทีที่แล้ว" style, for last-seen / tested-at columns.
export function timeAgo(iso: string | undefined, now: number = Date.now(), lang: Lang = 'th'): string {
  if (!iso) return ''
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return ''
  const seconds = Math.round((t - now) / 1000)
  const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' })
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [['day', 86400], ['hour', 3600], ['minute', 60]]
  for (const [unit, size] of steps) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.trunc(seconds / size), unit)
  }
  return rtf.format(0, 'minute')
}

export interface SuggestionSummary {
  engine: 'gen3'
  created: number
  merged: number
  reason: string
  // Echo of the request's origin_id ("" = platform admin queue).
  origin_id?: string
}

const REASON_TEXT_EN: Record<string, string> = {
  gen3_not_attack: 'Gen 3 does not see this request as an attack, so no rule is proposed.',
  gen3_no_detector: 'Gen 3 judged it from the request structure; no detector caught it, so there is no rule to propose.',
  generator_error: 'The rule generator returned an error. Try again.',
}

const REASON_TEXT: Record<string, string> = {
  gen3_not_attack: 'Gen 3 ไม่ถือว่า request นี้เป็นการโจมตี จึงไม่เสนอกฎ',
  gen3_no_detector: 'Gen 3 ตัดสินจากโครงสร้าง request ไม่มี detector ตัวไหนจับได้ จึงไม่มีกฎให้เสนอ',
  generator_error: 'ตัวสร้างกฎตอบกลับผิดพลาด ลองใหม่อีกครั้ง',
}

// One line for the AI analyst after predict-and-suggest. originLabel names
// the origin the proposal went to; null = the platform admin queue;
// undefined = say nothing about where.
export function describeSuggestion(
  s?: SuggestionSummary | null,
  originLabel?: string | null,
  lang: Lang = 'th',
): { queued: boolean; text: string } {
  if (lang === 'en') {
    if (!s) return { queued: false, text: 'Analysis finished' }
    if (s.created + s.merged === 0) return { queued: false, text: REASON_TEXT_EN[s.reason] || 'No rule proposed' }
    const parts = []
    if (s.created) parts.push(`proposed ${s.created} new rule${s.created === 1 ? '' : 's'}`)
    if (s.merged) parts.push(`added evidence to ${s.merged} pending rule${s.merged === 1 ? '' : 's'}`)
    const where = originLabel ? ` for ${originLabel}` : originLabel === null ? ' in the platform operator queue' : ''
    const text = parts.join(' and ') + where
    return { queued: true, text: text.charAt(0).toUpperCase() + text.slice(1) }
  }
  if (!s) return { queued: false, text: 'วิเคราะห์เสร็จแล้ว' }
  if (s.created + s.merged === 0) return { queued: false, text: REASON_TEXT[s.reason] || 'ไม่มีกฎที่เสนอ' }
  const parts = []
  if (s.created) parts.push(`เสนอกฎใหม่ ${s.created} ข้อ`)
  if (s.merged) parts.push(`เพิ่มหลักฐานให้กฎที่รออนุมัติ ${s.merged} ข้อ`)
  const where = originLabel ? ` สำหรับ ${originLabel}` : originLabel === null ? ' ในคิวของผู้ดูแลแพลตฟอร์ม' : ''
  return { queued: true, text: parts.join(' และ ') + where }
}

// The SecRule exactly as approve will deploy it: the backend fills every
// {RULE_ID} (Python str.replace), so the preview must too, not only the first
// (audit H55). split/join because the tsconfig lib is ES2020 (no replaceAll).
export function renderSecRule(rule: Pick<MLPendingRule, 'secrule_template' | 'deployed_rule_id'>): string {
  const id = rule.deployed_rule_id ? String(rule.deployed_rule_id) : 'PENDING_ID'
  return (rule.secrule_template ?? '').split('{RULE_ID}').join(id)
}
