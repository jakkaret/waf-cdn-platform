// Pure helpers behind the ML anomaly rules page and the AI analyst's
// suggestion toast. Kept out of the components so every branch is unit-tested.
import type { MLPendingRule, MLRuleBacktest, MLRuleGenerator } from '../types'

export const GENERATOR_LABEL: Record<MLRuleGenerator, string> = {
  'gen3-detector': 'Gen3 detector',
  'rf-regex': 'แบบเก่า',
  cve: 'CVE patch',
}

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

export function backtestView(backtest?: MLRuleBacktest | null): BacktestView {
  if (!backtest) {
    return { tone: 'none', label: 'ยังไม่ได้ทดสอบ', detail: 'กดทดสอบเพื่อดูว่ากฎนี้จะบล็อก traffic ปกติหรือไม่' }
  }
  const { matched, scanned, window_days: days } = backtest
  if (scanned === 0) {
    return { tone: 'warn', label: 'ไม่มี traffic ให้ทดสอบ', detail: `ไม่พบ request ที่ผ่าน WAF ใน ${days} วันล่าสุด` }
  }
  const sample = `${scanned.toLocaleString()} request ที่ผ่าน WAF ใน ${days} วันล่าสุด`
  if (matched === 0) {
    return { tone: 'clean', label: 'ไม่ชน traffic ปกติ', detail: `ไม่ match เลยใน ${sample}` }
  }
  const tone: BacktestTone = matched / scanned >= DANGER_RATIO ? 'danger' : 'warn'
  return { tone, label: `ชน ${matched.toLocaleString()} request`, detail: `match ${matched.toLocaleString()} จาก ${sample}` }
}

// The text an admin confirms before deploying, or null when no warning is needed.
export function approveWarning(rule: Pick<MLPendingRule, 'backtest' | 'generator' | 'created_by'>): string | null {
  if (!canBacktest(rule)) return null
  const view = backtestView(rule.backtest)
  if (view.tone === 'none') return 'กฎนี้ยังไม่ได้ทดสอบกับ traffic จริง ถ้าอนุมัติ กฎจะมีผลกับทุก origin ทันที'
  if (view.tone === 'warn' || view.tone === 'danger') {
    return `${view.detail} ถ้าอนุมัติ request แบบนี้จะถูกบล็อก (403) ทุก origin`
  }
  return null
}

export type RuleSort = 'hits' | 'newest'

export interface RuleFilters {
  status: 'pending' | 'approved' | 'rejected' | 'all'
  generator: MLRuleGenerator | 'all'
  attackType: string
  search: string
  sort: RuleSort
}

export function filterAndSortRules(rules: MLPendingRule[], f: RuleFilters): MLPendingRule[] {
  const q = f.search.trim().toLowerCase()
  const out = rules.filter((r) => {
    if (f.status !== 'all' && r.status !== f.status) return false
    if (f.generator !== 'all' && generatorOf(r) !== f.generator) return false
    if (f.attackType !== 'all' && r.attack_type !== f.attackType) return false
    if (!q) return true
    return [r.rule_id, r.attack_type, r.pattern, r.source_url, r.detector, r.reject_reason, r.cve_id,
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
export function timeAgo(iso: string | undefined, now: number = Date.now()): string {
  if (!iso) return ''
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return ''
  const seconds = Math.round((t - now) / 1000)
  const rtf = new Intl.RelativeTimeFormat('th', { numeric: 'auto' })
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
}

const REASON_TEXT: Record<string, string> = {
  gen3_not_attack: 'Gen 3 ไม่ถือว่า request นี้เป็นการโจมตี จึงไม่เสนอกฎ',
  gen3_no_detector: 'Gen 3 ตัดสินจากโครงสร้าง request ไม่มี detector ตัวไหนจับได้ จึงไม่มีกฎให้เสนอ',
  generator_error: 'ตัวสร้างกฎตอบกลับผิดพลาด ลองใหม่อีกครั้ง',
}

// One line for the AI analyst after predict-and-suggest.
export function describeSuggestion(s?: SuggestionSummary | null): { queued: boolean; text: string } {
  if (!s) return { queued: false, text: 'วิเคราะห์เสร็จแล้ว' }
  if (s.created + s.merged === 0) return { queued: false, text: REASON_TEXT[s.reason] || 'ไม่มีกฎที่เสนอ' }
  const parts = []
  if (s.created) parts.push(`เสนอกฎใหม่ ${s.created} ข้อ`)
  if (s.merged) parts.push(`เพิ่มหลักฐานให้กฎที่รออนุมัติ ${s.merged} ข้อ`)
  return { queued: true, text: parts.join(' และ ') }
}

// The SecRule exactly as approve will deploy it: the backend fills every
// {RULE_ID} (Python str.replace), so the preview must too, not only the first
// (audit H55). split/join because the tsconfig lib is ES2020 (no replaceAll).
export function renderSecRule(rule: Pick<MLPendingRule, 'secrule_template' | 'deployed_rule_id'>): string {
  const id = rule.deployed_rule_id ? String(rule.deployed_rule_id) : 'PENDING_ID'
  return (rule.secrule_template ?? '').split('{RULE_ID}').join(id)
}
