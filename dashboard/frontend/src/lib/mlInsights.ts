// ML Insights (AI Security Analyst page): Gen 3 scores of the origin's real
// traffic, from GET /api/ml/insights (dashboard/backend/services/ml_verdicts.py).
// An origin in log mode (the default) is only scored; one in enforce mode
// (Origin -> ML Protection) also carries what the inline gate did.

export interface InsightsSummary {
  total: number
  flagged: number
  watch: number
  hosts: number
  last_seen: string | null
  threshold: number | null
  feature_set: string | null
  /** Requests the inline gate blocked / sent to the challenge (enforce mode). */
  blocked?: number
  challenged?: number
}

export type GateAction = 'pass' | 'challenge' | 'block'

export interface HistogramBin {
  from: number
  to: number
  count: number
  flagged: number
}

export interface TimelinePoint {
  t: string
  count: number
  flagged: number
}

export interface InsightRequest {
  timestamp: string
  request_id: string
  host: string
  method: string
  path: string
  query: string
  score: number
  threshold: number
  is_attack: boolean
  detectors: string[]
  body_length: number
  /** null = log mode (scored only). */
  action?: GateAction | null
  /** A masked body sample is stored (score 50 and up). */
  has_body?: boolean
  /** The request's origin (host map), and whether the caller is its Owner or an Editor. */
  origin_id?: string | null
  can_edit?: boolean
  /** can_edit, flagged by Gen 3, and not already blocked by the inline gate. */
  can_propose?: boolean
  status_code: number | null
  client_ip: string | null
  country: string | null
}

export interface MLInsights {
  hours: number
  bucket_seconds: number
  summary: InsightsSummary
  histogram: HistogramBin[]
  timeline: TimelinePoint[]
  detectors: { detector: string; count: number }[]
  requests: InsightRequest[]
}

export const RANGES = [
  { hours: 24, label: '24 ชั่วโมง' },
  { hours: 168, label: '7 วัน' },
] as const

export type ListMode = 'flagged' | 'watch'

// Scores from here up are listed under "watch" (ml_verdicts.WATCH_FLOOR).
export const WATCH_FLOOR = 0.5

// Same names as ml/rule_proposal.py DETECTOR_INFO.
const DETECTOR_LABELS: Record<string, string> = {
  v_sqli_libinjection: 'SQL Injection',
  v_xss_libinjection: 'Cross-Site Scripting',
  v_cmd_injection: 'Command Injection',
  v_path_traversal: 'Path Traversal',
  v_sensitive_file: 'Sensitive File Access',
  v_template_injection: 'Template Injection',
  v_nosql_operator: 'NoSQL Injection',
  v_ssrf_target: 'SSRF',
  v_code_exec: 'Code Execution',
  v_xml_entity: 'XML External Entity',
  v_crlf_header: 'CRLF / Header Injection',
  v_restricted_file: 'Restricted File Access',
}

export const detectorLabel = (name: string): string => DETECTOR_LABELS[name] ?? name

// A score shown as points out of 100, e.g. 0.99318 -> "99.3".
export function scorePoints(score: number | null | undefined, digits = 1): string {
  if (typeof score !== 'number' || !Number.isFinite(score)) return '-'
  return (Math.min(1, Math.max(0, score)) * 100).toFixed(digits)
}

export function flaggedShare(summary: InsightsSummary): string {
  if (!summary.total) return '0%'
  const pct = (summary.flagged / summary.total) * 100
  if (pct > 0 && pct < 0.1) return '<0.1%'
  return `${pct.toFixed(pct < 10 ? 1 : 0)}%`
}

// Histogram bars: the label and whether the bin sits at or above the model threshold.
export function histogramBars(bins: HistogramBin[], threshold: number | null) {
  return bins.map((b) => ({
    ...b,
    label: `${Math.round(b.from * 100)}-${Math.round(b.to * 100)}`,
    atOrAbove: threshold !== null && b.to > threshold,
  }))
}

// What the WAF answered the request (access_logs), in words. The inline gate's
// own action wins: its 403/challenge is the ML's doing, not ModSecurity's.
export function statusView(
  code: number | null,
  action?: GateAction | null,
): { text: string; tone: 'ok' | 'blocked' | 'error' | 'unknown' } {
  if (action === 'block') return { text: '403 ML บล็อก', tone: 'blocked' }
  if (action === 'challenge') return { text: 'ML ส่ง challenge', tone: 'error' }
  if (code === null || code === undefined) return { text: 'ยังไม่มีใน log', tone: 'unknown' }
  if (code === 403 || code === 429) return { text: `${code} ถูกบล็อก`, tone: 'blocked' }
  if (code >= 500) return { text: `${code}`, tone: 'error' }
  return { text: `${code}`, tone: 'ok' }
}

// Why an Owner/Editor gets no "propose a rule" button on this request ("" = they do).
export function proposeHint(r: Pick<InsightRequest, 'can_edit' | 'can_propose' | 'action' | 'is_attack'>): string {
  if (!r.can_edit || r.can_propose) return ''
  if (r.action === 'block') return 'ML บล็อก request นี้อยู่แล้ว ไม่ต้องมีกฎเพิ่ม'
  if (!r.is_attack) return 'คะแนนยังต่ำกว่าเกณฑ์ของโมเดล โมเดลจึงไม่เสนอกฎจาก request นี้'
  return ''
}

// Why a pending proposal was not made, from the backend's suggestion.reason.
export function suggestReasonText(reason: string): string {
  switch (reason) {
    case 'gen3_not_attack':
      return 'เมื่อให้คะแนนใหม่จากข้อมูลที่เก็บไว้ (ซ่อนข้อมูลส่วนตัวแล้ว) คะแนนต่ำกว่าเกณฑ์ จึงไม่มีกฎที่เสนอได้'
    case 'gen3_no_detector':
      return 'โมเดลตั้งข้อสังเกตจากโครงสร้างของ request ไม่มี detector ตัวไหนตรง จึงสร้างกฎทั่วไปไม่ได้'
    case 'generator_error':
      return 'ตัวสร้างกฎของ ML ตอบผิดพลาด ลองใหม่อีกครั้ง'
    default:
      return reason ? `ไม่มีกฎที่เสนอได้ (${reason})` : ''
  }
}

export function requestTarget(r: Pick<InsightRequest, 'path' | 'query'>): string {
  return r.query ? `${r.path}?${r.query}` : r.path
}

export function emptyReason(summary: InsightsSummary, hasOrigins: boolean, isAdmin: boolean): string {
  if (!isAdmin && !hasOrigins) return 'ยังไม่มี origin ที่คุณดูได้ เพิ่ม origin หรือขอสิทธิ์จากเจ้าของก่อน'
  if (!summary.total) return 'ยังไม่มี request ที่ถูกให้คะแนนในช่วงเวลานี้ ระบบเริ่มให้คะแนนเมื่อมี traffic เข้าเว็บ'
  return ''
}
