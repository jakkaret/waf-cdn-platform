// AI Security Analyst: how to show the Gen 3 answer for one request.
// Gen 3 (ml/models/gen3/gen3_f_noopenappsec.onnx) is the only model the page
// uses; the RandomForest was retired here on 2026-10-13.

export interface Gen3Detector {
  detector: string
  attack_type: string
  severity: string
}

// /predict-gen3 as relayed by /api/ml/predict-and-suggest (`gen3`).
export interface Gen3Verdict {
  attack_probability: number
  is_attack: boolean
  threshold: number
  feature_set?: string
  mode?: string
  detectors?: Gen3Detector[]
}

export interface VerdictView {
  isAttack: boolean
  score: number | null
  threshold: number | null
  title: string
}

const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)

export function verdictView(gen3: Gen3Verdict | null | undefined): VerdictView | null {
  if (!gen3 || typeof gen3.is_attack !== 'boolean') return null
  return {
    isAttack: gen3.is_attack,
    score: isNum(gen3.attack_probability) ? gen3.attack_probability : null,
    threshold: isNum(gen3.threshold) ? gen3.threshold : null,
    title: gen3.is_attack ? 'น่าจะเป็นการโจมตี' : 'ดูเป็น request ปกติ',
  }
}

// Positions on a 0-100% bar; null when there is nothing to draw.
export function scoreBar(score: number | null, threshold: number | null): { score: number; threshold: number | null } | null {
  if (score === null) return null
  const pct = (v: number) => Math.min(100, Math.max(0, v * 100))
  return { score: pct(score), threshold: threshold === null ? null : pct(threshold) }
}

// The line under the detector list. Detectors are value features, not the
// decision, so the two can differ and the reader needs to know which way.
export function detectorNote(gen3: Gen3Verdict | null | undefined): string {
  if (!gen3) return ''
  const fired = gen3.detectors?.length ?? 0
  if (!gen3.detectors) return 'ML host ยังไม่ส่งรายชื่อ detector มา'
  if (gen3.is_attack && fired === 0) {
    return 'ไม่มี detector ตัวไหนตรง โมเดลตัดสินจากรูปแบบโครงสร้างของ request จึงไม่เสนอกฎ'
  }
  if (!gen3.is_attack && fired > 0) {
    return 'มี detector ตรง แต่คะแนนรวมยังต่ำกว่าเกณฑ์ โมเดลจึงไม่ถือว่าเป็นการโจมตี'
  }
  if (fired === 0) return 'ไม่มี detector ตัวไหนตรง'
  return 'กฎที่เสนอสร้างจาก detector เหล่านี้ (1 กฎต่อ 1 detector)'
}

export const formatPercent = (value: unknown, digits = 2): string =>
  isNum(value) ? `${(value * 100).toFixed(digits)}%` : 'N/A'

// Quick-fill requests for the form: one per kind the page is usually shown with.
export const SAMPLE_REQUESTS: { label: string; method: string; url: string; body: string }[] = [
  { label: 'SQL injection', method: 'GET', url: "/products?id=42' UNION SELECT username,password FROM users--", body: '' },
  { label: 'XSS', method: 'GET', url: '/search?q=<script>alert(document.cookie)</script>', body: '' },
  { label: 'Path traversal', method: 'GET', url: '/download?file=../../../../etc/passwd', body: '' },
  { label: 'Command injection', method: 'POST', url: '/api/ping', body: 'host=127.0.0.1;cat /etc/passwd' },
  { label: 'Request ปกติ', method: 'GET', url: '/products?page=2&sort=price', body: '' },
]
