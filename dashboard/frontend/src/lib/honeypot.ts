// Words, colours and the IOC export for the origin Honeypot tab
// (components/origins/OriginHoneypot.tsx). Stages and MITRE ids mirror
// services/honeypot.py STAGES / STAGE_ATTACK.

import type { HoneypotSession, HoneypotStage } from '../api/honeypot'
import type { Lang } from '../i18n'
import { formatBkkDateTime } from './time'

export const STAGES: HoneypotStage[] = ['recon', 'loot', 'exploit', 'credential_use', 'persistence']

export const STAGE_META: Record<HoneypotStage, { label: string; labelTh: string; attack: string; desc: string; descTh: string }> = {
  recon: { label: 'Scanning', labelTh: 'สำรวจ', attack: 'T1595', desc: 'Looked for pages and admin panels', descTh: 'ไล่หาหน้าและหน้าผู้ดูแล' },
  loot: { label: 'Took fake secrets', labelTh: 'ได้ข้อมูลลับปลอม', attack: 'T1552', desc: 'Downloaded a decoy config or credentials file', descTh: 'ดาวน์โหลดไฟล์ config หรือรหัสปลอม' },
  exploit: { label: 'Tried to break in', labelTh: 'พยายามเจาะ', attack: 'T1190', desc: 'Sent an injection or tried to log in', descTh: 'ส่ง injection หรือพยายามล็อกอิน' },
  credential_use: { label: 'Used fake credentials', labelTh: 'ใช้ credential ปลอม', attack: 'T1078', desc: 'Came back with a honeytoken we handed out', descTh: 'กลับมาใช้ honeytoken ที่เราแจกไป' },
  persistence: { label: 'Tried to plant a file', labelTh: 'พยายามฝังไฟล์', attack: 'T1505.003', desc: 'Uploaded a file (a web shell or plugin)', descTh: 'อัปโหลดไฟล์ (web shell หรือ plugin)' },
}

export const stageLabel = (s: HoneypotStage, lang: Lang) => (lang === 'th' ? STAGE_META[s].labelTh : STAGE_META[s].label)

// Later stages are worse; the colour says how far a session got.
export const STAGE_TONE: Record<HoneypotStage, string> = {
  recon: 'bg-[var(--bg-surface-active)] text-[var(--text-secondary)]',
  loot: 'bg-amber-500/10 text-amber-700 dark:text-amber-300',
  exploit: 'bg-orange-500/10 text-orange-700 dark:text-orange-300',
  credential_use: 'bg-red-500/10 text-red-700 dark:text-red-300',
  persistence: 'bg-red-600/15 text-red-800 dark:text-red-200',
}

// Solid colour of each stage's funnel bar.
export const STAGE_BAR: Record<HoneypotStage, string> = {
  recon: 'bg-slate-400',
  loot: 'bg-amber-500',
  exploit: 'bg-orange-500',
  credential_use: 'bg-red-500',
  persistence: 'bg-red-700',
}

// "45 s", "3 min", "1 h 20 min" ("45 วิ", "3 นาที", "1 ชม. 20 นาที")
export function formatSpan(seconds: number, lang: Lang = 'th'): string {
  const en = lang === 'en'
  if (seconds < 60) return en ? `${seconds} s` : `${seconds} วิ`
  const mins = Math.round(seconds / 60)
  if (mins < 60) return en ? `${mins} min` : `${mins} นาที`
  const h = Math.floor(mins / 60)
  const m = mins % 60
  return en ? `${h} h${m ? ` ${m} min` : ''}` : `${h} ชม.${m ? ` ${m} นาที` : ''}`
}

// A CSV cell: quoted, quotes doubled, and a leading = + - @ neutralised so a
// spreadsheet never runs attacker text as a formula.
export function csvCell(value: unknown): string {
  let s = String(value ?? '')
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`
  return `"${s.replace(/"/g, '""')}"`
}

// One row per indicator: each IP, each uploaded file hash, each honeytoken
// kind that came back. Feeds a block list or a SIEM watchlist.
export function iocCsv(sessions: HoneypotSession[]): string {
  const rows: string[][] = [['type', 'value', 'session', 'first_seen_bkk', 'last_seen_bkk', 'tool', 'furthest_stage', 'mitre']]
  const seen = new Set<string>()
  for (const s of sessions) {
    const common = [s.id, formatBkkDateTime(s.first_seen), formatBkkDateTime(s.last_seen), s.tool, s.max_stage, STAGE_META[s.max_stage].attack]
    const add = (type: string, value: string) => {
      const k = `${type}|${value}|${s.id}`
      if (!value || seen.has(k)) return
      seen.add(k)
      rows.push([type, value, ...common])
    }
    s.ips.forEach((ip) => add('ip', ip))
    s.uploads.forEach((u) => add('sha256', u.sha256))
    s.tokens_replayed.forEach((tk) => add('honeytoken_replayed', tk))
  }
  return rows.map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n'
}
