// Telegram notification choices per site (backend services/notification_prefs.py).

export type PrefKind = 'attacks' | 'outages' | 'certs' | 'team' | 'digest'
export type Sensitivity = 'low' | 'medium' | 'high'

export interface SitePrefs {
  origin_id: string
  label: string | null
  role: 'owner' | 'editor' | 'viewer'
  sensitivity: Sensitivity
  can_set_sensitivity: boolean
  prefs: Record<PrefKind, boolean>
  changeable: PrefKind[]
}

export interface NotificationPrefs {
  telegram_connected: boolean
  levels: Record<Sensitivity, { total: number; per_ip: number }>
  sites: SitePrefs[]
}

export const PREF_KINDS: { kind: PrefKind; label: string; labelTh: string }[] = [
  { kind: 'attacks', label: 'Attack started or ended', labelTh: 'การโจมตีเริ่มหรือจบ' },
  { kind: 'outages', label: 'Site unreachable or tunnel agent offline', labelTh: 'เข้าเว็บไม่ได้ หรือ tunnel agent ออฟไลน์' },
  { kind: 'certs', label: 'HTTPS certificate about to expire', labelTh: 'ใบรับรอง HTTPS ใกล้หมดอายุ' },
  { kind: 'team', label: 'Someone else changed this site', labelTh: 'มีคนอื่นแก้ไขเว็บนี้' },
  { kind: 'digest', label: 'Daily summary at 08:00', labelTh: 'สรุปรายวันเวลา 08:00' },
]

export const SENSITIVITY_LABEL: Record<Sensitivity, string> = { low: 'Low', medium: 'Medium', high: 'High' }
export const SENSITIVITY_LABEL_TH: Record<Sensitivity, string> = { low: 'ต่ำ', medium: 'ปานกลาง', high: 'สูง' }

export const ROLE_LABEL: Record<SitePrefs['role'], string> = { owner: 'Owner', editor: 'Editor', viewer: 'Viewer' }

export const sensitivityHint = (level: Sensitivity, levels: NotificationPrefs['levels'], lang: 'en' | 'th' = 'en'): string => {
  const l = levels[level]
  if (!l) return ''
  return lang === 'th'
    ? `แจ้งเมื่อมี request ถูกบล็อกตั้งแต่ ${l.total} ครั้งใน 5 นาที หรือจาก IP เดียวตั้งแต่ ${l.per_ip} ครั้ง`
    : `Alerts when ${l.total} or more requests are blocked in 5 minutes, or ${l.per_ip} or more from one IP`
}

// Kinds this person can see for the site: what their role may change, plus
// anything already on for them (shown, not changeable).
export const visibleKinds = (site: Pick<SitePrefs, 'changeable' | 'prefs'>) =>
  PREF_KINDS.filter(({ kind }) => site.changeable.includes(kind) || site.prefs[kind])
