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

export const PREF_KINDS: { kind: PrefKind; label: string }[] = [
  { kind: 'attacks', label: 'ถูกโจมตี (เริ่ม / จบ)' },
  { kind: 'outages', label: 'เว็บเปิดไม่ได้ หรือ agent หลุด' },
  { kind: 'certs', label: 'ใบรับรอง HTTPS ใกล้หมดอายุ' },
  { kind: 'team', label: 'คนอื่นแก้เว็บนี้' },
  { kind: 'digest', label: 'สรุปรายวัน 08:00' },
]

export const SENSITIVITY_LABEL: Record<Sensitivity, string> = { low: 'ต่ำ', medium: 'กลาง', high: 'สูง' }

export const ROLE_LABEL: Record<SitePrefs['role'], string> = { owner: 'Owner', editor: 'Editor', viewer: 'Viewer' }

export const sensitivityHint = (level: Sensitivity, levels: NotificationPrefs['levels']): string => {
  const l = levels[level]
  return l ? `แจ้งเมื่อบล็อก ≥ ${l.total} ครั้งใน 5 นาที หรือ IP เดียว ≥ ${l.per_ip} ครั้ง` : ''
}

// Kinds this person can see for the site: what their role may change, plus
// anything already on for them (shown, not changeable).
export const visibleKinds = (site: Pick<SitePrefs, 'changeable' | 'prefs'>) =>
  PREF_KINDS.filter(({ kind }) => site.changeable.includes(kind) || site.prefs[kind])
