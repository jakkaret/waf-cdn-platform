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
  { kind: 'attacks', label: 'Attack started or ended' },
  { kind: 'outages', label: 'Site unreachable or tunnel agent offline' },
  { kind: 'certs', label: 'HTTPS certificate about to expire' },
  { kind: 'team', label: 'Someone else changed this site' },
  { kind: 'digest', label: 'Daily summary at 08:00' },
]

export const SENSITIVITY_LABEL: Record<Sensitivity, string> = { low: 'Low', medium: 'Medium', high: 'High' }

export const ROLE_LABEL: Record<SitePrefs['role'], string> = { owner: 'Owner', editor: 'Editor', viewer: 'Viewer' }

export const sensitivityHint = (level: Sensitivity, levels: NotificationPrefs['levels']): string => {
  const l = levels[level]
  return l ? `Alerts when ${l.total} or more requests are blocked in 5 minutes, or ${l.per_ip} or more from one IP` : ''
}

// Kinds this person can see for the site: what their role may change, plus
// anything already on for them (shown, not changeable).
export const visibleKinds = (site: Pick<SitePrefs, 'changeable' | 'prefs'>) =>
  PREF_KINDS.filter(({ kind }) => site.changeable.includes(kind) || site.prefs[kind])
