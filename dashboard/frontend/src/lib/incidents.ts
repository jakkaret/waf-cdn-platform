// Attack incidents (backend services/alert_incidents.py): one burst of blocked
// requests on one site, with a start and an end. Telegram is sent when one
// opens and when it closes; these helpers word the same facts for the page.

export interface Incident {
  incident_id: string
  scope: string
  origin_id: string | null
  label: string | null
  opened_at: string
  last_seen_at: string
  closed_at: string | null
  blocked_count: number
  ip_count: number
  top_ips: [string, number][]
  top_types: [string, number][]
  top_paths: [string, number][]
  summary: string | null
  summary_by_ai: boolean
}

// Same wording as the Telegram messages (ATTACK_TYPE_TH in the backend).
const ATTACK_TYPE_TH: Record<string, string> = {
  'WAF Security Block': 'คำขอที่ WAF ห้าม',
  'Restricted File Access Attempt': 'พยายามเปิดไฟล์ต้องห้าม',
  'Restricted File Access Attempt: AI Coding Assistant Artifact': 'หาไฟล์ตั้งค่าของเครื่องมือ AI',
  'URL file extension is restricted by policy': 'ขอไฟล์นามสกุลต้องห้าม',
  'Attempt to access a backup or working file': 'หาไฟล์สำรอง',
  'Invalid character in request (null character)': 'อักขระแปลกปลอมใน URL',
  'ML Block': 'คำขอที่ ML บล็อก',
  'ML Challenge': 'คำขอที่ ML ให้ยืนยันว่าเป็นคน',
}

export const attackTypeLabel = (t: string): string => ATTACK_TYPE_TH[t] ?? t

export const incidentSite = (i: Pick<Incident, 'scope' | 'label'>): string =>
  i.scope === 'unattributed' ? 'traffic ที่ไม่ตรงกับเว็บไหน' : i.label || 'เว็บไม่มีชื่อ'

export const incidentTypes = (i: Pick<Incident, 'top_types'>): string => {
  const names = Array.from(new Set((i.top_types ?? []).slice(0, 2).map(([t]) => attackTypeLabel(t))))
  return names.join(', ') || 'ไม่ระบุ'
}

export const incidentMinutes = (i: Pick<Incident, 'opened_at' | 'last_seen_at'>): number =>
  Math.max(1, Math.ceil((Date.parse(i.last_seen_at) - Date.parse(i.opened_at)) / 60000))

const hm = new Intl.DateTimeFormat('th-TH', { timeZone: 'Asia/Bangkok', hour: '2-digit', minute: '2-digit', hour12: false })
const dhm = new Intl.DateTimeFormat('th-TH', {
  timeZone: 'Asia/Bangkok', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false,
})
const bkkDay = (iso: string) => new Date(Date.parse(iso) + 7 * 3600e3).toISOString().slice(0, 10)

// "23 ต.ค. 13:09–13:14" (end without a date when it is the same day).
export const incidentWhen = (i: Pick<Incident, 'opened_at' | 'last_seen_at'>): string => {
  const start = dhm.format(new Date(i.opened_at))
  const end = bkkDay(i.opened_at) === bkkDay(i.last_seen_at) ? hm.format(new Date(i.last_seen_at)) : dhm.format(new Date(i.last_seen_at))
  return `${start}–${end}`
}
