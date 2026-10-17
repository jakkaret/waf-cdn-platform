// Support tickets and time-limited support access (docs/tickets/support-access.md).
// Pure helpers behind the Support pages, kept out of the components so they are unit-tested.

export type SupportTicket = {
  ticket_id: string
  origin_id: string
  origin_label?: string
  subject: string
  status: 'open' | 'closed'
  created_at: string
  updated_at: string
  message_count?: number
  access_granted?: boolean
}

export type SupportMessage = {
  message_id: string
  author_id: string | null
  author_name?: string | null
  is_support: boolean
  body: string
  created_at: string
}

export type SupportGrant = {
  grant_id: string
  level: 'viewer' | 'editor'
  created_at: string
  expires_at: string
  revoked_at: string | null
  active: boolean
}

export type SupportAccessEntry = {
  at: string
  kind: 'read' | 'edit'
  staff_id: string | null
  staff_name?: string | null
  level: 'viewer' | 'editor'
}

export type SupportTicketDetail = {
  ticket: SupportTicket
  origin: { id: string; label?: string }
  messages: SupportMessage[]
  grants: SupportGrant[]
  access_log: SupportAccessEntry[]
  can_grant: boolean
  staff: boolean
}

export const GRANT_HOURS = [1, 4, 24, 72] as const

export const LEVEL_LABEL: Record<SupportGrant['level'], string> = {
  viewer: 'view only',
  editor: 'can edit',
}

export function activeGrant(grants: SupportGrant[]): SupportGrant | undefined {
  return grants.find((g) => g.active)
}

// "3h 20m left" style remaining time; "expired" once past.
export function remainingText(expiresAt: string, now: Date = new Date()): string {
  const ms = new Date(expiresAt).getTime() - now.getTime()
  if (!(ms > 0)) return 'expired'
  const mins = Math.floor(ms / 60000)
  const h = Math.floor(mins / 60)
  const m = mins % 60
  if (h === 0) return `${m}m left`
  return m === 0 ? `${h}h left` : `${h}h ${m}m left`
}

export function grantSummary(grants: SupportGrant[], now: Date = new Date()): string {
  const g = activeGrant(grants)
  if (!g) return 'Support has no access to this origin'
  return `Support access: ${LEVEL_LABEL[g.level]} (${remainingText(g.expires_at, now)})`
}
