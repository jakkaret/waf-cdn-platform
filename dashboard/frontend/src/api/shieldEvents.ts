import { api } from './axios'

export interface ShieldEventCount {
  kind: 'otp' | 'captcha'
  event: string
  label: string
  count: number
}

export interface ShieldEventRow {
  timestamp: string
  host: string
  kind: 'otp' | 'captcha'
  event: string
  label: string
  client_ip: string
  email: string // masked, e.g. al***@gmail.com
  path: string
}

export const getShieldEvents = (originId: string, hours = 24) =>
  api.get<{ hours: number; counts: ShieldEventCount[]; recent: ShieldEventRow[] }>(
    `/origins/${originId}/shield-events`,
    { params: { hours } },
  )

export interface ShieldPreview {
  hours: number
  total: number
  get_head: number
  other_methods: number
  non_browser: number
  top_non_browser: { user_agent: string; count: number }[]
}

export const previewShield = (
  originId: string,
  body: { login_paths: string[]; exclude_paths: string[]; hours?: number },
) => api.post<ShieldPreview>(`/origins/${originId}/shield-events/preview`, body)
