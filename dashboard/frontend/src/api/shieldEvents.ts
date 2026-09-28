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
