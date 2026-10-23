import { api } from './axios'
import { WafAlert } from '../types'
import type { Incident } from '../lib/incidents'
import type { NotificationPrefs, PrefKind, Sensitivity } from '../lib/notificationPrefs'

export const alertsApi = {
  getAlerts: async (limit: number = 200) => {
    const res = await api.get<{ alerts: WafAlert[] }>('/alerts/recent', { params: { limit } })
    return res.data.alerts
  },

  getIncidents: async (params: { limit?: number; incident?: string } = {}) => {
    const res = await api.get<{ incidents: Incident[] }>('/alerts/incidents', { params })
    return res.data.incidents
  },

  getPreferences: async () => {
    const res = await api.get<NotificationPrefs>('/alerts/preferences')
    return res.data
  },

  setPreferences: async (originId: string, changes: Partial<Record<PrefKind, boolean>>) => {
    const res = await api.put<{ prefs: Record<PrefKind, boolean> }>(`/alerts/preferences/${originId}`, changes)
    return res.data.prefs
  },

  setSensitivity: async (originId: string, sensitivity: Sensitivity) => {
    const res = await api.put<{ sensitivity: Sensitivity }>(`/alerts/sensitivity/${originId}`, { sensitivity })
    return res.data.sensitivity
  },

  sendTest: async () => {
    const res = await api.post<{ sent: boolean }>('/alerts/test')
    return res.data
  },

  getConnectionStatus: async () => {
    const res = await api.get<{ connected: boolean; chat_id: string | null }>('/alerts/connect/status')
    return res.data
  },

  startConnection: async () => {
    const res = await api.post<{ code: string; bot_username: string; expires_in: number }>('/alerts/connect/start')
    return res.data
  },

  pollConnection: async (code: string) => {
    const res = await api.get<{ status: 'pending' | 'connected' | 'expired'; chat_id?: string }>('/alerts/connect/poll', {
      params: { code }
    })
    return res.data
  },

  disconnect: async () => {
    const res = await api.delete('/alerts/connect')
    return res.data
  }
}
