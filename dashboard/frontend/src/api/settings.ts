import { api } from './axios'

export interface SystemSettings {
  waf_mode: 'blocking' | 'detection_only'
  paranoia_level: number
  inbound_anomaly_threshold: number
  outbound_anomaly_threshold: number
  auto_purge_edge_cache: boolean
  real_ip_header: string
  telegram_notifications: boolean
  telegram_bot_token?: string
  telegram_bot_token_masked?: string
  telegram_chat_id?: string
  edge_sync_interval_seconds: number
}

export const settingsApi = {
  getSettings: async (): Promise<SystemSettings> => {
    const res = await api.get<{ settings: SystemSettings }>('/settings/')
    return res.data.settings
  },

  updateSettings: async (data: Partial<SystemSettings>): Promise<SystemSettings> => {
    const res = await api.post<{ status: string; settings: SystemSettings }>('/settings/', data)
    return res.data.settings
  },

  sendTestNotification: async (channel: 'telegram' = 'telegram') => {
    const res = await api.post('/settings/test-notification', { channel })
    return res.data
  },
}
