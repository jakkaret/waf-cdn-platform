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
  telegram_bot_token_set?: boolean
  telegram_chat_id?: string
  edge_sync_interval_seconds: number
}

// POST /api/settings/ accepts only these fields (SettingsUpdate, extra="forbid").
// GET also returns read-only ones (not_implemented, telegram_bot_token_set,
// telegram_bot_token_masked, ml_*), and the Settings page posts back the
// object it loaded, so every save was refused with a 422.
const EDITABLE_SETTINGS = [
  'waf_mode',
  'paranoia_level',
  'inbound_anomaly_threshold',
  'outbound_anomaly_threshold',
  'auto_purge_edge_cache',
  'real_ip_header',
  'telegram_notifications',
  'telegram_bot_token',
  'telegram_chat_id',
  'edge_sync_interval_seconds',
] as const

export const editableSettings = (data: Partial<SystemSettings>): Partial<SystemSettings> => {
  const out: Partial<SystemSettings> = {}
  for (const key of EDITABLE_SETTINGS) {
    if (data[key] !== undefined) Object.assign(out, { [key]: data[key] })
  }
  return out
}

export const settingsApi = {
  getSettings: async (): Promise<SystemSettings> => {
    const res = await api.get<{ settings: SystemSettings }>('/settings/')
    return res.data.settings
  },

  updateSettings: async (data: Partial<SystemSettings>): Promise<SystemSettings> => {
    const res = await api.post<{ status: string; settings: SystemSettings }>('/settings/', editableSettings(data))
    return res.data.settings
  },

  sendTestNotification: async (channel: 'telegram' = 'telegram') => {
    const res = await api.post('/settings/test-notification', { channel })
    return res.data
  },
}
