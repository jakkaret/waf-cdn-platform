// The Settings page posts back the settings object it loaded. POST
// /api/settings/ forbids unknown fields, so the read-only ones GET adds must
// be dropped or every save is a 422.
import { describe, it, expect, vi, beforeEach } from 'vitest'

const post = vi.fn()
vi.mock('./axios', () => ({ api: { post: (...a: unknown[]) => post(...a), get: vi.fn() } }))

import { settingsApi, SystemSettings } from './settings'

const loaded = {
  not_implemented: ['real_ip_header', 'edge_sync_interval_seconds', 'auto_purge_edge_cache'],
  waf_mode: 'blocking',
  paranoia_level: 2,
  inbound_anomaly_threshold: 5,
  outbound_anomaly_threshold: 4,
  auto_purge_edge_cache: false,
  real_ip_header: 'X-Real-IP',
  telegram_notifications: false,
  telegram_bot_token_set: true,
  telegram_bot_token_masked: '...abcd',
  telegram_chat_id: '',
  edge_sync_interval_seconds: 30,
  ml_enforcement_enabled: false,
  ml_block_threshold: 0.9,
  ml_challenge_threshold: 0.7,
} as unknown as SystemSettings

beforeEach(() => {
  post.mockReset()
  post.mockResolvedValue({ data: { settings: {} } })
})

describe('settingsApi.updateSettings', () => {
  it('sends only the fields the API accepts', async () => {
    await settingsApi.updateSettings(loaded)
    expect(post).toHaveBeenCalledWith('/settings/', {
      waf_mode: 'blocking',
      paranoia_level: 2,
      inbound_anomaly_threshold: 5,
      outbound_anomaly_threshold: 4,
      auto_purge_edge_cache: false,
      real_ip_header: 'X-Real-IP',
      edge_sync_interval_seconds: 30,
    })
  })

  // Telegram moved to per-person links (Alert Center); the bot token lives in .env.
  it('never sends the retired global Telegram fields', async () => {
    await settingsApi.updateSettings({ ...loaded, telegram_bot_token: '123:abc' } as unknown as SystemSettings)
    const sent = post.mock.calls[0][1]
    expect(sent).not.toHaveProperty('telegram_bot_token')
    expect(sent).not.toHaveProperty('telegram_chat_id')
    expect(sent).not.toHaveProperty('telegram_notifications')
  })
})
