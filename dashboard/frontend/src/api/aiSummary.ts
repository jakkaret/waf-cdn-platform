import { api } from './axios'

export interface SummarizeRangeResponse {
  success: boolean
  time_range: {
    start: string
    end: string
    description: string
  }
  stats: {
    total_requests: number
    blocked_attacks: number
    top_attack_types: { type: string; count: number }[]
    top_attacker_ips: { ip: string; country: string; count: number }[]
    top_targeted_urls: { url: string; count: number }[]
  }
  ai_executive_summary: string
}

export interface NotificationItem {
  alert_id: string
  timestamp: string
  ip: string
  url: string
  status: string
  rule_id: string
  attack_type: string
  severity: string
  edge_node: string
  ai_summary?: string
  message?: string
  read?: boolean
}

export const aiSummaryApi = {
  summarizeRange: async (query?: string, startTime?: string, endTime?: string): Promise<SummarizeRangeResponse> => {
    const res = await api.post('/ai/summarize-range', {
      query,
      start_time: startTime,
      end_time: endTime,
    })
    return res.data
  },

  getNotificationFeed: async (limit = 50): Promise<{ success: boolean; count: number; unread_count: number; notifications: NotificationItem[] }> => {
    const res = await api.get('/ai/notifications/feed', { params: { limit } })
    return res.data
  },

  markRead: async (alertId?: string): Promise<{ success: boolean }> => {
    const res = await api.post('/ai/notifications/mark-read', { alert_id: alertId })
    return res.data
  },
}
