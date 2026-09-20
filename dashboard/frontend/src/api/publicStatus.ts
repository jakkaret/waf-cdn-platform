import axios from 'axios'

// Deliberately a separate axios instance, not the shared `api` client from
// './axios' -- that one attaches an Authorization header from the signed-in
// user's token whenever one exists, which is harmless here (the backend
// endpoint ignores it, there's no Depends(get_current_user)) but this page
// must work identically for a visitor who has never logged in at all, so
// it never depends on that store being initialized.
const publicApi = axios.create({ baseURL: '/api/status' })

export interface StatusComponent {
  id: string
  name: string
  status: 'operational' | 'degraded' | 'unknown'
}

export interface PublicStatus {
  overall_status: 'operational' | 'degraded' | 'unknown'
  components: StatusComponent[]
  checked_at: string
}

export interface UptimeDay {
  date: string
  uptime_pct: number | null
}

export type UptimeHistory = Record<string, UptimeDay[]>

export const publicStatusApi = {
  getStatus: async (): Promise<PublicStatus> => {
    const res = await publicApi.get<PublicStatus>('/public')
    return res.data
  },
  getHistory: async (days = 90): Promise<UptimeHistory> => {
    const res = await publicApi.get<UptimeHistory>('/public/history', { params: { days } })
    return res.data
  },
}
