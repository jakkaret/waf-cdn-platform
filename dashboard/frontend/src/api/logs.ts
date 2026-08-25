import { api } from './axios'
import { WafLog } from '../types'

export interface LogsResponse {
  logs: WafLog[]
  total: number
  page: number
  limit: number
  total_pages: number
}

export interface LogFilterOptions {
  status_codes: number[]
  methods: string[]
  severities: string[]
}

export const logsApi = {
  getRecentLogs: async (limit: number = 100, origin: string = 'ALL'): Promise<WafLog[]> => {
    const res = await api.get<{ logs: WafLog[] }>('/logs/recent', {
      params: { limit, origin, page: 1 }
    })
    return res.data.logs || []
  },
  getLogsPaginated: async (params?: {
    limit?: number
    page?: number
    search?: string
    status_filter?: string
    severity_filter?: string
    method_filter?: string
    origin?: string
  }): Promise<LogsResponse> => {
    const res = await api.get<LogsResponse>('/logs', {
      params: {
        limit: params?.limit || 20,
        page: params?.page || 1,
        search: params?.search || '',
        status: params?.status_filter || 'ALL',
        severity: params?.severity_filter || 'ALL',
        method: params?.method_filter || 'ALL',
        origin: params?.origin || 'ALL'
      }
    })
    return res.data
  },
  getFilterOptions: async (): Promise<LogFilterOptions> => {
    const res = await api.get<LogFilterOptions>('/logs/filters')
    return res.data
  }
}
