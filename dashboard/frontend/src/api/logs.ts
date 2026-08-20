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
  getRecentLogs: async (limit: number = 100): Promise<WafLog[]> => {
    const res = await api.get<{ logs: WafLog[] }>('/logs/recent', {
      params: { limit, page: 1 }
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
  }): Promise<LogsResponse> => {
    const res = await api.get<LogsResponse>('/logs/recent', {
      params: {
        limit: params?.limit || 20,
        page: params?.page || 1,
        search: params?.search || '',
        status_filter: params?.status_filter || 'ALL',
        severity_filter: params?.severity_filter || 'ALL',
        method_filter: params?.method_filter || 'ALL'
      }
    })
    return res.data
  },
  getFilterOptions: async (): Promise<LogFilterOptions> => {
    const res = await api.get<LogFilterOptions>('/logs/filters')
    return res.data
  }
}
