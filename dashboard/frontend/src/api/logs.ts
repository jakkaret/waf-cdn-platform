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


export interface LogCursor { ts: number; id: string }
export interface LogStreamResponse { logs: WafLog[]; has_more: boolean; next_cursor: LogCursor | null }
export interface HistogramBucket { bucket: number; total: number; blocked: number }

export interface LogStreamParams {
  limit?: number
  search?: string
  status_filter?: string
  severity_filter?: string
  method_filter?: string
  origin?: string
  from_ts?: number | null
  to_ts?: number | null
  cursor?: LogCursor | null
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
  // Keyset (cursor) pagination -- stays fast at any depth, unlike page offsets.
  getLogStream: async (params: LogStreamParams): Promise<LogStreamResponse> => {
    const res = await api.get<LogStreamResponse>('/logs/stream', {
      params: {
        limit: params.limit ?? 50,
        search: params.search || '',
        status: params.status_filter || 'ALL',
        severity: params.severity_filter || 'ALL',
        method: params.method_filter || 'ALL',
        origin: params.origin || 'ALL',
        from_ts: params.from_ts ?? undefined,
        to_ts: params.to_ts ?? undefined,
        cursor_ts: params.cursor?.ts ?? undefined,
        cursor_id: params.cursor?.id ?? undefined,
      },
    })
    return res.data
  },
  getHistogram: async (params: Omit<LogStreamParams, 'cursor' | 'limit'> & { bucket_seconds?: number }): Promise<HistogramBucket[]> => {
    const res = await api.get<{ buckets: HistogramBucket[] }>('/logs/histogram', {
      params: {
        bucket_seconds: params.bucket_seconds ?? 3600,
        search: params.search || '',
        status: params.status_filter || 'ALL',
        severity: params.severity_filter || 'ALL',
        method: params.method_filter || 'ALL',
        origin: params.origin || 'ALL',
        from_ts: params.from_ts ?? undefined,
        to_ts: params.to_ts ?? undefined,
      },
    })
    return res.data.buckets || []
  },
  getFilterOptions: async (): Promise<LogFilterOptions> => {
    const res = await api.get<LogFilterOptions>('/logs/filters')
    return res.data
  },
  explainLog: async (logId: string): Promise<any> => {
    // GET /api/logs/explain/{log_id}
    const res = await api.get(`/logs/explain/${logId}`)
    return res.data
  },
  maskPreview: async (text: string): Promise<any> => {
    // POST /api/logs/mask-preview takes { text: "..." }
    const res = await api.post('/logs/mask-preview', { text })
    return res.data
  }
}
