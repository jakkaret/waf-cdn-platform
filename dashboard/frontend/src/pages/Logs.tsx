import React, { useState, useMemo } from 'react'
import { useQuery, useInfiniteQuery } from '@tanstack/react-query'
import { logsApi, LogCursor, HistogramBucket } from '../api/logs'
import { useOriginFilterStore } from '../store/originFilterStore'
import { TopBar } from '../components/layout/TopBar'
import { Drawer } from '../components/ui/Drawer'
import { Badge } from '../components/ui/Badge'
import {
  Download,
  Search,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Code,
  Shield,
  X,
} from 'lucide-react'
import { WafLog } from '../types'
import toast from 'react-hot-toast'
import { useDebouncedValue } from '../lib/useDebouncedValue'

// Helper function to format timestamp to Thailand Timezone (Asia/Bangkok • UTC+7)
export const formatThaiDateTime = (rawDate?: string | number | Date | null): string => {
  if (!rawDate) return '—'
  try {
    let d: Date
    if (rawDate instanceof Date) {
      d = rawDate
    } else if (typeof rawDate === 'number') {
      d = rawDate < 1e12 ? new Date(rawDate * 1000) : new Date(rawDate)
    } else {
      let s = String(rawDate).trim()
      if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(s)) {
        s = s.replace(' ', 'T') + 'Z'
      } else if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$/.test(s)) {
        s = s + 'Z'
      }
      d = new Date(s)
    }

    if (isNaN(d.getTime())) return String(rawDate)

    const parts = new Intl.DateTimeFormat('en-GB', {
      timeZone: 'Asia/Bangkok',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).formatToParts(d)

    const map: Record<string, string> = {}
    parts.forEach((p) => {
      map[p.type] = p.value
    })

    return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}:${map.second}`
  } catch {
    return String(rawDate)
  }
}

export const Logs: React.FC = () => {
  // Filter-first at scale: a time range narrows the search, and we never
  // deep-page -- a cursor 'load more' walks newest->older in place (F: log UX).
  const [rangePreset, setRangePreset] = useState<'15m'|'1h'|'24h'|'7d'|'all'>('24h')
  const [search, setSearch] = useState('')
  const debouncedSearch = useDebouncedValue(search)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [selectedLog, setSelectedLog] = useState<WafLog | null>(null)
  const [copiedText, setCopiedText] = useState<string | null>(null)
  
  const [explanation, setExplanation] = useState<string | null>(null)
  const [isExplaining, setIsExplaining] = useState(false)
  const [maskedPayload, setMaskedPayload] = useState<string | null>(null)
  const [isMasking, setIsMasking] = useState(false)
  const range = useMemo(() => {
    if (rangePreset === 'all') return { from: null as number | null, to: null as number | null }
    const now = Math.floor(Date.now() / 1000)
    const span = { '15m': 900, '1h': 3600, '24h': 86400, '7d': 604800 }[rangePreset]
    return { from: now - span, to: null as number | null }
  }, [rangePreset])
  // histogram bucket chosen from the span so the bar chart stays readable
  const bucketSeconds = rangePreset === '15m' ? 60 : rangePreset === '1h' ? 300 : rangePreset === '24h' ? 3600 : rangePreset === '7d' ? 86400 : 86400

  const { selectedOrigin, selectedOriginLabel, setSelectedOrigin } = useOriginFilterStore()

  const { data: filterOptions } = useQuery({
    queryKey: ['log-filters'],
    queryFn: () => logsApi.getFilterOptions(),
    staleTime: 30000,
  })

  const commonFilters = {
    search: debouncedSearch,
    status_filter: statusFilter,
    severity_filter: severityFilter,
    method_filter: methodFilter,
    origin: selectedOrigin,
    from_ts: range.from,
    to_ts: range.to,
  }

  const { data, isLoading, isFetching, refetch, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useInfiniteQuery({
      queryKey: ['logs-stream', debouncedSearch, statusFilter, severityFilter, methodFilter, selectedOrigin, range.from, range.to],
      queryFn: ({ pageParam }) => logsApi.getLogStream({ ...commonFilters, limit: 50, cursor: pageParam as LogCursor | null }),
      initialPageParam: null as LogCursor | null,
      getNextPageParam: (lastPage) => (lastPage.has_more ? lastPage.next_cursor : undefined),
      refetchInterval: 8000,
    })

  const logs = data?.pages.flatMap((pg) => pg.logs) ?? []
  const total = logs.length

  const { data: histogram = [] } = useQuery<HistogramBucket[]>({
    queryKey: ['logs-histogram', debouncedSearch, statusFilter, severityFilter, methodFilter, selectedOrigin, range.from, range.to, bucketSeconds],
    queryFn: () => logsApi.getHistogram({ ...commonFilters, bucket_seconds: bucketSeconds }),
    refetchInterval: 15000,
  })
  const histoMax = histogram.reduce((m, b) => Math.max(m, b.total), 1)

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value)
  }

  const handleExplainLog = async (logId: string) => {
    try {
      setIsExplaining(true)
      const res = await logsApi.explainLog(logId)
      setExplanation(res.explanation || res.analysis || JSON.stringify(res))
    } catch (err) {
      toast.error('Failed to generate explanation')
    } finally {
      setIsExplaining(false)
    }
  }

  const handleMaskPreview = async (logId: string, logUrl: string) => {
    try {
      setIsMasking(true)
      // Sending URL to preview masking
      const res = await logsApi.maskPreview(logUrl)
      setMaskedPayload(res.masked_text || res.masked_payload || JSON.stringify(res))
    } catch (err) {
      toast.error('Failed to generate mask preview')
    } finally {
      setIsMasking(false)
    }
  }

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(text)
    toast.success(`Copied ${label}`)
    setTimeout(() => setCopiedText(null), 2000)
  }


  const exportToCSV = () => {
    if (logs.length === 0) return
    const headers = ['datetime_bkk', 'ip', 'method', 'url', 'status', 'rule_id', 'severity']
    const csvRows = [
      headers.join(','),
      ...logs.map((log) => [
        `"${formatThaiDateTime(log.datetime)}"`,
        `"${log.ip}"`,
        `"${log.method}"`,
        `"${(log.url || '').replace(/"/g, '""')}"`,
        log.status,
        `"${log.rule_id || (log.status === 403 ? 'WAF-CRS' : '')}"`,
        `"${log.severity || (log.status === 403 ? 'CRITICAL' : '')}"`,
      ].join(',')),
    ]
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const a = document.createElement('a')
    a.href = window.URL.createObjectURL(blob)
    a.download = `waf_traffic_logs_${formatThaiDateTime(new Date()).slice(0, 10)}.csv`
    a.click()
    toast.success('Downloaded log records CSV')
  }

  const getStatusBadge = (status: number) => {
    if (status === 403) return <Badge color="danger">403 BLOCKED</Badge>
    if (status === 429) return <Badge color="warning">429 RATE LIMIT</Badge>
    if (status >= 500) return <Badge color="danger">{status} SERVER ERR</Badge>
    if (status >= 400) return <Badge color="warning">{status} CLIENT ERR</Badge>
    if (status >= 300) return <Badge color="info">{status} REDIRECT</Badge>
    return <Badge color="success">{status} OK</Badge>
  }

  const getSeverityBadge = (severity?: string | null) => {
    const sev = (severity || 'NONE').toUpperCase()
    if (sev === 'CRITICAL') return <Badge color="danger">CRITICAL</Badge>
    if (sev === 'HIGH') return <Badge color="danger">HIGH</Badge>
    if (sev === 'MEDIUM') return <Badge color="warning">MEDIUM</Badge>
    if (sev === 'LOW') return <Badge color="info">LOW</Badge>
    return <Badge color="gray">NONE</Badge>
  }


  return (
    <div className="animate-fade-in pb-8">
      {/* Top Header Bar */}
      <TopBar
        title="Traffic Inspection Log"
        subtitle="Real-time reverse proxy access stream and deep threat inspection"
        badge={
          <Badge color="success" dot pulse>
            LIVE TELEMETRY
          </Badge>
        }
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={exportToCSV}
              disabled={logs.length === 0}
              className="flex items-center gap-1.5 px-3 py-1.8 bg-[var(--bg-surface)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] text-[12px] font-mono font-medium text-[var(--text-primary)] rounded-xl hover:bg-[var(--bg-hover)] shadow-sm transition-all cursor-pointer disabled:opacity-40"
              title="Export visible log rows to CSV"
            >
              <Download size={13} className="text-[var(--text-muted)]" />
              <span className="hidden sm:inline">Export CSV</span>
            </button>
            <button
              onClick={() => {
                refetch()
                toast.success('Logs refreshed')
              }}
              disabled={isFetching}
              className="flex items-center gap-1.5 px-3 py-1.8 bg-[var(--bg-surface)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] text-[12px] font-mono font-medium text-[var(--text-primary)] rounded-xl hover:bg-[var(--bg-hover)] shadow-sm transition-all cursor-pointer"
              title="Refresh log stream"
            >
              <RefreshCw size={13} className={isFetching ? 'animate-spin text-orange-500' : 'text-[var(--text-muted)]'} />
              <span className="hidden sm:inline">Refresh</span>
            </button>
          </div>
        }
      />

      {/* Origin Scope Filter Indicator Banner */}
      {selectedOrigin !== 'ALL' && (
        <div className="mb-5 p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-between gap-3 text-indigo-300 font-mono text-[12px] animate-fade-in">
          <div className="flex items-center gap-2 truncate">
            <Shield size={16} className="text-indigo-400 shrink-0" />
            <span className="truncate">
              Showing Traffic Logs for Origin:{' '}
              <strong className="text-white font-bold">{selectedOriginLabel}</strong>{' '}
              <span className="text-indigo-300/70 text-[11px]">({selectedOrigin})</span>
            </span>
          </div>
          <button
            onClick={() => setSelectedOrigin('ALL', 'All Managed Origins (ทั้งหมด)')}
            className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-white text-[11px] font-bold transition-colors cursor-pointer shrink-0"
          >
            <X size={12} />
            <span>Show All Origins</span>
          </button>
        </div>
      )}

      {/* Time range + activity histogram (filter-first, click a bar to zoom) */}
      <div className="dash-card p-4 mb-4 font-mono">
        <div className="flex items-center justify-between mb-3 gap-2 flex-wrap">
          <div className="flex items-center gap-1.5">
            {(['15m','1h','24h','7d','all'] as const).map((r) => (
              <button
                key={r}
                onClick={() => setRangePreset(r)}
                className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold border transition-colors cursor-pointer ${
                  rangePreset === r
                    ? 'border-orange-500 bg-orange-500/10 text-orange-500'
                    : 'border-[var(--bg-border)] text-[var(--text-muted)] hover:bg-[var(--bg-hover)]'
                }`}
              >
                {r === 'all' ? 'All' : `Last ${r}`}
              </button>
            ))}
          </div>
          <div className="text-[11px] text-[var(--text-muted)]">
            {histogram.reduce((a: number, b: HistogramBucket) => a + b.total, 0).toLocaleString()} events in range
            {' · '}
            {histogram.reduce((a: number, b: HistogramBucket) => a + b.blocked, 0).toLocaleString()} blocked
          </div>
        </div>
        <div className="flex items-end gap-[2px] h-16">
          {histogram.length === 0 ? (
            <div className="w-full text-center text-[11px] text-[var(--text-muted)] self-center">No activity in this range</div>
          ) : (
            histogram.map((b: HistogramBucket) => {
              const h = Math.max(2, Math.round((b.total / histoMax) * 64))
              const bh = b.total > 0 ? Math.round((b.blocked / b.total) * h) : 0
              const d = new Date(b.bucket * 1000)
              const label = `${d.toLocaleString('en-GB', { timeZone: 'Asia/Bangkok' })} — ${b.total} events, ${b.blocked} blocked`
              return (
                <div
                  key={b.bucket}
                  title={label}
                  className="flex-1 min-w-[2px] flex flex-col justify-end cursor-pointer group"
                  onClick={() => { setRangePreset('all'); }}
                >
                  <div className="w-full bg-red-500/80 rounded-t-sm" style={{ height: `${bh}px` }} />
                  <div className="w-full bg-orange-400/50 group-hover:bg-orange-400 rounded-b-sm" style={{ height: `${h - bh}px` }} />
                </div>
              )
            })
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="dash-card p-4 mb-4 font-mono">
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
          {/* Search Box */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" size={14} />
            <input
              type="text"
              placeholder="Search IP, URL, Rule ID..."
              value={search}
              onChange={handleSearchChange}
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[12px] text-[var(--text-primary)] focus:outline-none focus:border-orange-500 transition-colors"
            />
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value)
              }}
              className="w-full px-3 py-2 rounded-xl bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[12px] text-[var(--text-primary)] focus:outline-none focus:border-orange-500 transition-colors cursor-pointer"
            >
              <option value="ALL">All HTTP Status</option>
              <option value="BLOCKED">Blocked (403 / 429)</option>
              <option value="ALLOWED">Allowed (2xx OK)</option>
              {filterOptions?.status_codes?.map((code) => (
                <option key={code} value={String(code)}>
                  Status {code}
                </option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value)
              }}
              className="w-full px-3 py-2 rounded-xl bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[12px] text-[var(--text-primary)] focus:outline-none focus:border-orange-500 transition-colors cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">CRITICAL (Mitigated)</option>
              <option value="HIGH">HIGH (Server Errors)</option>
              <option value="MEDIUM">MEDIUM (Client Warnings)</option>
              <option value="LOW">LOW (Redirects)</option>
              <option value="NONE">NONE (Clean Traffic)</option>
            </select>
          </div>

          {/* Method Filter */}
          <div>
            <select
              value={methodFilter}
              onChange={(e) => {
                setMethodFilter(e.target.value)
              }}
              className="w-full px-3 py-2 rounded-xl bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[12px] text-[var(--text-primary)] focus:outline-none focus:border-orange-500 transition-colors cursor-pointer"
            >
              <option value="ALL">All Methods</option>
              {filterOptions?.methods?.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="dash-card overflow-hidden font-mono">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[12px]">
            <thead className="bg-[var(--bg-primary)] border-b border-[var(--bg-border)] text-[var(--text-muted)] uppercase text-[10.5px]">
              <tr>
                <th className="py-3 px-3.5">Timestamp (BKK)</th>
                <th className="py-3 px-3.5">Client IP</th>
                <th className="py-3 px-3.5">Method</th>
                <th className="py-3 px-3.5">Target Path / URL</th>
                <th className="py-3 px-3.5">Status</th>
                <th className="py-3 px-3.5">Severity</th>
                <th className="py-3 px-3.5 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--bg-border-subtle)]">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[var(--text-muted)]">
                    <div className="flex items-center justify-center gap-2">
                      <RefreshCw size={14} className="animate-spin text-orange-500" />
                      <span>Loading logs from ClickHouse database...</span>
                    </div>
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-[var(--text-muted)]">
                    No traffic log records found for this query / origin.
                  </td>
                </tr>
              ) : (
                logs.map((log, idx) => (
                  <tr
                    key={log.request_id || `log-${idx}`}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-[var(--bg-hover)] transition-colors cursor-pointer"
                  >
                    <td className="py-2.5 px-3.5 text-[var(--text-secondary)] whitespace-nowrap">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedLog(log)
                        }}
                        aria-label={`Inspect event from ${log.ip} at ${log.datetime}`}
                        className="text-left cursor-pointer rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-orange-500/60"
                      >
                        {formatThaiDateTime(log.datetime)}
                      </button>
                    </td>
                    <td className="py-2.5 px-3.5 font-bold text-[var(--text-primary)] whitespace-nowrap">
                      {log.ip}
                    </td>
                    <td className="py-2.5 px-3.5">
                      <span className="px-1.5 py-0.5 rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[10.5px] font-bold text-sky-400">
                        {log.method}
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 text-[var(--text-primary)] truncate max-w-[280px]">
                      {log.url || '/'}
                    </td>
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      {getStatusBadge(log.status)}
                    </td>
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      {getSeverityBadge(log.severity)}
                    </td>
                    <td className="py-2.5 px-3.5 text-right whitespace-nowrap">
                      <span className="text-orange-500 font-semibold text-[11px] hover:underline">
                        Inspect →
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Load-more footer (keyset -- no deep paging) */}
        <div className="p-3.5 border-t border-[var(--bg-border)] flex flex-col sm:flex-row items-center justify-between gap-3 text-[12px] font-mono text-[var(--text-muted)]">
          <div>
            Loaded <strong className="text-orange-500">{total.toLocaleString()}</strong> events
            {hasNextPage ? ' (more available)' : ' (end of range)'}
          </div>
          <button
            onClick={() => fetchNextPage()}
            disabled={!hasNextPage || isFetchingNextPage}
            className="px-4 py-1.5 rounded-lg border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] disabled:opacity-40 cursor-pointer text-[var(--text-primary)] font-semibold"
          >
            {isFetchingNextPage ? 'Loading…' : hasNextPage ? 'Load more' : 'No more'}
          </button>
        </div>
      </div>

      {/* Log Detail */}
      <Drawer
        open={!!selectedLog}
        onClose={() => {
          setSelectedLog(null)
          setExplanation(null)
          setMaskedPayload(null)
        }}
        size="lg"
        title={
          <span className="inline-flex items-center gap-2">
            <Code size={16} className="text-orange-500 shrink-0" aria-hidden="true" />
            <span>Event Inspection Details</span>
          </span>
        }
      >
        {selectedLog && (
          <div className="space-y-4 font-mono">
              <div className="grid grid-cols-2 gap-3 text-[12px]">
                <div className="p-2.5 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] space-y-1">
                  <span className="text-[10.5px] text-[var(--text-muted)] uppercase">Timestamp (Asia/Bangkok)</span>
                  <p className="font-bold text-[var(--text-primary)] m-0">{formatThaiDateTime(selectedLog.datetime)}</p>
                </div>
                <div className="p-2.5 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] space-y-1">
                  <span className="text-[10.5px] text-[var(--text-muted)] uppercase">Client IPv4</span>
                  <p className="font-bold text-orange-400 m-0">{selectedLog.ip}</p>
                </div>
              </div>

              <div className="p-2.5 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] space-y-1 text-[12px]">
                <span className="text-[10.5px] text-[var(--text-muted)] uppercase">Requested URL</span>
                <p className="font-bold text-[var(--text-primary)] break-all m-0">{selectedLog.url}</p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-[12px]">
                <div className="p-2.5 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] space-y-1">
                  <span className="text-[10.5px] text-[var(--text-muted)] uppercase">HTTP Method</span>
                  <p className="font-bold text-sky-400 m-0">{selectedLog.method}</p>
                </div>
                <div className="p-2.5 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] space-y-1">
                  <span className="text-[10.5px] text-[var(--text-muted)] uppercase">Status Code</span>
                  <p className="font-bold text-[var(--text-primary)] m-0">{selectedLog.status}</p>
                </div>
                <div className="p-2.5 rounded-xl bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] space-y-1">
                  <span className="text-[10.5px] text-[var(--text-muted)] uppercase">Severity</span>
                  {/* Matches the table badge's own fallback ('NONE', line
                      ~162) -- showing 'LOW' here for the same empty
                      severity implied an actual detected threat on a row
                      the table correctly marked as clean traffic. */}
                  <p className="font-bold text-[var(--text-primary)] m-0">{selectedLog.severity || 'NONE'}</p>
                </div>
              </div>

              {selectedLog.rule_id && (
                <div className="p-2.5 rounded-xl bg-red-950/20 border border-red-500/30 space-y-1 text-[12px]">
                  <span className="text-[10.5px] text-red-400 uppercase font-bold">Triggered ModSecurity Rule</span>
                  <p className="font-bold text-red-300 m-0">Rule ID: {selectedLog.rule_id}</p>
                </div>
              )}

              {/* Log Explain & Mask Preview Actions */}
              <div className="flex gap-2 pt-2">
                <button
                  onClick={() => handleExplainLog(selectedLog.log_id!)}
                  disabled={isExplaining}
                  className="flex-1 py-2 rounded-xl bg-indigo-500/20 text-indigo-400 hover:bg-indigo-500/30 font-bold text-[12px] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {isExplaining ? 'Analyzing...' : 'AI Explain Log'}
                </button>
                <button
                  onClick={() => handleMaskPreview(selectedLog.log_id!, selectedLog.url)}
                  disabled={isMasking}
                  className="flex-1 py-2 rounded-xl bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/30 font-bold text-[12px] transition-colors cursor-pointer disabled:opacity-50"
                >
                  {isMasking ? 'Masking...' : 'PII Mask Preview'}
                </button>
              </div>

              {explanation && (
                <div className="p-3 rounded-xl bg-indigo-950/30 border border-indigo-500/30 space-y-2 text-[12px]">
                  <span className="text-[10.5px] text-indigo-400 uppercase font-bold">AI Explanation</span>
                  <p className="text-[var(--text-primary)] m-0 leading-relaxed whitespace-pre-wrap">{explanation}</p>
                </div>
              )}

              {maskedPayload && (
                <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/30 space-y-2 text-[12px]">
                  <span className="text-[10.5px] text-emerald-400 uppercase font-bold">Masked Payload Preview</span>
                  <pre className="text-[var(--text-primary)] m-0 p-2 bg-black/40 rounded-lg overflow-x-auto text-[11px] font-mono whitespace-pre-wrap">
                    {maskedPayload}
                  </pre>
                </div>
              )}
          </div>
        )}
      </Drawer>
    </div>
  )
}

export default Logs
