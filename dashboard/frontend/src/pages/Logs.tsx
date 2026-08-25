import React, { useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { useOriginFilterStore } from '../store/originFilterStore'
import { TopBar } from '../components/layout/TopBar'
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
  const [page, setPage] = useState(1)
  const [pageInput, setPageInput] = useState('')
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [selectedLog, setSelectedLog] = useState<WafLog | null>(null)
  const [copiedText, setCopiedText] = useState<string | null>(null)
  const limit = 20

  const { selectedOrigin, selectedOriginLabel, setSelectedOrigin } = useOriginFilterStore()

  const { data: filterOptions } = useQuery({
    queryKey: ['log-filters'],
    queryFn: () => logsApi.getFilterOptions(),
    staleTime: 30000,
  })

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['logs-paginated', page, search, statusFilter, severityFilter, methodFilter, selectedOrigin],
    queryFn: () =>
      logsApi.getLogsPaginated({
        page,
        limit,
        search,
        status_filter: statusFilter,
        severity_filter: severityFilter,
        method_filter: methodFilter,
        origin: selectedOrigin,
      }),
    refetchInterval: 6000,
  })

  const logs = data?.logs || []
  const total = data?.total || 0
  const totalPages = data?.total_pages || 1

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value)
    setPage(1)
  }

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(text)
    toast.success(`Copied ${label}`)
    setTimeout(() => setCopiedText(null), 2000)
  }

  const handleJumpPage = (e: React.FormEvent) => {
    e.preventDefault()
    const target = parseInt(pageInput, 10)
    if (!isNaN(target) && target >= 1 && target <= totalPages) {
      setPage(target)
      setPageInput('')
    }
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
    a.download = `waf_traffic_logs_page${page}_${formatThaiDateTime(new Date()).slice(0, 10)}.csv`
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

  const startRecord = (page - 1) * limit + 1
  const endRecord = Math.min(page * limit, total)

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
                setPage(1)
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
                setPage(1)
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
                setPage(1)
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
                      {formatThaiDateTime(log.datetime)}
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

        {/* Pagination Bar */}
        <div className="p-3.5 border-t border-[var(--bg-border)] flex flex-col sm:flex-row items-center justify-between gap-3 text-[12px] font-mono text-[var(--text-muted)]">
          <div>
            Showing <strong className="text-[var(--text-primary)]">{total > 0 ? startRecord : 0}</strong>–
            <strong className="text-[var(--text-primary)]">{endRecord}</strong> of{' '}
            <strong className="text-orange-500">{total.toLocaleString()}</strong> events
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(1)}
              disabled={page <= 1}
              className="p-1.5 rounded-lg border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] disabled:opacity-40 cursor-pointer"
            >
              <ChevronsLeft size={14} />
            </button>
            <button
              onClick={() => setPage((p) => Math.max(p - 1, 1))}
              disabled={page <= 1}
              className="p-1.5 rounded-lg border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] disabled:opacity-40 cursor-pointer"
            >
              <ChevronLeft size={14} />
            </button>

            <span className="px-2 font-bold text-[var(--text-primary)]">
              Page {page} of {totalPages}
            </span>

            <button
              onClick={() => setPage((p) => Math.min(p + 1, totalPages))}
              disabled={page >= totalPages}
              className="p-1.5 rounded-lg border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] disabled:opacity-40 cursor-pointer"
            >
              <ChevronRight size={14} />
            </button>
            <button
              onClick={() => setPage(totalPages)}
              disabled={page >= totalPages}
              className="p-1.5 rounded-lg border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] disabled:opacity-40 cursor-pointer"
            >
              <ChevronsRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Log Detail Modal */}
      {selectedLog &&
        createPortal(
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in font-mono">
            <div className="bg-[var(--bg-surface)] border border-[var(--bg-border)] rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl overflow-y-auto max-h-[90vh]">
              <div className="flex justify-between items-center border-b border-[var(--bg-border)] pb-3">
                <div className="flex items-center gap-2">
                  <Code size={16} className="text-orange-500" />
                  <h3 className="text-[14px] font-bold text-[var(--text-primary)] m-0">
                    Event Inspection Details
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedLog(null)}
                  className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] text-[16px] cursor-pointer"
                >
                  ✕
                </button>
              </div>

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

              <div className="grid grid-cols-3 gap-3 text-[12px]">
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
                  <p className="font-bold text-[var(--text-primary)] m-0">{selectedLog.severity || 'LOW'}</p>
                </div>
              </div>

              {selectedLog.rule_id && (
                <div className="p-2.5 rounded-xl bg-red-950/20 border border-red-500/30 space-y-1 text-[12px]">
                  <span className="text-[10.5px] text-red-400 uppercase font-bold">Triggered ModSecurity Rule</span>
                  <p className="font-bold text-red-300 m-0">Rule ID: {selectedLog.rule_id}</p>
                </div>
              )}

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setSelectedLog(null)}
                  className="px-4 py-2 rounded-xl bg-orange-500 hover:bg-orange-600 text-white font-bold text-[12px] transition-colors cursor-pointer"
                >
                  Close Inspection
                </button>
              </div>
            </div>
          </div>,
          document.body
        )}
    </div>
  )
}

export default Logs
