import React, { useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import {
  Download,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Copy,
  Check,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  ExternalLink,
  Code,
} from 'lucide-react'
import { WafLog } from '../types'
import toast from 'react-hot-toast'

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

  const { data: filterOptions } = useQuery({
    queryKey: ['log-filters'],
    queryFn: () => logsApi.getFilterOptions(),
    staleTime: 30000,
  })

  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ['logs-paginated', page, search, statusFilter, severityFilter, methodFilter],
    queryFn: () =>
      logsApi.getLogsPaginated({
        page,
        limit,
        search,
        status_filter: statusFilter,
        severity_filter: severityFilter,
        method_filter: methodFilter,
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
    const headers = ['datetime', 'ip', 'method', 'url', 'status', 'rule_id', 'severity']
    const csvRows = [
      headers.join(','),
      ...logs.map((log) => [
        `"${log.datetime}"`,
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
    a.download = `waf_traffic_logs_page${page}_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    toast.success('Downloaded log records CSV')
  }

  const getStatusBadge = (status: number) => {
    if (status === 403) return <Badge color="danger">403 BLOCKED</Badge>
    if (status === 429) return <Badge color="warning">429 RATE LIMIT</Badge>
    if (status >= 500) return <Badge color="danger">{status} SERVER ERR</Badge>
    if (status >= 400) return <Badge color="gray">{status} CLIENT ERR</Badge>
    if (status >= 300) return <Badge color="info">{status} REDIRECT</Badge>
    if (status >= 200) return <Badge color="success">{status} OK</Badge>
    return <Badge>{status}</Badge>
  }

  const getSeverityBadge = (severity?: string | null, status?: number) => {
    if (!severity && status === 403) return <Badge color="danger">CRITICAL</Badge>
    if (!severity) return <Badge color="gray">NONE</Badge>
    const s = String(severity).toUpperCase()
    if (s === 'CRITICAL' || s === '0' || s === '1' || s === '2') return <Badge color="danger">CRITICAL</Badge>
    if (s === 'HIGH' || s === '3' || s === 'ERROR') return <Badge color="warning">HIGH</Badge>
    if (s === 'MEDIUM' || s === '4' || s === 'WARNING') return <Badge color="info">MEDIUM</Badge>
    if (s === 'LOW' || s === '5' || s === 'NOTICE') return <Badge color="success">LOW</Badge>
    return <Badge color="gray">{s}</Badge>
  }

  const getMethodBadge = (method: string) => {
    const m = (method || 'GET').toUpperCase()
    if (m === 'GET') return <span className="font-mono font-bold text-[11px] text-sky-500">GET</span>
    if (m === 'POST') return <span className="font-mono font-bold text-[11px] text-emerald-500">POST</span>
    if (m === 'PUT') return <span className="font-mono font-bold text-[11px] text-amber-500">PUT</span>
    if (m === 'DELETE') return <span className="font-mono font-bold text-[11px] text-red-500">DELETE</span>
    return <span className="font-mono font-bold text-[11px] text-[var(--text-secondary)]">{m}</span>
  }

  const startRecord = total === 0 ? 0 : (page - 1) * limit + 1
  const endRecord = Math.min(page * limit, total)

  const getPageNumbers = () => {
    const pages: (number | string)[] = []
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i)
    } else {
      pages.push(1)
      if (page > 3) pages.push('...')
      for (let i = Math.max(2, page - 1); i <= Math.min(totalPages - 1, page + 1); i++) pages.push(i)
      if (page < totalPages - 2) pages.push('...')
      pages.push(totalPages)
    }
    return pages
  }

  return (
    <div className="space-y-5 animate-fade-in">
      <TopBar
        title="Live Traffic & Threat Inspector"
        subtitle="Full real-time ModSecurity & Nginx HTTP request stream"
        badge={
          <Badge color="brand" dot pulse>
            STREAMING ACTIVE
          </Badge>
        }
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--bg-surface)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] text-[12px] font-mono font-medium text-[var(--text-primary)] rounded-md hover:bg-[var(--bg-hover)] transition-colors cursor-pointer"
            >
              <RefreshCw size={13} className={isFetching ? 'animate-spin text-orange-500' : 'text-[var(--text-muted)]'} />
              <span>Refresh</span>
            </button>
            <button
              onClick={exportToCSV}
              disabled={logs.length === 0}
              className="flex items-center gap-1.5 bg-orange-500 hover:bg-orange-600 text-white px-3 py-1.5 text-[12px] font-mono font-semibold rounded-md disabled:opacity-40 shadow-sm transition-all cursor-pointer"
            >
              <Download size={13} />
              <span>Export CSV</span>
            </button>
          </div>
        }
      />

      <div className="dash-card overflow-hidden">
        {/* Advanced Filter Toolbar */}
        <div className="p-3.5 border-b border-[var(--bg-border)] bg-[var(--bg-surface)] flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5 flex-1">
            {/* Search Box */}
            <div className="relative flex-1 min-w-[200px] max-w-sm">
              <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
              <input
                type="text"
                placeholder="Filter by IP, Path, Rule ID, or URI..."
                className="w-full dash-input pl-8 py-1.5 text-[12px] font-mono"
                value={search}
                onChange={handleSearchChange}
              />
            </div>

            {/* Status Filter */}
            <select
              className="dash-input py-1.5 text-[12px] font-mono cursor-pointer"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value)
                setPage(1)
              }}
            >
              <option value="ALL">All Status Codes</option>
              <option value="BLOCKED">403 (WAF Blocked)</option>
              <option value="ALLOWED">2xx (Clean / OK)</option>
              <option value="429">429 (Rate Limited)</option>
              <option value="500">500 (Server Error)</option>
            </select>

            {/* Method Filter */}
            <select
              className="dash-input py-1.5 text-[12px] font-mono cursor-pointer"
              value={methodFilter}
              onChange={(e) => {
                setMethodFilter(e.target.value)
                setPage(1)
              }}
            >
              <option value="ALL">All HTTP Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>

            {/* Severity Filter */}
            <select
              className="dash-input py-1.5 text-[12px] font-mono cursor-pointer"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value)
                setPage(1)
              }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="NONE">None</option>
            </select>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-[var(--text-secondary)] text-[12px] font-mono whitespace-nowrap">
              {total > 0 ? (
                <>
                  <strong className="text-[var(--text-primary)]">{startRecord.toLocaleString()}</strong>–
                  <strong className="text-[var(--text-primary)]">{endRecord.toLocaleString()}</strong> of{' '}
                  <strong className="text-orange-500">{total.toLocaleString()}</strong> events
                </>
              ) : (
                '0 matching events'
              )}
            </span>
          </div>
        </div>

        {/* Enterprise Log Table */}
        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>Timestamp (UTC+7)</th>
                <th>Client IP</th>
                <th>Method</th>
                <th>Request URI</th>
                <th>Status</th>
                <th>Triggered Rule</th>
                <th>Severity</th>
                <th className="text-right">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)] text-[12.5px] font-mono">
                    <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                    Querying ClickHouse telemetry database...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)] text-[12.5px] font-mono">
                    <ShieldCheck size={24} className="mx-auto mb-2 text-emerald-500 opacity-60" />
                    No traffic records match the specified query filters.
                  </td>
                </tr>
              ) : (
                logs.map((log: WafLog, idx: number) => {
                  const isThreat = log.status === 403 || log.status === 429
                  return (
                    <tr
                      key={log.log_id || idx}
                      className={`cursor-pointer transition-colors ${
                        isThreat
                          ? 'bg-red-500/[0.04] hover:bg-red-500/[0.08]'
                          : 'hover:bg-[var(--bg-hover)]'
                      }`}
                      onClick={() => setSelectedLog(log)}
                    >
                      <td className="font-mono text-[11px] text-[var(--text-muted)] whitespace-nowrap">
                        {log.datetime}
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5 font-mono font-bold text-[12px] text-[var(--text-primary)]">
                          <span>{log.ip}</span>
                        </div>
                      </td>
                      <td>{getMethodBadge(log.method)}</td>
                      <td className="font-mono text-[11.5px] max-w-[320px] truncate text-[var(--text-primary)]" title={log.url}>
                        {log.url}
                      </td>
                      <td>{getStatusBadge(log.status)}</td>
                      <td>
                        <span className="font-mono text-[11px] text-[var(--text-secondary)]">
                          {log.rule_id || (log.status === 403 ? 'WAF-CRS-942100' : '—')}
                        </span>
                      </td>
                      <td>{getSeverityBadge(log.severity, log.status)}</td>
                      <td className="text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedLog(log)
                          }}
                          className="px-2 py-1 text-[11px] font-mono font-semibold rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[var(--text-secondary)] hover:text-orange-500 hover:border-orange-500/30 transition-colors"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Enterprise Pagination Bar */}
        <div className="px-4 py-3 border-t border-[var(--bg-border)] bg-[var(--bg-surface)] flex items-center justify-between gap-4 flex-wrap text-[12px] font-mono">
          <form onSubmit={handleJumpPage} className="flex items-center gap-2 text-[var(--text-secondary)]">
            <span>
              Page <strong className="text-[var(--text-primary)]">{page}</strong> of{' '}
              <strong className="text-[var(--text-primary)]">{totalPages.toLocaleString()}</strong>
            </span>
            <span className="opacity-30">|</span>
            <span className="text-[11px] text-[var(--text-muted)]">Go to:</span>
            <input
              type="number"
              min={1}
              max={totalPages}
              placeholder="#"
              value={pageInput}
              onChange={(e) => setPageInput(e.target.value)}
              className="w-14 dash-input py-0.5 px-2 text-center text-[12px] font-mono"
            />
            <button
              type="submit"
              disabled={!pageInput}
              className="bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] px-2.5 py-1 text-[11.5px] font-semibold rounded disabled:opacity-40 hover:bg-[var(--bg-hover)] cursor-pointer"
            >
              Jump
            </button>
            {isFetching && <span className="ml-1 text-orange-500 text-[11px] animate-pulse">Syncing...</span>}
          </form>

          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setPage(1)}
              disabled={page <= 1}
              title="First Page"
              className="p-1.5 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] disabled:opacity-30 cursor-pointer"
            >
              <ChevronsLeft size={14} />
            </button>
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="flex items-center gap-1 px-2.5 py-1 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] disabled:opacity-30 cursor-pointer"
            >
              <ChevronLeft size={13} /> Prev
            </button>

            {getPageNumbers().map((num, idx) =>
              num === '...' ? (
                <span key={`ellipsis-${idx}`} className="px-1 text-[var(--text-muted)]">
                  …
                </span>
              ) : (
                <button
                  key={`page-${num}`}
                  onClick={() => setPage(num as number)}
                  className={`min-w-[28px] h-7 text-[12px] font-mono font-semibold rounded border cursor-pointer ${
                    page === num
                      ? 'bg-orange-500 text-white border-orange-500 shadow-sm'
                      : 'bg-[var(--bg-surface)] border-[var(--bg-border)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)]'
                  }`}
                >
                  {num}
                </button>
              )
            )}

            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="flex items-center gap-1 px-2.5 py-1 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] disabled:opacity-30 cursor-pointer"
            >
              Next <ChevronRight size={13} />
            </button>
            <button
              onClick={() => setPage(totalPages)}
              disabled={page >= totalPages}
              title="Last Page"
              className="p-1.5 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] disabled:opacity-30 cursor-pointer"
            >
              <ChevronsRight size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Log Detail Inspector Modal */}
      {selectedLog && typeof document !== 'undefined' && createPortal(
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setSelectedLog(null)
          }}
        >
          <div
            className="dash-modal w-full max-w-2xl shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="dash-card-header bg-[var(--bg-surface-elevated)]">
              <div className="flex items-center gap-2.5">
                <Code size={16} className="text-orange-500" />
                <h3 className="font-mono">Security Event Inspector</h3>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] font-mono text-base px-2 cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="p-5 space-y-4 max-h-[80vh] overflow-y-auto font-mono text-[12px]">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                    Event Time
                  </span>
                  <span className="text-[var(--text-primary)]">{selectedLog.datetime}</span>
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] flex items-center justify-between">
                  <div>
                    <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                      Client IP
                    </span>
                    <span className="text-[var(--text-primary)] font-bold">{selectedLog.ip}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(selectedLog.ip, 'IP')}
                    className="p-1 rounded text-[var(--text-muted)] hover:text-orange-500 cursor-pointer"
                  >
                    {copiedText === selectedLog.ip ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                  HTTP Request Target
                </span>
                <div className="flex items-center gap-2">
                  {getMethodBadge(selectedLog.method)}
                  <span className="text-[var(--text-primary)] break-all">{selectedLog.url}</span>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                    HTTP Status
                  </span>
                  {getStatusBadge(selectedLog.status)}
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                    Threat Severity
                  </span>
                  {getSeverityBadge(selectedLog.severity, selectedLog.status)}
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                    Rule ID
                  </span>
                  <span className="font-bold text-orange-500">
                    {selectedLog.rule_id || (selectedLog.status === 403 ? 'WAF-CRS-942100' : 'NONE')}
                  </span>
                </div>
              </div>

              {selectedLog.status === 403 && (
                <div className="p-3.5 rounded-lg bg-red-500/[0.08] border border-red-500/20 text-red-400 space-y-1">
                  <div className="flex items-center gap-1.5 font-bold text-[11px] uppercase">
                    <ShieldAlert size={14} />
                    <span>ModSecurity Inbound Anomaly Score Exceeded</span>
                  </div>
                  <p className="text-[11.5px] text-[var(--text-secondary)] m-0">
                    This request was intercepted and denied by the OWASP ModSecurity Core Rule Set (CRS 3.3) engine.
                  </p>
                </div>
              )}

              <div className="flex justify-end pt-3 border-t border-[var(--bg-border)]">
                <button
                  onClick={() => setSelectedLog(null)}
                  className="px-4 py-1.5 bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] rounded-md font-semibold text-[12px] cursor-pointer"
                >
                  Close Inspector
                </button>
              </div>
            </div>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}

export default Logs
