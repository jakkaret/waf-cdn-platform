import React, { useEffect, useState, useMemo } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { alertsApi } from '../api/alerts'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Drawer } from '../components/ui/Drawer'
import { Button } from '../components/ui/Button'
import {
  Bell,
  Send,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Search,
  Calendar,
  Download,
  Code,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  X,
  Filter,
  Radio,
  Clock,
  Shield,
  Zap,
} from 'lucide-react'
import { WafAlert } from '../types'
import toast from 'react-hot-toast'
import { getDispatchLabel } from '../lib/alertDispatch'
import { IncidentList } from '../components/alerts/IncidentList'
import { BKK_LABEL, bkkDateKey, formatBkkDateTime } from '../lib/time'
import { originTabPath } from '../components/layout/navigation'
import { alertSeverity, isBlockableIp, logsSearchPath } from '../lib/alertActions'

const ALERTS_FETCH_LIMIT = 200

// Clean Alert ID helper (formats cleanly and strips accidental IP suffix)
const formatAlertId = (rawId?: string | null, fallbackIndex?: number): string => {
  if (!rawId) return `#ALT-${fallbackIndex ?? 1}`
  const raw = String(rawId).trim()
  // If it contains IP suffix like "1787395505-158.220.106.54", strip "-158.220.106.54"
  const cleaned = raw.replace(/-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/, '')
  if (cleaned.startsWith('ALT-') || cleaned.startsWith('#ALT-')) {
    return cleaned
  }
  return `ALT-${cleaned}`
}

export const Alerts: React.FC = () => {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  // ?alert=<alert_id> opens that alert's details (notification bell, links).
  const linkedAlertId = searchParams.get('alert')

  // Filter & Pagination States
  const [page, setPage] = useState(1)
  const [pageInput, setPageInput] = useState('')
  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [datePreset, setDatePreset] = useState<'all' | 'today' | '7d' | '30d'>('all')

  // Selected Alert Inspector Modal
  const [selectedAlert, setSelectedAlert] = useState<WafAlert | null>(null)
  const [copiedText, setCopiedText] = useState<string | null>(null)
  const limit = 15

  // Telegram connection (managed on the Notifications page; read here only
  // for the header link).
  const { data: status } = useQuery({
    queryKey: ['telegram-status'],
    queryFn: alertsApi.getConnectionStatus,
  })

  // Fetch Alerts History
  const { data: rawAlerts = [], isLoading: isAlertsLoading, isFetching: isAlertsFetching, refetch: refetchAlerts } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => alertsApi.getAlerts(ALERTS_FETCH_LIMIT),
    refetchInterval: 8000,
  })

  // Same query as IncidentList (shared cache): Telegram goes out per incident.
  const { data: incidents = [] } = useQuery({
    queryKey: ['alert-incidents'],
    queryFn: () => alertsApi.getIncidents({ limit: 10 }),
    refetchInterval: 30000,
  })

  // Open the linked alert once the list has it. An id that is not in the
  // fetched page (older, or not visible to this account) is reported, not
  // silently dropped.
  const [linkMissing, setLinkMissing] = useState(false)
  useEffect(() => {
    if (!linkedAlertId || isAlertsLoading) return
    const found = rawAlerts.find((a) => a.alert_id === linkedAlertId)
    if (found) {
      setSelectedAlert(found)
      setLinkMissing(false)
    } else {
      setLinkMissing(true)
    }
  }, [linkedAlertId, isAlertsLoading, rawAlerts])

  const closeAlert = () => {
    setSelectedAlert(null)
    if (searchParams.has('alert')) {
      const p = new URLSearchParams(searchParams)
      p.delete('alert')
      setSearchParams(p, { replace: true })
    }
  }

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(text)
    toast.success(`Copied ${label}`)
    setTimeout(() => setCopiedText(null), 2000)
  }

  // Date Preset Handler
  const handleDatePreset = (preset: 'all' | 'today' | '7d' | '30d') => {
    setDatePreset(preset)
    const now = new Date()
    // Calendar date in Asia/Bangkok, the zone the table displays (F-030):
    // toISOString() gave the UTC date, i.e. yesterday before 07:00 local.
    const formatDate = (d: Date) => bkkDateKey(d)

    if (preset === 'all') {
      setDateFrom('')
      setDateTo('')
    } else if (preset === 'today') {
      const todayStr = formatDate(now)
      setDateFrom(todayStr)
      setDateTo(todayStr)
    } else if (preset === '7d') {
      const past = new Date()
      past.setDate(past.getDate() - 7)
      setDateFrom(formatDate(past))
      setDateTo(formatDate(now))
    } else if (preset === '30d') {
      const past = new Date()
      past.setDate(past.getDate() - 30)
      setDateFrom(formatDate(past))
      setDateTo(formatDate(now))
    }
    setPage(1)
  }

  // Summary Metrics
  const alertMetrics = useMemo(() => {
    // /alerts/recent returns no total (needs a backend field); the array is
    // only the fetched page, so a full page is shown as a lower bound ("200+").
    const total = rawAlerts.length
    const totalIsLowerBound = rawAlerts.length >= ALERTS_FETCH_LIMIT
    // Recorded severity only: a 403 is the WAF's answer, not a threat level.
    const critical = rawAlerts.filter((a) => alertSeverity(a.severity) === 'CRITICAL').length
    const tracked = rawAlerts.some((a) => getDispatchLabel(a).label !== 'Not tracked')
    const dispatched = tracked ? rawAlerts.filter((a) => getDispatchLabel(a).state === 'sent').length : null
    return { total, totalIsLowerBound, critical, dispatched }
  }, [rawAlerts])

  // Filtered Alerts calculation
  const filteredAlerts = useMemo(() => {
    return rawAlerts.filter((alert) => {
      // 1. Search filter
      if (search.trim()) {
        const q = search.toLowerCase().trim()
        const matchIp = (alert.ip || '').toLowerCase().includes(q)
        const matchUrl = (alert.url || '').toLowerCase().includes(q)
        const matchMsg = (alert.message || '').toLowerCase().includes(q)
        const matchRule = (alert.rule_id || '').toLowerCase().includes(q)
        const formattedId = formatAlertId(alert.alert_id).toLowerCase()
        const matchId = (alert.alert_id || '').toLowerCase().includes(q) || formattedId.includes(q)
        if (!matchIp && !matchUrl && !matchMsg && !matchRule && !matchId) {
          return false
        }
      }

      // 2. Severity filter
      if (severityFilter !== 'ALL') {
        const sev = alertSeverity(alert.severity) ?? 'NONE'
        if (sev !== severityFilter) return false
      }

      // 3. Status filter
      if (statusFilter !== 'ALL') {
        const st = (alert.status || '').toUpperCase()
        if (statusFilter === 'DISPATCHED' && getDispatchLabel(alert).state !== 'sent') {
          return false
        }
        if (statusFilter === 'BLOCKED' && !st.includes('403') && !st.includes('BLOCK')) {
          return false
        }
      }

      // 4. Date From / Date To filter
      if (dateFrom || dateTo) {
        if (!alert.timestamp) return false
        const alertDate = new Date(alert.timestamp)
        if (isNaN(alertDate.getTime())) return true

        // Day bounds in Asia/Bangkok (UTC+7), matching the displayed
        // timestamps regardless of the browser's own time zone (F-030).
        if (dateFrom) {
          const from = new Date(`${dateFrom}T00:00:00.000+07:00`)
          if (alertDate < from) return false
        }
        if (dateTo) {
          const to = new Date(`${dateTo}T23:59:59.999+07:00`)
          if (alertDate > to) return false
        }
      }

      return true
    })
  }, [rawAlerts, search, severityFilter, statusFilter, dateFrom, dateTo])

  // Pagination calculation
  const total = filteredAlerts.length
  const totalPages = Math.max(1, Math.ceil(total / limit))
  const paginatedAlerts = useMemo(() => {
    const start = (page - 1) * limit
    return filteredAlerts.slice(start, start + limit)
  }, [filteredAlerts, page, limit])

  const startRecord = total === 0 ? 0 : (page - 1) * limit + 1
  const endRecord = Math.min(page * limit, total)

  const handleJumpPage = (e: React.FormEvent) => {
    e.preventDefault()
    const target = parseInt(pageInput, 10)
    if (!isNaN(target) && target >= 1 && target <= totalPages) {
      setPage(target)
      setPageInput('')
    }
  }

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

  // Export to CSV
  const exportToCSV = () => {
    if (filteredAlerts.length === 0) return
    const headers = ['Timestamp_BKK', 'Alert ID', 'Source IP', 'Target URL', 'Status', 'Message', 'Severity', 'Rule ID']
    const csvRows = [
      headers.join(','),
      ...filteredAlerts.map((a) => [
        `"${formatBkkDateTime(a.timestamp)}"`,
        `"${formatAlertId(a.alert_id)}"`,
        `"${a.ip || ''}"`,
        `"${(a.url || '').replace(/"/g, '""')}"`,
        `"${a.status || ''}"`,
        `"${(a.message || '').replace(/"/g, '""')}"`,
        `"${alertSeverity(a.severity) ?? ''}"`,
        `"${a.rule_id || ''}"`,
      ].join(',')),
    ]
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const a = document.createElement('a')
    a.href = window.URL.createObjectURL(blob)
    a.download = `waf_alert_incidents_${bkkDateKey()}.csv`
    a.click()
    toast.success('Downloaded incident alerts CSV')
  }

  const getSeverityBadge = (severity?: string | null) => {
    const s = alertSeverity(severity)
    if (s === 'CRITICAL') return <Badge color="danger">Critical</Badge>
    if (s === 'HIGH') return <Badge color="warning">High</Badge>
    if (s === 'MEDIUM') return <Badge color="info">Medium</Badge>
    if (s === 'LOW') return <Badge color="gray">Low</Badge>
    return <Badge color="gray">Not recorded</Badge>
  }

  const isAnyFilterActive = Boolean(
    search || severityFilter !== 'ALL' || statusFilter !== 'ALL' || dateFrom || dateTo || datePreset !== 'all'
  )

  return (
    <div className="animate-fade-in pb-12">
      {/* Top Header Bar */}
      <TopBar
        title="Alerts"
        subtitle={`Requests the WAF flagged on your sites, grouped into attack incidents. Times are ${BKK_LABEL}.`}
        action={
          <div className="flex items-center gap-2">
            <Link
              to="/notifications"
              className="inline-flex items-center gap-1.5 h-9 px-3 rounded-md border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[12.5px] font-medium text-[var(--text-primary)]"
            >
              <Send size={13} aria-hidden="true" />
              {status?.connected ? 'Telegram connected' : 'Set up Telegram'}
            </Link>
            <Button
              variant="secondary"
              onClick={() => refetchAlerts()}
              disabled={isAlertsFetching}
              icon={<RefreshCw size={13} className={isAlertsFetching ? 'animate-spin motion-reduce:animate-none' : ''} />}
            >
              Refresh
            </Button>
            <Button
              variant="secondary"
              onClick={exportToCSV}
              disabled={filteredAlerts.length === 0}
              icon={<Download size={13} />}
            >
              Export CSV
            </Button>
          </div>
        }
      />

      {linkedAlertId && linkMissing && (
        <div role="status" className="mb-4 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-4 py-3 text-[12.5px] text-[var(--text-secondary)]">
          The linked alert is not among the latest {ALERTS_FETCH_LIMIT} alerts visible to your account. Search its IP below, or open{' '}
          <Link to="/logs" className="text-[var(--accent)] hover:underline">Traffic logs</Link>.
        </div>
      )}

      <IncidentList />

      {/* 3 Metric Cards Strip (Balanced & Scannable) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5 mt-3.5">
        <div className="dash-card p-4 sm:p-4.5 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-[var(--text-muted)] block font-mono mb-1">
              Alerts listed
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-[24px] font-bold font-mono text-[var(--text-primary)] leading-none">
                {alertMetrics.total}{alertMetrics.totalIsLowerBound ? '+' : ''}
              </span>
              <span className="text-[11px] text-[var(--text-muted)]">
                {alertMetrics.totalIsLowerBound ? `latest ${ALERTS_FETCH_LIMIT} loaded` : 'one per flagged request'}
              </span>
            </div>
          </div>
          <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-orange-500/10">
            <Bell size={16} className="text-orange-600 dark:text-orange-400" />
          </div>
        </div>

        <div className="dash-card p-4 sm:p-4.5 flex items-center justify-between bg-red-50/40 dark:bg-red-950/[0.08] border-red-200/60 dark:border-red-500/15">
          <div>
            <span className="text-[11px] font-bold text-red-600/80 dark:text-red-400/80 block font-mono mb-1">
              Critical severity
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-[24px] font-bold font-mono text-red-600 dark:text-red-400 leading-none">
                {alertMetrics.critical}
              </span>
              <span className="text-[11px] text-red-700/80 dark:text-red-400/80">of the alerts listed</span>
            </div>
          </div>
          <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-red-500/10">
            <ShieldAlert size={16} className="text-red-600 dark:text-red-400" />
          </div>
        </div>

        <div className="dash-card p-4 sm:p-4.5 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold text-[var(--text-muted)] block font-mono mb-1">
              Attack incidents
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-[24px] font-bold font-mono text-sky-600 dark:text-sky-400 leading-none">
                {incidents.length}
              </span>
              <span className="text-[11px] font-mono text-[var(--text-muted)]">Latest, Telegram sent per incident</span>
            </div>
          </div>
          <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-sky-500/10">
            <Send size={16} className="text-sky-600 dark:text-sky-400" />
          </div>
        </div>
      </div>

      {/* ═══ Section 2: Alert Records Table & Filters ═══ */}
      <div className="dash-card overflow-hidden mt-7">
        {/* Advanced Filter Toolbar */}
        <div className="p-3.5 border-b border-[var(--bg-border)] bg-[var(--bg-surface)] space-y-3">
          {/* Top Filter Row */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2.5 flex-1">
              {/* Search Box */}
              <div className="relative flex-1 min-w-[220px] max-w-sm">
                <Search className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={14} />
                <input
                  type="text"
                  placeholder="Search Alert ID, IP, URI path, message..."
                  className="w-full dash-input pl-8 pr-7 py-1.5 text-[12px] font-mono"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                />
                {search && (
                  <button
                    onClick={() => {
                      setSearch('')
                      setPage(1)
                    }}
                    className="absolute right-2.5 top-2 text-[var(--text-muted)] hover:text-[var(--text-primary)] p-0.5 cursor-pointer"
                  >
                    <X size={13} />
                  </button>
                )}
              </div>

              {/* Severity Filter */}
              <select
                className="dash-input py-1.5 text-[11.5px] font-mono cursor-pointer"
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
                <option value="NONE">Not recorded</option>
              </select>

              {/* Status Filter */}
              <select
                className="dash-input py-1.5 text-[11.5px] font-mono cursor-pointer"
                value={statusFilter}
                onChange={(e) => {
                  setStatusFilter(e.target.value)
                  setPage(1)
                }}
              >
                <option value="ALL">All Alert Status</option>
                <option value="DISPATCHED">Dispatched (Telegram)</option>
                <option value="BLOCKED">403 (Blocked)</option>
              </select>
            </div>

            {/* Total Records Counter */}
            <div className="text-[11.5px] font-mono text-[var(--text-muted)]">
              Showing{' '}
              <span className="text-[var(--text-primary)] font-semibold">{startRecord}</span> to{' '}
              <span className="text-[var(--text-primary)] font-semibold">{endRecord}</span> of{' '}
              <span className="text-orange-600 dark:text-orange-400 font-semibold">{total}</span> incidents
            </div>
          </div>

          {/* Date / Time Filter Row */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2.5 border-t border-[var(--bg-border-subtle)] text-[12px]">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-1.5 text-[var(--text-muted)] font-mono text-[11px]">
                <Calendar size={12} className="text-orange-600 dark:text-orange-400" />
                <span>Date Presets:</span>
              </div>

              {/* Quick Date Presets */}
              <div className="flex items-center gap-1 bg-[var(--bg-primary)] p-0.5 rounded-md border border-[var(--bg-border)]">
                <button
                  type="button"
                  onClick={() => handleDatePreset('all')}
                  className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === 'all' && !dateFrom && !dateTo
                      ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-sm font-bold'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  All Time
                </button>
                <button
                  type="button"
                  onClick={() => handleDatePreset('today')}
                  className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === 'today'
                      ? 'bg-[var(--bg-surface)] text-orange-600 dark:text-orange-400 shadow-sm font-bold'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Today
                </button>
                <button
                  type="button"
                  onClick={() => handleDatePreset('7d')}
                  className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === '7d'
                      ? 'bg-[var(--bg-surface)] text-orange-600 dark:text-orange-400 shadow-sm font-bold'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Last 7 Days
                </button>
                <button
                  type="button"
                  onClick={() => handleDatePreset('30d')}
                  className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === '30d'
                      ? 'bg-[var(--bg-surface)] text-orange-600 dark:text-orange-400 shadow-sm font-bold'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Last 30 Days
                </button>
              </div>

              {/* Custom Date Pickers */}
              <div className="flex items-center gap-1.5 font-mono text-[11px]">
                <span className="text-[var(--text-muted)]">From:</span>
                <input
                  type="date"
                  className="dash-input py-0.5 px-2 text-[11px] font-mono cursor-pointer"
                  value={dateFrom}
                  onChange={(e) => {
                    setDateFrom(e.target.value)
                    setDatePreset('all')
                    setPage(1)
                  }}
                />
                <span className="text-[var(--text-muted)]">To:</span>
                <input
                  type="date"
                  className="dash-input py-0.5 px-2 text-[11px] font-mono cursor-pointer"
                  value={dateTo}
                  onChange={(e) => {
                    setDateTo(e.target.value)
                    setDatePreset('all')
                    setPage(1)
                  }}
                />
              </div>

              {isAnyFilterActive && (
                <button
                  type="button"
                  onClick={() => {
                    setSearch('')
                    setSeverityFilter('ALL')
                    setStatusFilter('ALL')
                    setDateFrom('')
                    setDateTo('')
                    setDatePreset('all')
                    setPage(1)
                  }}
                  className="px-2 py-0.5 text-[11px] font-mono text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 bg-red-50 hover:bg-red-100 dark:bg-red-500/10 rounded border border-red-200 dark:border-red-500/20 transition-colors cursor-pointer flex items-center gap-1"
                >
                  <X size={11} />
                  <span>Reset Filters</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Incident Alerts Table with Vertical Column Dividers */}
        <div className="overflow-x-auto">
          <table className="dash-table border-collapse w-full">
            <thead>
              <tr className="border-b border-[var(--bg-border)]">
                <th className="w-44 border-r border-[var(--bg-border)]">Time ({BKK_LABEL})</th>
                <th className="w-36 border-r border-[var(--bg-border)]">Source IP</th>
                <th className="w-28 border-r border-[var(--bg-border)]">Severity</th>
                <th className="border-r border-[var(--bg-border)]">Detection reason</th>
                <th className="hidden lg:table-cell border-r border-[var(--bg-border)]">Target URI</th>
                <th className="hidden xl:table-cell w-28 border-r border-[var(--bg-border)]">Alert ID</th>
                <th className="hidden xl:table-cell w-36 border-r border-[var(--bg-border)]">Telegram</th>
                <th className="text-right w-20"><span className="sr-only">Details</span></th>
              </tr>
            </thead>
            <tbody>
              {isAlertsLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)] text-[12px] font-mono">
                    <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                    Fetching incident alert history...
                  </td>
                </tr>
              ) : paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-14 text-center">
                    <div className="space-y-3">
                      <ShieldCheck size={32} className="mx-auto text-emerald-500 opacity-60" />
                      <p className="text-[13.5px] font-bold font-mono text-[var(--text-primary)] m-0">
                        No security incident alerts match the specified filters
                      </p>
                      <p className="text-[12px] text-[var(--text-muted)] font-mono m-0 max-w-sm mx-auto">
                        {isAnyFilterActive
                          ? 'Try resetting the search filters or adjusting the date range.'
                          : 'WAF has recorded no critical incident alerts in this window.'}
                      </p>
                    </div>
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map((alert: WafAlert, idx: number) => {
                  const alertId = formatAlertId(alert.alert_id, (page - 1) * limit + idx + 1)
                  const isCritical = alertSeverity(alert.severity) === 'CRITICAL'
                  // formatAlertId strips the trailing IP suffix for display,
                  // so two alerts from different attacking IPs in the same
                  // second (plausible in a distributed attack) can format
                  // to the same string -- use the raw, un-stripped ID for
                  // the React key so rows don't get misreconciled.
                  const rowKey = alert.alert_id || alertId

                  return (
                    <tr
                      key={rowKey}
                      className={`cursor-pointer transition-colors border-b border-[var(--bg-border-subtle)] ${
                        isCritical
                          ? 'bg-red-50/40 dark:bg-red-950/[0.08] hover:bg-red-50/80 dark:hover:bg-red-950/[0.15]'
                          : 'hover:bg-[var(--bg-hover)]'
                      }`}
                      onClick={() => setSelectedAlert(alert)}
                    >
                      {/* Timestamp (Bangkok) */}
                      <td className="font-mono text-[11px] text-[var(--text-muted)] whitespace-nowrap border-r border-[var(--bg-border-subtle)]">
                        {formatBkkDateTime(alert.timestamp)}
                      </td>

                      {/* Source IP */}
                      <td className="border-r border-[var(--bg-border-subtle)]">
                        <span className="font-mono font-semibold text-[12px] text-[var(--text-primary)]">
                          {alert.ip}
                        </span>
                      </td>

                      {/* Severity */}
                      <td className="border-r border-[var(--bg-border-subtle)]">
                        {getSeverityBadge(alert.severity)}
                      </td>

                      {/* Message / Reason (the rule id stays visible) */}
                      <td className="text-[12.5px] text-[var(--text-secondary)] max-w-[300px] border-r border-[var(--bg-border-subtle)]" title={alert.message}>
                        <span className="block truncate">{alert.message || '—'}</span>
                        {alert.rule_id && (
                          <span className="block font-mono text-[11px] text-[var(--text-muted)]">Rule {alert.rule_id}</span>
                        )}
                      </td>

                      {/* Target URI */}
                      <td className="hidden lg:table-cell font-mono text-[11.5px] max-w-[260px] truncate text-[var(--text-primary)] border-r border-[var(--bg-border-subtle)]" title={alert.url}>
                        {alert.url || '/'}
                      </td>

                      {/* Alert ID */}
                      <td className="hidden xl:table-cell border-r border-[var(--bg-border-subtle)]">
                        <span className="font-mono text-[11px] text-[var(--text-muted)] truncate block max-w-[110px]" title={alertId}>
                          {alertId}
                        </span>
                      </td>

                      {/* Dispatch Status -- fallback matches alertMetrics'
                          own `dispatched` KPI, which never counts an empty
                          status as dispatched; showing the literal text
                          "DISPATCHED" here for the same empty status
                          contradicted that count. */}
                      <td className="hidden xl:table-cell border-r border-[var(--bg-border-subtle)]">
                        {(() => {
                          const d = getDispatchLabel(alert)
                          const tone =
                            d.state === 'sent'
                              ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'
                              : d.state === 'failed'
                                ? 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20'
                                : 'bg-[var(--bg-surface-elevated)] text-[var(--text-muted)] border-[var(--bg-border)]'
                          return (
                            <span
                              title={alert.status ? `WAF response: HTTP ${alert.status}` : undefined}
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10.5px] font-mono font-semibold border ${tone}`}
                            >
                              <Send size={10} />
                              <span>{d.label}</span>
                            </span>
                          )
                        })()}
                      </td>

                      {/* Inspect Button */}
                      <td className="text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedAlert(alert)
                          }}
                          aria-label={`Details of the alert from ${alert.ip}`}
                          className="px-2 py-1 text-[12px] font-medium rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--bg-border-hover)] transition-colors cursor-pointer"
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

        {/* Pagination Bar */}
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
            {isAlertsFetching && <span className="ml-1 text-orange-500 text-[11px] animate-pulse">Syncing...</span>}
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
                      : 'bg-[var(--bg-surface)] border-[var(--bg-border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
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

      {/* ═══ Alert Detail Inspector ═══ */}
      <Drawer
        open={!!selectedAlert}
        onClose={closeAlert}
        size="lg"
        title={
          <span className="inline-flex items-center gap-2">
            <ShieldAlert size={16} className="text-red-600 dark:text-red-400 shrink-0" aria-hidden="true" />
            <span>Alert details</span>
          </span>
        }
      >
        {selectedAlert && (
          <div className="space-y-4 text-[12.5px]">
              {/* Next steps from this alert. Blocking happens on the origin's
                  IP access tab, which checks the role and asks to confirm;
                  nothing changes from this drawer. */}
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  size="md"
                  onClick={() => navigate(logsSearchPath(selectedAlert.ip))}
                  icon={<Search size={13} />}
                >
                  View this IP in traffic logs
                </Button>
                {selectedAlert.origin_id && isBlockableIp(selectedAlert.ip) ? (
                  <Button
                    variant="danger"
                    size="md"
                    onClick={() =>
                      navigate(originTabPath(selectedAlert.origin_id!, 'ip-access', { ip: selectedAlert.ip, note: `Alert ${formatAlertId(selectedAlert.alert_id)}` }))
                    }
                    icon={<Shield size={13} />}
                  >
                    Block this IP on the origin
                  </Button>
                ) : (
                  <span className="self-center text-[12px] text-[var(--text-muted)]">
                    This alert is not linked to one of your origins, so it cannot be blocked from here.
                  </span>
                )}
              </div>
              <div className="grid grid-cols-1 gap-3">
                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] flex items-center justify-between">
                  <div>
                    <span className="text-[10.5px] font-bold text-[var(--text-muted)] block mb-1">
                      Alert ID
                    </span>
                    <span className="text-orange-600 dark:text-orange-400 font-mono font-bold">
                      {formatAlertId(selectedAlert.alert_id)}
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopy(formatAlertId(selectedAlert.alert_id), 'Alert ID')}
                    className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] rounded cursor-pointer"
                    title="Copy Alert ID" aria-label="Copy Alert ID"
                  >
                    {copiedText === formatAlertId(selectedAlert.alert_id) ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                  </button>
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] font-bold text-[var(--text-muted)] block mb-1">
                    Event Timestamp ({BKK_LABEL})
                  </span>
                  <span className="text-[var(--text-primary)] font-bold">
                    {formatBkkDateTime(selectedAlert.timestamp)}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] flex items-center justify-between">
                  <div>
                    <span className="text-[10.5px] font-bold text-[var(--text-muted)] block mb-1">
                      Attacking Client IP
                    </span>
                    <span className="text-[var(--text-primary)] font-bold">{selectedAlert.ip}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(selectedAlert.ip, 'IP Address')}
                    className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] rounded cursor-pointer"
                    title="Copy IP" aria-label="Copy IP address"
                  >
                    {copiedText === selectedAlert.ip ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10.5px] font-bold text-[var(--text-muted)]">
                    Target Request URI
                  </span>
                  <button
                    onClick={() => handleCopy(selectedAlert.url, 'Target URI')}
                    className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] rounded cursor-pointer"
                    title="Copy URI" aria-label="Copy target request URI"
                  >
                    {copiedText === selectedAlert.url ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                  </button>
                </div>
                <span className="text-orange-600 dark:text-orange-400 break-all font-bold">{selectedAlert.url || '/'}</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] font-bold text-[var(--text-muted)] block mb-1">
                    Threat Severity Level
                  </span>
                  {getSeverityBadge(selectedAlert.severity)}
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[12px] font-medium text-[var(--text-muted)] block mb-1">
                    Telegram delivery
                  </span>
                  {/* Same label as the table: the backend does not record
                      whether this alert was sent, so the bot being connected
                      says nothing about this particular alert. */}
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[12px] font-medium bg-[var(--bg-surface-elevated)] text-[var(--text-secondary)] border border-[var(--bg-border)]">
                    <Send size={11} aria-hidden="true" />
                    <span>{getDispatchLabel(selectedAlert).label}</span>
                  </span>
                  <span className="block mt-1 text-[11.5px] text-[var(--text-muted)]">
                    {status?.connected ? 'Your Telegram is connected; attacks are sent once per incident.' : 'Telegram is not connected.'}
                  </span>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-red-50 dark:bg-red-500/[0.08] border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 space-y-1.5">
                <div className="flex items-center gap-1.5 font-bold text-[11px]">
                  <ShieldAlert size={14} />
                  <span>Detection & Alert Reason</span>
                </div>
                <p className="text-[12px] text-[var(--text-primary)] font-sans m-0 leading-relaxed">
                  {selectedAlert.message}
                </p>
                {selectedAlert.rule_id && (
                  <p className="text-[11px] text-[var(--text-muted)] font-mono m-0 mt-1">
                    Trigger Rule Reference: <span className="text-orange-600 dark:text-orange-400 font-bold">{selectedAlert.rule_id}</span>
                  </p>
                )}
              </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}

export default Alerts
