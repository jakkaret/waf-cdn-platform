import React, { useEffect, useState, useMemo } from 'react'
import { createPortal } from 'react-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertsApi } from '../api/alerts'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
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
} from 'lucide-react'
import { WafAlert } from '../types'
import toast from 'react-hot-toast'

export const Alerts: React.FC = () => {
  const queryClient = useQueryClient()

  // Pairing code state
  const [code, setCode] = useState<string | null>(null)
  const [botUsername, setBotUsername] = useState<string>('WAF_Project_Bot')
  const [copiedCode, setCopiedCode] = useState(false)

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

  // Fetch Telegram Connection Status
  const { data: status, isLoading: isStatusLoading } = useQuery({
    queryKey: ['telegram-status'],
    queryFn: alertsApi.getConnectionStatus,
    refetchInterval: code ? 3000 : false,
  })

  // Fetch Alerts History
  const { data: rawAlerts = [], isLoading: isAlertsLoading, isFetching: isAlertsFetching, refetch: refetchAlerts } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => alertsApi.getAlerts(200),
    refetchInterval: 8000,
  })

  // Connect Mutation
  const connectMutation = useMutation({
    mutationFn: alertsApi.startConnection,
    onSuccess: (data) => {
      setCode(data.code)
      if (data.bot_username) {
        setBotUsername(data.bot_username)
      }
      toast.success('Connection token generated! Send code to the Telegram bot.')
    },
    onError: () => toast.error('Failed to initiate Telegram connection'),
  })

  // Disconnect Mutation
  const disconnectMutation = useMutation({
    mutationFn: alertsApi.disconnect,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
      toast.success('Disconnected from Telegram Alert Bot')
    },
  })

  // Poll connection code
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>
    if (code) {
      interval = setInterval(async () => {
        try {
          const res = await alertsApi.pollConnection(code)
          if (res.status === 'connected') {
            setCode(null)
            queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
            toast.success('Telegram Bot Connected Successfully!')
          } else if (res.status === 'expired') {
            setCode(null)
            toast.error('Verification code expired')
          }
        } catch (e) {
          // ignore
        }
      }, 3000)
    }
    return () => clearInterval(interval)
  }, [code, queryClient])

  const handleCopyCode = () => {
    if (!code) return
    navigator.clipboard.writeText(code)
    setCopiedCode(true)
    toast.success('Copied verification code')
    setTimeout(() => setCopiedCode(false), 2000)
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
    const formatDate = (d: Date) => d.toISOString().split('T')[0]

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
        const matchId = (alert.alert_id || '').toLowerCase().includes(q)
        if (!matchIp && !matchUrl && !matchMsg && !matchRule && !matchId) {
          return false
        }
      }

      // 2. Severity filter
      if (severityFilter !== 'ALL') {
        const sev = (alert.severity || (alert.status === '403' ? 'CRITICAL' : 'HIGH')).toUpperCase()
        if (sev !== severityFilter) return false
      }

      // 3. Status filter
      if (statusFilter !== 'ALL') {
        const st = (alert.status || '').toUpperCase()
        if (statusFilter === 'DISPATCHED' && !st.includes('DISPATCH') && !st.includes('SENT') && !st.includes('200')) {
          return false
        }
        if (statusFilter === 'BLOCKED' && !st.includes('403') && !st.includes('BLOCK')) {
          return false
        }
      }

      // 4. Date From / Date To filter (วัน เดือน ปี)
      if (dateFrom || dateTo) {
        if (!alert.timestamp) return false
        const alertDate = new Date(alert.timestamp)
        if (isNaN(alertDate.getTime())) return true

        if (dateFrom) {
          const from = new Date(dateFrom)
          from.setHours(0, 0, 0, 0)
          if (alertDate < from) return false
        }
        if (dateTo) {
          const to = new Date(dateTo)
          to.setHours(23, 59, 59, 999)
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
    const headers = ['Timestamp', 'Alert ID', 'Source IP', 'Target URL', 'Status', 'Message', 'Severity', 'Rule ID']
    const csvRows = [
      headers.join(','),
      ...filteredAlerts.map((a) => [
        `"${a.timestamp}"`,
        `"${a.alert_id || ''}"`,
        `"${a.ip || ''}"`,
        `"${(a.url || '').replace(/"/g, '""')}"`,
        `"${a.status || ''}"`,
        `"${(a.message || '').replace(/"/g, '""')}"`,
        `"${a.severity || 'CRITICAL'}"`,
        `"${a.rule_id || '942100'}"`,
      ].join(',')),
    ]
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const a = document.createElement('a')
    a.href = window.URL.createObjectURL(blob)
    a.download = `waf_alert_incidents_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    toast.success('Downloaded incident alerts CSV')
  }

  const getSeverityBadge = (severity?: string | null) => {
    const s = (severity || 'CRITICAL').toUpperCase()
    if (s === 'CRITICAL') return <Badge color="danger">CRITICAL</Badge>
    if (s === 'HIGH') return <Badge color="warning">HIGH</Badge>
    if (s === 'MEDIUM') return <Badge color="info">MEDIUM</Badge>
    if (s === 'LOW') return <Badge color="success">LOW</Badge>
    return <Badge color="gray">{s}</Badge>
  }

  return (
    <div className="space-y-5 animate-fade-in">
      <TopBar
        title="Security Alert Center"
        subtitle="Real-time Telegram bot incident dispatch and critical attack notifications"
        badge={
          status?.connected ? (
            <Badge color="success" dot pulse>
              BOT CONNECTED
            </Badge>
          ) : (
            <Badge color="warning" dot>
              NOT CONNECTED
            </Badge>
          )
        }
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetchAlerts()}
              disabled={isAlertsFetching}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--bg-surface)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] text-[12px] font-mono font-medium text-[var(--text-primary)] rounded-md hover:bg-[var(--bg-hover)] transition-colors cursor-pointer"
            >
              <RefreshCw size={13} className={isAlertsFetching ? 'animate-spin text-orange-500' : 'text-[var(--text-muted)]'} />
              <span>Refresh</span>
            </button>
            <button
              onClick={exportToCSV}
              disabled={filteredAlerts.length === 0}
              className="flex items-center gap-1.5 bg-orange-500 hover:bg-orange-600 text-white px-3 py-1.5 text-[12px] font-mono font-semibold rounded-md disabled:opacity-40 shadow-sm transition-all cursor-pointer"
            >
              <Download size={13} />
              <span>Export CSV</span>
            </button>
          </div>
        }
      />

      {/* Telegram Bot Integration Card */}
      <div className="dash-card p-5 sm:p-6 border-l-2 border-l-[#229ed9] bg-gradient-to-r from-[#229ed9]/[0.05] via-transparent to-transparent">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className="w-11 h-11 rounded-xl bg-[#229ed9]/15 border border-[#229ed9]/30 flex items-center justify-center text-[#229ed9] shrink-0">
              <Send size={20} />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                  Telegram Incident Dispatch Bot
                </h3>
                <Badge color={status?.connected ? 'success' : 'warning'} size="sm">
                  {status?.connected ? 'ACTIVE DISPATCH' : 'DISCONNECTED'}
                </Badge>
              </div>
              <p className="text-[12.5px] text-[var(--text-secondary)] m-0 mt-1">
                Dispatches real-time alerts for SQL Injection, XSS, High Anomaly score spikes, and Perimeter IP blocks.
              </p>
              {status?.connected && (
                <p className="text-[11.5px] text-emerald-500 font-mono mt-1 mb-0 flex items-center gap-1.5">
                  <CheckCircle2 size={13} />
                  <span>Target Chat ID: {status.chat_id}</span>
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            {!status?.connected && !code && (
              <Button
                variant="brand"
                onClick={() => connectMutation.mutate()}
                isLoading={connectMutation.isPending}
                icon={<Send size={14} />}
              >
                Connect Telegram
              </Button>
            )}

            {status?.connected && (
              <Button
                variant="danger"
                onClick={() => disconnectMutation.mutate()}
                isLoading={disconnectMutation.isPending}
              >
                Disconnect
              </Button>
            )}
          </div>
        </div>

        {/* Verification Code Box */}
        {code && (
          <div className="mt-5 pt-4 border-t border-[var(--bg-border)] space-y-3 animate-fade-in">
            <p className="text-[12px] font-semibold text-[var(--text-primary)] m-0">
              Step 1: Copy this verification token and send it to your bot
            </p>

            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2 font-mono text-[18px] font-bold text-[#229ed9] bg-[#229ed9]/10 border border-[#229ed9]/30 px-4 py-1.5 rounded-lg">
                <span>{code}</span>
                <button
                  onClick={handleCopyCode}
                  className="p-1 text-[#229ed9] hover:text-white transition-colors cursor-pointer"
                  title="Copy code"
                >
                  {copiedCode ? <Check size={16} className="text-emerald-500" /> : <Copy size={16} />}
                </button>
              </div>

              <a
                href={`https://t.me/${botUsername}?start=${code}`}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#229ed9] hover:bg-[#1a8bbf] text-white rounded-md text-[12px] font-semibold transition-all shadow-sm"
              >
                <span>Open @{botUsername}</span>
                <ExternalLink size={13} />
              </a>

              <span className="text-[11.5px] text-[var(--text-muted)] font-mono flex items-center gap-1.5">
                <RefreshCw size={13} className="animate-spin text-[#229ed9]" />
                Waiting for Telegram handshake confirmation...
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Main Alert Records Card & Table (Matching Traffic Logs Layout) */}
      <div className="dash-card overflow-hidden">
        {/* Advanced Filter Toolbar */}
        <div className="p-3.5 border-b border-[var(--bg-border)] bg-[var(--bg-surface)] space-y-3">
          {/* Top Filter Row */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2.5 flex-1">
              {/* Search Box */}
              <div className="relative flex-1 min-w-[220px] max-w-sm">
                <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
                <input
                  type="text"
                  placeholder="Filter by Alert ID, IP, Path, or Message..."
                  className="w-full dash-input pl-8 py-1.5 text-[12px] font-mono"
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value)
                    setPage(1)
                  }}
                />
              </div>

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
              </select>

              {/* Status Filter */}
              <select
                className="dash-input py-1.5 text-[12px] font-mono cursor-pointer"
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
            <div className="flex items-center gap-3">
              <span className="text-[var(--text-secondary)] text-[12px] font-mono whitespace-nowrap">
                {total > 0 ? (
                  <>
                    <strong className="text-[var(--text-primary)]">{startRecord.toLocaleString()}</strong>–
                    <strong className="text-[var(--text-primary)]">{endRecord.toLocaleString()}</strong> of{' '}
                    <strong className="text-orange-500">{total.toLocaleString()}</strong> alert incidents
                  </>
                ) : (
                  '0 matching alert incidents'
                )}
              </span>
            </div>
          </div>

          {/* Date / Time Filter Row (วัน เดือน ปี) */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-2.5 border-t border-[var(--bg-border-subtle)] text-[12px]">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="flex items-center gap-1.5 text-[var(--text-muted)] font-mono text-[11.5px]">
                <Calendar size={13} className="text-orange-500" />
                <span>Date Filter (วัน/เดือน/ปี):</span>
              </div>

              {/* Quick Date Presets */}
              <div className="flex items-center gap-1 bg-[var(--bg-primary)] p-0.5 rounded-md border border-[var(--bg-border)]">
                <button
                  type="button"
                  onClick={() => handleDatePreset('all')}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === 'all' && !dateFrom && !dateTo
                      ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-sm'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  All Time
                </button>
                <button
                  type="button"
                  onClick={() => handleDatePreset('today')}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === 'today'
                      ? 'bg-[var(--bg-surface)] text-orange-500 shadow-sm'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Today
                </button>
                <button
                  type="button"
                  onClick={() => handleDatePreset('7d')}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === '7d'
                      ? 'bg-[var(--bg-surface)] text-orange-500 shadow-sm'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Last 7 Days
                </button>
                <button
                  type="button"
                  onClick={() => handleDatePreset('30d')}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                    datePreset === '30d'
                      ? 'bg-[var(--bg-surface)] text-orange-500 shadow-sm'
                      : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  Last 30 Days
                </button>
              </div>

              {/* Custom Date Pickers */}
              <div className="flex items-center gap-1.5 font-mono text-[11.5px]">
                <span className="text-[var(--text-muted)]">From:</span>
                <input
                  type="date"
                  className="dash-input py-1 px-2 text-[11.5px] font-mono cursor-pointer"
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
                  className="dash-input py-1 px-2 text-[11.5px] font-mono cursor-pointer"
                  value={dateTo}
                  onChange={(e) => {
                    setDateTo(e.target.value)
                    setDatePreset('all')
                    setPage(1)
                  }}
                />
              </div>

              {(search || severityFilter !== 'ALL' || statusFilter !== 'ALL' || dateFrom || dateTo) && (
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
                  className="px-2 py-1 text-[11px] font-mono text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded border border-red-500/20 transition-colors cursor-pointer flex items-center gap-1"
                >
                  <X size={11} />
                  <span>Clear Filters</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Incident Alerts Table (Matching Logs.tsx) */}
        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>Timestamp (UTC+7)</th>
                <th>Alert ID</th>
                <th>Source IP</th>
                <th>Target URI</th>
                <th>Detection Reason</th>
                <th>Severity</th>
                <th>Dispatch Status</th>
                <th className="text-right">Inspect</th>
              </tr>
            </thead>
            <tbody>
              {isAlertsLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)] text-[12.5px] font-mono">
                    <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                    Fetching incident alert history...
                  </td>
                </tr>
              ) : paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)] text-[12.5px] font-mono">
                    <ShieldCheck size={24} className="mx-auto mb-2 text-emerald-500 opacity-60" />
                    No security incident alerts match the specified query filters.
                  </td>
                </tr>
              ) : (
                paginatedAlerts.map((alert: WafAlert, idx: number) => {
                  const alertId = alert.alert_id || `#ALT-${(page - 1) * limit + idx + 1}`
                  const isThreat = String(alert.severity).toUpperCase() === 'CRITICAL' || String(alert.status).includes('403')

                  return (
                    <tr
                      key={alertId}
                      className={`cursor-pointer transition-colors ${
                        isThreat
                          ? 'bg-red-500/[0.04] hover:bg-red-500/[0.08]'
                          : 'hover:bg-[var(--bg-hover)]'
                      }`}
                      onClick={() => setSelectedAlert(alert)}
                    >
                      {/* Timestamp */}
                      <td className="font-mono text-[11px] text-[var(--text-muted)] whitespace-nowrap">
                        {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : '—'}
                      </td>

                      {/* Alert ID */}
                      <td>
                        <span className="font-mono font-bold text-[11px] text-orange-400">
                          {alertId}
                        </span>
                      </td>

                      {/* Source IP */}
                      <td>
                        <div className="flex items-center gap-1.5 font-mono font-bold text-[12px] text-[var(--text-primary)]">
                          <span>{alert.ip}</span>
                        </div>
                      </td>

                      {/* Target URI */}
                      <td className="font-mono text-[11.5px] max-w-[280px] truncate text-[var(--text-primary)]" title={alert.url}>
                        {alert.url || '/'}
                      </td>

                      {/* Message / Reason */}
                      <td className="text-[12px] text-[var(--text-secondary)] max-w-[320px] truncate" title={alert.message}>
                        {alert.message}
                      </td>

                      {/* Severity */}
                      <td>{getSeverityBadge(alert.severity)}</td>

                      {/* Dispatch Status */}
                      <td>
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                          <Send size={10} />
                          <span>{alert.status || 'DISPATCHED'}</span>
                        </span>
                      </td>

                      {/* Inspect Button */}
                      <td className="text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedAlert(alert)
                          }}
                          className="px-2 py-1 text-[11px] font-mono font-semibold rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[var(--text-secondary)] hover:text-orange-500 hover:border-orange-500/30 transition-colors cursor-pointer"
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

        {/* Pagination Bar (Matching Logs.tsx) */}
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

      {/* Alert Detail Inspector Modal (Mounted via Portal) */}
      {selectedAlert && typeof document !== 'undefined' && createPortal(
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setSelectedAlert(null)
          }}
        >
          <div
            className="dash-modal w-full max-w-2xl shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="dash-card-header bg-[var(--bg-surface-elevated)]">
              <div className="flex items-center gap-2.5">
                <ShieldAlert size={16} className="text-red-500" />
                <h3 className="font-mono text-[14px]">
                  Incident Alert Inspector & Payload Analysis
                </h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] font-mono text-base px-2 cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="p-5 space-y-4 max-h-[80vh] overflow-y-auto font-mono text-[12px]">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                    Event Timestamp
                  </span>
                  <span className="text-[var(--text-primary)]">
                    {selectedAlert.timestamp ? new Date(selectedAlert.timestamp).toLocaleString() : '—'}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] flex items-center justify-between">
                  <div>
                    <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                      Attacking Client IP
                    </span>
                    <span className="text-[var(--text-primary)] font-bold">{selectedAlert.ip}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(selectedAlert.ip, 'IP Address')}
                    className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] rounded cursor-pointer"
                    title="Copy IP"
                  >
                    {copiedText === selectedAlert.ip ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                  </button>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)]">
                    Target Request URI
                  </span>
                  <button
                    onClick={() => handleCopy(selectedAlert.url, 'Target URI')}
                    className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] rounded cursor-pointer"
                    title="Copy URI"
                  >
                    {copiedText === selectedAlert.url ? <Check size={14} className="text-emerald-500" /> : <Copy size={14} />}
                  </button>
                </div>
                <span className="text-orange-400 break-all">{selectedAlert.url || '/'}</span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                    Threat Severity Level
                  </span>
                  {getSeverityBadge(selectedAlert.severity)}
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]">
                  <span className="text-[10.5px] uppercase font-bold text-[var(--text-muted)] block mb-1">
                    Dispatch Channel
                  </span>
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    <Send size={10} />
                    <span>Telegram Bot Active</span>
                  </span>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-red-500/[0.08] border border-red-500/20 text-red-400 space-y-1.5">
                <div className="flex items-center gap-1.5 font-bold text-[11px] uppercase">
                  <ShieldAlert size={14} />
                  <span>Detection & Alert Reason</span>
                </div>
                <p className="text-[12px] text-[var(--text-primary)] font-sans m-0 leading-relaxed">
                  {selectedAlert.message}
                </p>
                {selectedAlert.rule_id && (
                  <p className="text-[11px] text-[var(--text-muted)] font-mono m-0 mt-1">
                    Trigger Rule Reference: <span className="text-orange-400">{selectedAlert.rule_id}</span>
                  </p>
                )}
              </div>

              <div className="flex justify-end gap-2.5 pt-3 border-t border-[var(--bg-border)]">
                <button
                  onClick={() => setSelectedAlert(null)}
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

export default Alerts
