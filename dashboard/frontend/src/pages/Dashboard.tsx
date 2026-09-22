import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { systemApi } from '../api/system'
import { analyticsApi } from '../api/analytics'
import { aiSummaryApi } from '../api/aiSummary'
import { mlRulesApi } from '../api/mlRules'
import { useOriginFilterStore } from '../store/originFilterStore'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { selectNode } from '../lib/systemStatus'
import { useThemeStore } from '../store/themeStore'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'
import {
  ShieldAlert,
  Activity,
  Globe,
  RefreshCw,
  ShieldCheck,
  Zap,
  Server,
  Terminal,
  Sparkles,
  Copy,
  Check,
  Shield,
  Layers,
  X,
  AlertTriangle,
  Bell,
  FlaskConical,
  WifiOff,
} from 'lucide-react'
import toast from 'react-hot-toast'

export const Dashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'security' | 'infrastructure'>('security')
  const [chartView, setChartView] = useState<'area' | 'bar'>('area')
  const [copiedIp, setCopiedIp] = useState<string | null>(null)
  const { theme } = useThemeStore()
  const { selectedOrigin, selectedOriginLabel, setSelectedOrigin } = useOriginFilterStore()
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'

  const { data: logs = [], isLoading: isLogsLoading, isFetching: isLogsFetching, refetch: refetchLogs } = useQuery({
    queryKey: ['logs-dashboard', selectedOrigin],
    queryFn: () => logsApi.getRecentLogs(200, selectedOrigin),
    refetchInterval: 8000,
    enabled: activeTab === 'security',
  })

  const { data: analytics, isLoading: isAnalyticsLoading, isFetching: isAnalyticsFetching, refetch: refetchAnalytics } = useQuery({
    queryKey: ['analytics-summary', selectedOrigin],
    queryFn: () => analyticsApi.getSummary(selectedOrigin),
    refetchInterval: 8000,
    enabled: activeTab === 'security',
  })

  const { data: systemStatus, isFetching: isSystemFetching, refetch: refetchSystem } = useQuery({
    queryKey: ['system-status-dashboard'],
    queryFn: () => systemApi.getSystemStatus(),
    refetchInterval: 5000,
    // Always enabled (not just on the infrastructure tab): the "Needs
    // Attention" summary above the tabs needs node health regardless of
    // which tab is active.
  })

  // "Needs Attention" summary data -- real counts, no new backend
  // endpoints. unread_count already backs the notification bell/mark-all-
  // read feature (tenant-scoped since 09234bf); pending ML rule count is
  // admin-only since the review queue itself is admin-only (b414134).
  const { data: notificationFeed } = useQuery({
    queryKey: ['notifications-feed-dashboard'],
    queryFn: () => aiSummaryApi.getNotificationFeed(1),
    refetchInterval: 15000,
  })

  const { data: pendingMlRules } = useQuery({
    queryKey: ['ml-rules-pending-dashboard'],
    queryFn: () => mlRulesApi.listRules('pending'),
    refetchInterval: 15000,
    enabled: isAdmin,
  })

  // Edge/hub health for the infrastructure cards, from /api/system/status.
  // (These cards used to hardcode a permanent green 'ONLINE (Healthy)'.)
  const thNode = selectNode(systemStatus?.cdn_nodes as any, 'TH')
  const mainNode = selectNode(systemStatus?.cdn_nodes as any, 'MAIN')
  const nodeBadgeColor = (v: { online: boolean; statusLabel: string }) =>
    v.online ? 'success' : v.statusLabel === 'DEGRADED' ? 'warning'
    : v.statusLabel === 'OFFLINE' ? 'danger' : 'gray'

  const handleRefresh = () => {
    if (activeTab === 'security') {
      refetchLogs()
      refetchAnalytics()
      toast.success(`Refreshed telemetry for: ${selectedOriginLabel}`)
    } else {
      refetchSystem()
      toast.success('Infrastructure status refreshed')
    }
  }

  const handleCopyIp = (ip: string) => {
    navigator.clipboard.writeText(ip)
    setCopiedIp(ip)
    toast.success(`Copied IP ${ip} to clipboard`)
    setTimeout(() => setCopiedIp(null), 2000)
  }

  // Calculations
  const totalRequests = analytics?.total_requests ?? logs.length
  const blockedCount = analytics?.blocked_requests ?? logs.filter((l) => l.status === 403 || l.status === 429).length
  const uniqueIPs = analytics?.unique_ips ?? new Set(logs.map((l) => l.ip)).size
  const blockRate = totalRequests > 0 ? ((blockedCount / totalRequests) * 100).toFixed(1) : '0.0'

  // Time aggregated timeline. log.datetime is a ClickHouse-sourced,
  // offset-less string ("2026-09-22 06:14:00") -- treated as UTC and
  // rendered in Asia/Bangkok, matching formatThaiDateTime's convention in
  // Alerts.tsx/Logs.tsx. Previously read as raw browser-local time here,
  // so the same event plotted up to 7 hours off from where it shows on
  // those other pages.
  const chartData = logs
    .reduce((acc, log) => {
      const rawDt = String(log.datetime)
      const isoDt = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$/.test(rawDt)
        ? rawDt.replace(' ', 'T') + 'Z'
        : rawDt
      const time = new Date(isoDt).toLocaleTimeString('en-GB', {
        timeZone: 'Asia/Bangkok', hour: '2-digit', minute: '2-digit', second: '2-digit',
      })
      const existing = acc.find((d: any) => d.time === time)
      const isBlocked = log.status === 403
      const isLimited = log.status === 429
      const isAllowed = !isBlocked && !isLimited

      if (existing) {
        if (isBlocked) existing.blocked++
        else if (isLimited) existing.limited++
        else existing.allowed++
        existing.total++
      } else {
        acc.push({
          time,
          allowed: isAllowed ? 1 : 0,
          blocked: isBlocked ? 1 : 0,
          limited: isLimited ? 1 : 0,
          total: 1,
        })
      }
      return acc
    }, [] as any[])
    .slice(-20)

  const isDark = theme === 'dark'
  const gridColor = isDark ? '#1a2436' : '#e2e8f0'
  const axisColor = isDark ? '#64748b' : '#94a3b8'
  const isSyncing = isLogsFetching || isAnalyticsFetching || isSystemFetching

  return (
    <div className="animate-fade-in pb-8">
      {/* Top Header Bar */}
      <TopBar
        title="Security Operations Center"
        subtitle="Real-time WAF inspection, threat mitigation & traffic analytics"
        badge={
          <Badge color="success" dot pulse>
            WAF ENGINE ONLINE
          </Badge>
        }
        action={
          <div className="flex items-center gap-2">
            {/* View Switcher */}
            <div className="flex rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-0.5" role="tablist" aria-label="Dashboard perspective tabs">
              <button
                role="tab"
                aria-selected={activeTab === 'security'}
                aria-controls="security-panel"
                onClick={() => setActiveTab('security')}
                className={`px-3 py-1 text-[12px] font-semibold rounded-md transition-all font-mono cursor-pointer focus:outline-none focus:ring-1 focus:ring-orange-500 ${
                  activeTab === 'security'
                    ? 'bg-orange-500 text-white shadow-sm'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                Security Analytics
              </button>
              <button
                role="tab"
                aria-selected={activeTab === 'infrastructure'}
                aria-controls="infrastructure-panel"
                onClick={() => setActiveTab('infrastructure')}
                className={`px-3 py-1 text-[12px] font-semibold rounded-md transition-all font-mono cursor-pointer focus:outline-none focus:ring-1 focus:ring-orange-500 ${
                  activeTab === 'infrastructure'
                    ? 'bg-orange-500 text-white shadow-sm'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                Infrastructure & Nodes
              </button>
            </div>

            {/* Refresh Button */}
            <button
              onClick={handleRefresh}
              disabled={isSyncing}
              aria-label="Refresh telemetry data"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--bg-surface)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] text-[12px] font-mono font-medium text-[var(--text-primary)] rounded-md hover:bg-[var(--bg-hover)] shadow-sm transition-all cursor-pointer focus:outline-none focus:ring-1 focus:ring-orange-500"
              title="Refresh telemetry"
            >
              <RefreshCw size={13} className={isSyncing ? 'animate-spin text-orange-500' : 'text-[var(--text-muted)]'} />
              <span className="hidden sm:inline">Sync</span>
            </button>
          </div>
        }
      />

      {/* Origin Scope Filter Indicator Banner */}
      {selectedOrigin !== 'ALL' && activeTab === 'security' && (
        <div className="mb-5 p-3 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-between gap-3 text-indigo-300 font-mono text-[12px] animate-fade-in">
          <div className="flex items-center gap-2 truncate">
            <Shield size={16} className="text-indigo-400 shrink-0" />
            <span className="truncate">
              Currently Scoped to Origin:{' '}
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

      {/* ═══ Needs Attention -- Level 1 of the visual hierarchy: what to
          handle first, always visible regardless of which tab is active ═══ */}
      {(() => {
        const unreadCount = notificationFeed?.unread_count ?? 0
        const pendingRuleCount = pendingMlRules?.length ?? 0
        const offlineNodes = [thNode, mainNode].filter((n) => n && !n.online)
        const hasAttentionItems = unreadCount > 0 || pendingRuleCount > 0 || offlineNodes.length > 0

        if (!hasAttentionItems) {
          return (
            <div className="mb-5 p-3.5 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/[0.12] border border-emerald-200/60 dark:border-emerald-500/20 flex items-center gap-2.5 text-[12.5px] font-mono">
              <ShieldCheck size={16} className="text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span className="text-emerald-700 dark:text-emerald-400 font-semibold">Nothing needs attention right now</span>
              <span className="text-[var(--text-muted)]">-- no unread alerts, no pending rule reviews, all nodes online.</span>
            </div>
          )
        }

        return (
          <div className="mb-5 p-3.5 rounded-xl bg-amber-50/60 dark:bg-amber-950/[0.12] border border-amber-300/60 dark:border-amber-500/25">
            <div className="flex items-center gap-2 mb-2.5">
              <AlertTriangle size={15} className="text-amber-600 dark:text-amber-400" />
              <span className="text-[11px] font-bold uppercase tracking-wide text-amber-700 dark:text-amber-400 font-mono">
                Needs Attention
              </span>
            </div>
            <div className="flex flex-wrap gap-2.5">
              {unreadCount > 0 && (
                <Link
                  to="/alerts"
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-amber-300/50 dark:border-amber-500/20 text-[12px] font-mono hover:border-amber-400 dark:hover:border-amber-500/40 transition-colors"
                >
                  <Bell size={13} className="text-amber-600 dark:text-amber-400" />
                  <span className="font-semibold text-[var(--text-primary)]">{unreadCount}</span>
                  <span className="text-[var(--text-muted)]">unread alert{unreadCount === 1 ? '' : 's'}</span>
                </Link>
              )}
              {isAdmin && pendingRuleCount > 0 && (
                <Link
                  to="/ml-rules"
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-amber-300/50 dark:border-amber-500/20 text-[12px] font-mono hover:border-amber-400 dark:hover:border-amber-500/40 transition-colors"
                >
                  <FlaskConical size={13} className="text-amber-600 dark:text-amber-400" />
                  <span className="font-semibold text-[var(--text-primary)]">{pendingRuleCount}</span>
                  <span className="text-[var(--text-muted)]">rule{pendingRuleCount === 1 ? '' : 's'} awaiting review</span>
                </Link>
              )}
              {offlineNodes.length > 0 && (
                <button
                  type="button"
                  onClick={() => setActiveTab('infrastructure')}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-amber-300/50 dark:border-amber-500/20 text-[12px] font-mono hover:border-amber-400 dark:hover:border-amber-500/40 transition-colors cursor-pointer"
                >
                  <WifiOff size={13} className="text-amber-600 dark:text-amber-400" />
                  <span className="font-semibold text-[var(--text-primary)]">{offlineNodes.length}</span>
                  <span className="text-[var(--text-muted)]">node{offlineNodes.length === 1 ? '' : 's'} offline</span>
                </button>
              )}
            </div>
          </div>
        )
      })()}

      {activeTab === 'security' ? (
        <div id="security-panel" role="tabpanel" aria-label="Security Analytics Dashboard" className="animate-fade-in">

          {/* ═══ Section 1: KPI Summary Strip ═══ */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">

            {/* Primary KPI: Total Traffic */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[11px] font-semibold tracking-wide text-[var(--text-muted)] uppercase font-mono">
                  Inbound Traffic
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-sky-500/10">
                  <Activity size={15} className="text-sky-600 dark:text-sky-400" />
                </div>
              </div>
              <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-[var(--text-primary)]">
                {isAnalyticsLoading ? '—' : (analytics?.total_requests ?? totalRequests).toLocaleString()}
              </span>
              <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] flex items-center text-[11px]">
                <span className="text-[var(--text-muted)] font-mono">HTTP/S Analyzed</span>
              </div>
            </div>

            {/* Decision KPI: Threats Mitigated */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between bg-red-50/50 dark:bg-red-950/[0.08] border-red-200/60 dark:border-red-500/15">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[11px] font-semibold tracking-wide text-red-600/70 dark:text-red-400/70 uppercase font-mono">
                  Threats Mitigated
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-red-500/10">
                  <ShieldAlert size={15} className="text-red-600 dark:text-red-400" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-red-600 dark:text-red-400">
                  {isAnalyticsLoading ? '—' : (analytics?.blocked_requests ?? blockedCount).toLocaleString()}
                </span>
                <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-500/15 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 font-mono">
                  {blockRate}%
                </span>
              </div>
              <div className="mt-3 pt-2.5 border-t border-red-200/40 dark:border-red-500/10 flex items-center text-[11px]">
                <span className="text-red-600/60 dark:text-red-400/50 font-mono">CRS & Custom Rules</span>
              </div>
            </div>

            {/* Supporting: Unique IPs */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[11px] font-semibold tracking-wide text-[var(--text-muted)] uppercase font-mono">
                  Distinct Client IPs
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-amber-500/10">
                  <Globe size={15} className="text-amber-600 dark:text-amber-400" />
                </div>
              </div>
              <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-amber-600 dark:text-amber-400">
                {isLogsLoading ? '—' : uniqueIPs.toLocaleString()}
              </span>
              <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] flex items-center text-[11px]">
                <span className="text-[var(--text-muted)] font-mono">Unique Origin Addresses</span>
              </div>
            </div>

            {/* Supporting: Engine Latency. Was a hardcoded fake "100.0%
                Engine Health" with no data behind it at all -- replaced
                with the one real metric this card already had access to
                (average_latency_ms), which used to be relegated to a
                secondary badge with a fake "14ms" fallback. */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[11px] font-semibold tracking-wide text-[var(--text-muted)] uppercase font-mono">
                  Avg Response Time
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-emerald-500/10">
                  <ShieldCheck size={15} className="text-emerald-600 dark:text-emerald-400" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-emerald-600 dark:text-emerald-400">
                  {isAnalyticsLoading ? '—' : analytics?.average_latency_ms != null ? `${analytics.average_latency_ms}ms` : '—'}
                </span>
              </div>
              <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] flex items-center text-[11px]">
                <span className="text-[var(--text-muted)] font-mono">ModSecurity v3 + CRS 3.3.10</span>
              </div>
            </div>
          </div>

          {/* AI Threat Summary Banner */}
          {analytics?.ai_summary && (
            <div className="mt-4 p-4 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)] flex items-start gap-3 text-[12.5px] font-mono shadow-sm">
              <Sparkles size={18} className="text-orange-500 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-bold text-[var(--text-primary)]">AI Traffic & Threat Summary</span>
                <p className="text-[var(--text-secondary)] m-0 leading-relaxed">{analytics.ai_summary}</p>
              </div>
            </div>
          )}

          {/* ═══ Section 2: Analysis Zone ═══ */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mt-7">

            {/* Traffic & Threat Timeline Chart */}
            <div className="lg:col-span-2 dash-card overflow-hidden flex flex-col">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <Activity size={15} className="text-orange-600 dark:text-orange-400" />
                  <h3>Traffic & Threat Timeline</h3>
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex rounded border border-[var(--bg-border)] bg-[var(--bg-primary)] p-0.5 text-[11px] font-mono" role="group" aria-label="Chart render type">
                    <button
                      type="button"
                      aria-pressed={chartView === 'area'}
                      aria-label="Area chart view"
                      onClick={() => setChartView('area')}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        chartView === 'area' ? 'bg-orange-500 text-white font-semibold' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                      }`}
                    >
                      Area
                    </button>
                    <button
                      type="button"
                      aria-pressed={chartView === 'bar'}
                      aria-label="Bar chart view"
                      onClick={() => setChartView('bar')}
                      className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
                        chartView === 'bar' ? 'bg-orange-500 text-white font-semibold' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                      }`}
                    >
                      Bar
                    </button>
                  </div>
                  <Badge color="gray" size="sm">
                    LIVE 8s
                  </Badge>
                </div>
              </div>

              <div
                className="p-4 sm:p-5 flex-1 flex flex-col"
                role="region"
                aria-label="Traffic and Threat Telemetry Timeline Chart"
              >
                <div className="h-[280px] w-full flex-1">
                  <ResponsiveContainer width="100%" height="100%">
                    {chartView === 'area' ? (
                      <AreaChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                        <defs>
                          <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={isDark ? '#38bdf8' : '#0284c7'} stopOpacity={0.35} />
                            <stop offset="95%" stopColor={isDark ? '#38bdf8' : '#0284c7'} stopOpacity={0.0} />
                          </linearGradient>
                          <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="time" stroke={axisColor} fontSize={10} tickLine={false} tickMargin={8} />
                        <YAxis stroke={axisColor} fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: isDark ? '#101827' : '#ffffff',
                            borderColor: isDark ? '#2a374d' : '#e2e8f0',
                            borderRadius: '8px',
                            fontSize: '11px',
                            fontFamily: 'ui-monospace, monospace',
                            boxShadow: isDark
                              ? '0 10px 25px -5px rgba(0, 0, 0, 0.4)'
                              : '0 10px 25px -5px rgba(0, 0, 0, 0.1)',
                            color: isDark ? '#f1f5f9' : '#0f172a',
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="allowed"
                          stroke={isDark ? '#38bdf8' : '#0284c7'}
                          strokeWidth={2}
                          fillOpacity={1}
                          fill="url(#colorAllowed)"
                          name="Clean Traffic"
                        />
                        <Area
                          type="monotone"
                          dataKey="blocked"
                          stroke="#ef4444"
                          strokeWidth={2}
                          fillOpacity={1}
                          fill="url(#colorBlocked)"
                          name="WAF Mitigated"
                        />
                      </AreaChart>
                    ) : (
                      <BarChart data={chartData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                        <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="time" stroke={axisColor} fontSize={10} tickLine={false} tickMargin={8} />
                        <YAxis stroke={axisColor} fontSize={10} tickLine={false} axisLine={false} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: isDark ? '#101827' : '#ffffff',
                            borderColor: isDark ? '#2a374d' : '#e2e8f0',
                            borderRadius: '8px',
                            fontSize: '11px',
                            fontFamily: 'ui-monospace, monospace',
                            boxShadow: isDark
                              ? '0 10px 25px -5px rgba(0, 0, 0, 0.4)'
                              : '0 10px 25px -5px rgba(0, 0, 0, 0.1)',
                            color: isDark ? '#f1f5f9' : '#0f172a',
                          }}
                        />
                        <Bar
                          dataKey="allowed"
                          stackId="a"
                          fill={isDark ? '#1e3a5f' : '#bfdbfe'}
                          radius={[0, 0, 0, 0]}
                          maxBarSize={28}
                          name="Clean Traffic"
                        />
                        <Bar
                          dataKey="blocked"
                          stackId="a"
                          fill="#ef4444"
                          radius={[3, 3, 0, 0]}
                          maxBarSize={28}
                          name="WAF Mitigated"
                        />
                      </BarChart>
                    )}
                  </ResponsiveContainer>
                </div>
              </div>
            </div>

            {/* Attack Types Breakdown */}
            <div className="dash-card overflow-hidden flex flex-col">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <ShieldAlert size={15} className="text-red-500" />
                  <h3>Detected Threat Types</h3>
                </div>
                <span className="text-[10px] text-[var(--text-dim)] font-mono uppercase">By Severity</span>
              </div>

              <div className="p-4 flex-1 flex flex-col justify-center space-y-3 font-mono text-[12px]">
                {analytics?.attack_types && Object.keys(analytics.attack_types).length > 0 ? (
                  Object.entries(analytics.attack_types).map(([type, count]) => {
                    const totalAtks = Object.values(analytics.attack_types).reduce((a, b) => a + b, 0) || 1
                    const pct = Math.round((count / totalAtks) * 100)
                    return (
                      <div key={type} className="space-y-1">
                        <div className="flex justify-between items-center text-[11.5px]">
                          <span className="font-bold text-[var(--text-primary)] truncate max-w-[200px]" title={type}>
                            {type}
                          </span>
                          <span className="text-red-400 font-bold">{count.toLocaleString()} ({pct}%)</span>
                        </div>
                        <div className="w-full h-1.5 bg-[var(--bg-primary)] rounded-full overflow-hidden">
                          <div className="h-full bg-red-500 rounded-full transition-all" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    )
                  })
                ) : (
                  <div className="py-12 text-center text-[var(--text-muted)] text-[12px]">
                    No active threat violations detected for this origin.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ═══ Section 3: Threat Intelligence & Demographics ═══ */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mt-7">

            {/* Top Suspicious Attacker Sources */}
            <div className="dash-card overflow-hidden">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <Terminal size={14} className="text-orange-600 dark:text-orange-400" />
                  <h3>Top Suspicious Sources</h3>
                </div>
                <span className="text-[10px] text-[var(--text-dim)] font-mono uppercase">By Block Freq</span>
              </div>

              <div className="overflow-x-auto">
                <table className="dash-table">
                  <thead>
                    <tr>
                      <th>Client IP</th>
                      <th>Mitigated</th>
                      <th>Total</th>
                      <th className="text-right">Threat Ratio</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analytics?.suspicious_ips && analytics.suspicious_ips.length > 0 ? (
                      analytics.suspicious_ips.map((item, idx) => {
                        const totalItem = item.total || item.count || item.blocked || 1
                        const blockedItem = item.blocked || 0
                        const ratio = totalItem > 0 ? ((blockedItem / totalItem) * 100).toFixed(0) : '0'
                        const isHighRisk = Number(ratio) >= 50

                        return (
                          <tr key={item.ip || idx}>
                            <td>
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-[12px] text-[var(--text-primary)]">
                                  {item.ip}
                                </span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIp(item.ip)}
                                  className="text-[var(--text-muted)] hover:text-orange-500 transition-colors p-0.5 rounded cursor-pointer focus:outline-none focus:ring-1 focus:ring-orange-500"
                                  title={`Copy IP ${item.ip}`}
                                  aria-label={`Copy IP ${item.ip}`}
                                >
                                  {copiedIp === item.ip ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                                </button>
                              </div>
                            </td>
                            <td>
                              <span className="font-mono font-bold text-red-600 dark:text-red-400">{blockedItem}</span>
                            </td>
                            <td>
                              <span className="font-mono text-[var(--text-secondary)]">{totalItem}</span>
                            </td>
                            <td className="text-right">
                              <span
                                className={`inline-flex px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${
                                  isHighRisk
                                    ? 'bg-red-100 dark:bg-red-500/10 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-500/20'
                                    : 'bg-amber-100 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-200 dark:border-amber-500/20'
                                }`}
                              >
                                {ratio}% Blocked
                              </span>
                            </td>
                          </tr>
                        )
                      })
                    ) : (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-[var(--text-muted)] text-[12px] font-mono">
                          No suspicious source IPs recorded for this origin.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Geographic Distribution */}
            <div className="dash-card overflow-hidden">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <Globe size={14} className="text-sky-600 dark:text-sky-400" />
                  <h3>Geographic Distribution</h3>
                </div>
                <span className="text-[10px] text-[var(--text-dim)] font-mono uppercase">Global Inbound</span>
              </div>

              <div className="overflow-x-auto">
                <table className="dash-table">
                  <thead>
                    <tr>
                      <th>Origin Region</th>
                      <th>Requests</th>
                      <th>Mitigated</th>
                      <th className="text-right">Traffic Share</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analytics?.top_countries && analytics.top_countries.length > 0 ? (
                      analytics.top_countries.map((c, i) => {
                        const totalAll = analytics.total_requests || 1
                        const cTotal = c.total || c.count || 0
                        const cBlocked = c.blocked || 0
                        const share = ((cTotal / totalAll) * 100).toFixed(1)

                        return (
                          <tr key={c.country || i}>
                            <td>
                              <div className="flex items-center gap-2">
                                <span className="text-base leading-none">{c.flag || '🌐'}</span>
                                <span className="font-medium text-[12px] text-[var(--text-primary)]">
                                  {c.name || c.country}
                                </span>
                                <span className="text-[10px] font-mono text-[var(--text-dim)] uppercase">
                                  [{c.country}]
                                </span>
                              </div>
                            </td>
                            <td>
                              <span className="font-mono text-[var(--text-secondary)]">{cTotal.toLocaleString()}</span>
                            </td>
                            <td>
                              <span className={`font-mono font-semibold ${cBlocked > 0 ? 'text-red-600 dark:text-red-400' : 'text-[var(--text-muted)]'}`}>
                                {cBlocked}
                              </span>
                            </td>
                            <td className="text-right">
                              <div className="flex items-center justify-end gap-2">
                                <span className="font-mono text-[11px] text-[var(--text-secondary)]">{share}%</span>
                                <div className="w-12 h-1.5 bg-[var(--bg-primary)] rounded-full overflow-hidden hidden sm:block">
                                  <div
                                    className="h-full bg-sky-500 rounded-full transition-all"
                                    style={{ width: `${Math.min(Number(share), 100)}%` }}
                                  />
                                </div>
                              </div>
                            </td>
                          </tr>
                        )
                      })
                    ) : (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-[var(--text-muted)] text-[12px] font-mono">
                          No geographic telemetry available for this origin.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      ) : (
        /* ── Infrastructure Tab ── */
        <div id="infrastructure-panel" role="tabpanel" aria-label="Infrastructure and Nodes Dashboard" className="animate-fade-in">
          {/* Cluster Status Header */}
          <div className="flex flex-wrap justify-between items-center bg-[var(--bg-surface)] border border-[var(--bg-border)] p-4 rounded-lg gap-3">
            <div>
              <h2 className="text-[14px] font-bold text-[var(--text-primary)] m-0 font-mono flex items-center gap-2">
                <Server size={16} className="text-orange-600 dark:text-orange-400" />
                Edge POP Nodes & Service Mesh
              </h2>
              <p className="text-[11.5px] text-[var(--text-muted)] m-0 mt-1">
                ModSecurity Reverse Proxy, Caddy SSL Termination, and ClickHouse OLAP
              </p>
            </div>
            {/* Was hardcoded regardless of thNode/mainNode's real status --
                the exact bug class selectNode() (lib/systemStatus.ts) was
                written to eliminate on the individual node cards below,
                just missed on this summary badge. */}
            <Badge
              color={thNode.online && mainNode.online ? 'success' : 'danger'}
              dot
              pulse={thNode.online && mainNode.online}
            >
              {thNode.online && mainNode.online ? 'ALL SYSTEMS OPERATIONAL' : 'DEGRADED — CHECK NODE STATUS'}
            </Badge>
          </div>

          {/* Edge POP Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-5">
            <div className="dash-card p-4 flex flex-col justify-between">
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2.5">
                  <span className="text-2xl">🇹🇭</span>
                  <div>
                    <p className="font-bold text-[13px] text-[var(--text-primary)] m-0 font-mono">
                      Thailand Edge POP (Bangkok)
                    </p>
                    <p className="text-[10.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                      45.154.26.91 • Port 443 (HTTPS) / 80
                    </p>
                  </div>
                </div>
                <Badge color={nodeBadgeColor(thNode)} dot>
                  {thNode.statusLabel}
                </Badge>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-3 border-t border-[var(--bg-border-subtle)] text-[11px] font-mono">
                <div>
                  <span className="text-[var(--text-dim)] block text-[10px] uppercase">Latency</span>
                  <span className="font-bold text-emerald-400">{thNode.latencyLabel}</span>
                </div>
                <div>
                  <span className="text-[var(--text-dim)] block text-[10px] uppercase">WAF Engine</span>
                  <span className="font-bold text-emerald-400">CRS 3.3.10 Active</span>
                </div>
              </div>
            </div>

            <div className="dash-card p-4 flex flex-col justify-between">
              <div className="flex justify-between items-start mb-3">
                <div className="flex items-center gap-2.5">
                  <span className="text-2xl">🛡️</span>
                  <div>
                    <p className="font-bold text-[13px] text-[var(--text-primary)] m-0 font-mono">
                      Central WAF Core (Hub)
                    </p>
                    <p className="text-[10.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                      178.104.53.123 • Port 8000 / 7000 (FRP)
                    </p>
                  </div>
                </div>
                <Badge color={nodeBadgeColor(mainNode)} dot>
                  {mainNode.statusLabel}
                </Badge>
              </div>

              <div className="grid grid-cols-2 gap-2 pt-3 border-t border-[var(--bg-border-subtle)] text-[11px] font-mono">
                <div>
                  <span className="text-[var(--text-dim)] block text-[10px] uppercase">OLAP DB</span>
                  <span className="font-bold text-emerald-400">ClickHouse Connected</span>
                </div>
                <div>
                  <span className="text-[var(--text-dim)] block text-[10px] uppercase">Tunnel Hub</span>
                  <span className="font-bold text-emerald-400">FRP Core Active</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard
