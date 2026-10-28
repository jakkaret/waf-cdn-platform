import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { systemApi } from '../api/system'
import { analyticsApi } from '../api/analytics'
import { aiSummaryApi } from '../api/aiSummary'
import { mlRulesApi } from '../api/mlRules'
import { canReviewRule } from '../lib/mlRules'
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
  Legend,
} from 'recharts'
import { buildTimeline, bucketLabel } from '../lib/timeline'
import { BlockIpButton } from '../components/BlockIpButton'
import { logsSearchPath } from '../lib/alertActions'
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
import { CRS_VERSION } from '../lib/crsVersion'
import { BKK_LABEL, formatBkkDateTime, formatBkkTime } from '../lib/time'

// Full English country name for an ISO alpha-2 code, from the browser's own
// data (always complete and current) rather than a list we maintain. The API's
// `name` only covers a handful of countries now that the code comes from real
// GeoIP; falls back to the code itself if the runtime lacks Intl.DisplayNames.
const regionNames: Intl.DisplayNames | null = (() => {
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' })
  } catch {
    return null
  }
})()
const countryDisplayName = (code: string, fallback?: string): string => {
  try {
    return regionNames?.of(code.toUpperCase()) || fallback || code
  } catch {
    return fallback || code
  }
}

export const Dashboard: React.FC = () => {
  const [tab, setActiveTab] = useState<'security' | 'infrastructure'>('security')
  const [chartView, setChartView] = useState<'area' | 'bar'>('area')
  const [copiedIp, setCopiedIp] = useState<string | null>(null)
  const { theme } = useThemeStore()
  const { selectedOrigin, selectedOriginLabel, setSelectedOrigin } = useOriginFilterStore()
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const activeTab = isAdmin ? tab : 'security'

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
  // read feature (tenant-scoped since 09234bf). The pending ML rule queue is
  // filtered server-side to the caller's origins (admin: every rule); the
  // count below is the rules this user may approve or reject.
  const { data: notificationFeed } = useQuery({
    queryKey: ['notifications-feed-dashboard'],
    queryFn: () => aiSummaryApi.getNotificationFeed(1),
    refetchInterval: 15000,
  })

  const { data: pendingMlRules } = useQuery({
    queryKey: ['ml-rules-pending-dashboard'],
    queryFn: () => mlRulesApi.listRules('pending'),
    refetchInterval: 15000,
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

  // KPIs come from /analytics/summary only. They used to fall back to counts
  // over the 200 log rows below, which mixed two different populations into
  // one card; a missing summary now shows "—".
  const totalRequests = analytics?.total_requests ?? null
  const blockedCount = analytics?.blocked_requests ?? null
  const uniqueIPs = analytics?.unique_ips ?? null
  const blockRate =
    totalRequests && blockedCount !== null ? ((blockedCount / totalRequests) * 100).toFixed(1) : null
  const kpi = (v: number | null) => (isAnalyticsLoading || v === null ? '—' : v.toLocaleString())
  const attackTypeTotal = Object.values(analytics?.attack_types ?? {}).reduce((a, b) => a + b, 0)

  // Timeline of the latest log rows on a real time axis (lib/timeline.ts):
  // empty buckets are kept, so uneven gaps show as gaps. log.datetime is
  // UTC from ClickHouse and is shown in Bangkok time like everywhere else.
  const timeline = buildTimeline(logs)
  const chartData = timeline.buckets

  const isDark = theme === 'dark'
  const gridColor = isDark ? '#1a2436' : '#e2e8f0'
  const axisColor = isDark ? '#94a3b8' : '#64748b'
  const chartTooltipStyle = {
    backgroundColor: isDark ? '#101827' : '#ffffff',
    borderColor: isDark ? '#2a374d' : '#e2e8f0',
    borderRadius: '8px',
    fontSize: '12px',
    color: isDark ? '#f1f5f9' : '#0f172a',
  }
  const isSyncing = isLogsFetching || isAnalyticsFetching || isSystemFetching

  return (
    <div className="animate-fade-in pb-8">
      {/* Top Header Bar */}
      <TopBar
        scope
        title="Dashboard"
        subtitle="Traffic and threats across your sites"
        action={
          <div className="flex items-center gap-2">
            {/* View Switcher: the infrastructure view (node addresses,
                ports, internal services) is for the platform operator. */}
            {isAdmin && (
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
            )}

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
              <strong className="text-white font-bold">{selectedOriginLabel}</strong>
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
        // Viewers see an origin's pending rules but cannot act on them.
        const pendingRuleCount = (pendingMlRules ?? []).filter((r) => canReviewRule(r, isAdmin)).length
        // Until /system/status answers, selectNode() reports every node as
        // UNKNOWN/offline -- that is "not loaded yet", not an outage, so it
        // must not raise a false alarm on first paint.
        const statusLoaded = systemStatus !== undefined
        const offlineNodes = statusLoaded ? [thNode, mainNode].filter((n) => n && !n.online) : []
        if (!statusLoaded && notificationFeed === undefined) {
          return (
            <div className="mb-5 p-3.5 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)] flex items-center gap-2.5 text-[12.5px] font-mono text-[var(--text-muted)]">
              <RefreshCw size={14} className="animate-spin shrink-0" />
              <span>Checking system status...</span>
            </div>
          )
        }
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
              {pendingRuleCount > 0 && (
                <Link
                  to="/rule-proposals?type=ml"
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-amber-300/50 dark:border-amber-500/20 text-[12px] font-mono hover:border-amber-400 dark:hover:border-amber-500/40 transition-colors"
                >
                  <FlaskConical size={13} className="text-amber-600 dark:text-amber-400" />
                  <span className="font-semibold text-[var(--text-primary)]">{pendingRuleCount}</span>
                  <span className="text-[var(--text-muted)]">
                    ML rule{pendingRuleCount === 1 ? '' : 's'} awaiting {isAdmin ? 'review' : 'your review'}
                  </span>
                </Link>
              )}
              {offlineNodes.length > 0 && (
                isAdmin ? (
                  <button
                    type="button"
                    onClick={() => setActiveTab('infrastructure')}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-amber-300/50 dark:border-amber-500/20 text-[12px] hover:border-amber-400 dark:hover:border-amber-500/40 transition-colors cursor-pointer"
                  >
                    <WifiOff size={13} className="text-amber-600 dark:text-amber-400" />
                    <span className="font-semibold text-[var(--text-primary)]">{offlineNodes.length}</span>
                    <span className="text-[var(--text-muted)]">node{offlineNodes.length === 1 ? '' : 's'} offline</span>
                  </button>
                ) : (
                  <span className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--bg-surface)] border border-amber-300/50 dark:border-amber-500/20 text-[12px]">
                    <WifiOff size={13} className="text-amber-600 dark:text-amber-400" />
                    <span className="text-[var(--text-secondary)]">Part of the platform is degraded right now, so some requests may be slow or fail.</span>
                  </span>
                )
              )}
            </div>
          </div>
        )
      })()}

      {activeTab === 'security' ? (
        <div id="security-panel" role="tabpanel" aria-label="Security Analytics Dashboard" className="animate-fade-in">

          {/* ═══ Section 1: KPI Summary Strip ═══ */}
          {/* /analytics/summary queries access_logs with no time filter, so
              the cards cover every request still stored, not a recent window. */}
          <div className="flex flex-wrap items-baseline justify-between gap-2 mb-2.5">
            <h2 className="m-0 text-[14px] font-semibold text-[var(--text-primary)]">
              {selectedOrigin === 'ALL' ? (isAdmin ? 'All platform traffic' : 'All your origins') : selectedOriginLabel}
            </h2>
            <span className="text-[12px] text-[var(--text-muted)]">
              All stored traffic, no time limit{analytics?.source === 'offline' ? ' (log store offline, figures unavailable)' : ''}
            </span>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">

            {/* Primary KPI: Total Traffic */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[12.5px] font-medium text-[var(--text-secondary)]">
                  Requests
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-sky-500/10">
                  <Activity size={15} className="text-sky-600 dark:text-sky-400" />
                </div>
              </div>
              <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-[var(--text-primary)]">
                {kpi(totalRequests)}
              </span>
              <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] flex items-center text-[11.5px]">
                <span className="text-[var(--text-muted)]">Requests inspected</span>
              </div>
            </div>

            {/* Decision KPI: Threats Mitigated */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between bg-red-50/50 dark:bg-red-950/[0.08] border-red-200/60 dark:border-red-500/15">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[12.5px] font-medium text-red-800 dark:text-red-300">
                  Blocked or flagged
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-red-500/10">
                  <ShieldAlert size={15} className="text-red-600 dark:text-red-400" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-red-600 dark:text-red-400">
                  {kpi(blockedCount)}
                </span>
                {blockRate !== null && (
                  <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-500/15 border border-red-200 dark:border-red-500/20 text-red-700 dark:text-red-400 font-mono">
                    {blockRate}%
                  </span>
                )}
              </div>
              <div className="mt-3 pt-2.5 border-t border-red-200/40 dark:border-red-500/10 flex items-center text-[11.5px]">
                <span className="text-red-800/80 dark:text-red-300/70">Requests blocked (403), rate limited (429) or flagged</span>
              </div>
            </div>

            {/* Supporting: Unique IPs */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[12.5px] font-medium text-[var(--text-secondary)]">
                  Unique visitor IPs
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-amber-500/10">
                  <Globe size={15} className="text-amber-600 dark:text-amber-400" />
                </div>
              </div>
              <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-amber-600 dark:text-amber-400">
                {kpi(uniqueIPs)}
              </span>
              <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] flex items-center text-[11.5px]">
                <span className="text-[var(--text-muted)]">Visitor IP addresses seen</span>
              </div>
            </div>

            {/* Supporting: Engine Latency. Was a hardcoded fake "100.0%
                Engine Health" with no data behind it at all -- replaced
                with the one real metric this card already had access to
                (average_latency_ms), which used to be relegated to a
                secondary badge with a fake "14ms" fallback. */}
            <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
              <div className="flex items-center justify-between gap-2 mb-3">
                <span className="text-[12.5px] font-medium text-[var(--text-secondary)]">
                  Average response time
                </span>
                <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-emerald-500/10">
                  <ShieldCheck size={15} className="text-emerald-600 dark:text-emerald-400" />
                </div>
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-[26px] font-bold font-mono tracking-tight leading-none text-emerald-600 dark:text-emerald-400">
                  {isAnalyticsLoading ? '—' : analytics?.average_latency_ms != null ? `${analytics.average_latency_ms} ms` : '—'}
                </span>
              </div>
              <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] flex items-center text-[11.5px]">
                <span className="text-[var(--text-muted)]">
                  {analytics && analytics.average_latency_ms == null ? 'No response times recorded' : 'Mean time to answer a request'}
                </span>
              </div>
            </div>
          </div>

          {/* AI Threat Summary Banner */}
          {/* The backend writes this sentence from the same totals as the
              cards above (api/analytics.py), not with a language model. */}
          {analytics?.ai_summary && (
            <div className="mt-4 p-4 rounded-xl bg-[var(--bg-surface)] border border-[var(--bg-border)] flex items-start gap-3 text-[13px]">
              <Sparkles size={16} className="text-[var(--text-muted)] shrink-0 mt-0.5" aria-hidden="true" />
              <div className="space-y-0.5">
                <span className="font-semibold text-[var(--text-primary)]">In short</span>
                <p className="text-[var(--text-secondary)] m-0 leading-relaxed max-w-[90ch]">{analytics.ai_summary}</p>
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
                  <div>
                    <h3>Traffic timeline</h3>
                    <p className="m-0 text-[12px] text-[var(--text-muted)]">
                      Latest {logs.length.toLocaleString()} requests, counted {bucketLabel(timeline.bucketMs)}, {BKK_LABEL} time
                    </p>
                  </div>
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
                  <span className="text-[11.5px] text-[var(--text-muted)] hidden sm:inline">Updates every 8 s</span>
                </div>
              </div>

              <div
                className="p-4 sm:p-5 flex-1 flex flex-col"
                role="region"
                aria-label="Traffic and Threat Telemetry Timeline Chart"
              >
                <div className="h-[280px] w-full flex-1">
                  {isLogsLoading ? (
                    <div className="h-full flex items-center justify-center text-[13px] text-[var(--text-muted)]">Loading requests…</div>
                  ) : chartData.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-[13px] text-[var(--text-muted)]">No requests recorded for this scope yet.</div>
                  ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    {/* Numeric time axis: ticks and spacing follow real time.
                        Step lines, so a count of 1 or 2 reads as a level, not
                        as a smooth wave. */}
                    {chartView === 'area' ? (
                      <AreaChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                        <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical={false} />
                        <XAxis
                          dataKey="t"
                          type="number"
                          scale="time"
                          domain={['dataMin', 'dataMax']}
                          tickFormatter={(t: number) => formatBkkTime(t)}
                          stroke={axisColor}
                          fontSize={11}
                          tickLine={false}
                          tickMargin={8}
                          minTickGap={40}
                        />
                        <YAxis stroke={axisColor} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} width={36} label={{ value: 'Requests', angle: -90, position: 'insideLeft', fill: axisColor, fontSize: 11 }} />
                        <Tooltip
                          labelFormatter={(t: number) => `${formatBkkDateTime(t, { seconds: false })} (${bucketLabel(timeline.bucketMs)})`}
                          contentStyle={chartTooltipStyle}
                        />
                        <Legend wrapperStyle={{ fontSize: 12 }} />
                        <Area type="stepAfter" dataKey="allowed" stroke={isDark ? '#38bdf8' : '#0369a1'} strokeWidth={1.5} fill={isDark ? '#38bdf8' : '#0369a1'} fillOpacity={0.12} name="Allowed" isAnimationActive={false} />
                        <Area type="stepAfter" dataKey="limited" stroke="#d97706" strokeWidth={1.5} fill="#d97706" fillOpacity={0.12} name="Rate limited (429)" isAnimationActive={false} />
                        <Area type="stepAfter" dataKey="blocked" stroke="#dc2626" strokeWidth={1.5} fill="#dc2626" fillOpacity={0.15} name="Blocked (403)" isAnimationActive={false} />
                      </AreaChart>
                    ) : (
                      <BarChart data={chartData} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                        <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical={false} />
                        <XAxis
                          dataKey="t"
                          type="number"
                          scale="time"
                          domain={['dataMin - ' + timeline.bucketMs / 2, 'dataMax + ' + timeline.bucketMs / 2]}
                          tickFormatter={(t: number) => formatBkkTime(t)}
                          stroke={axisColor}
                          fontSize={11}
                          tickLine={false}
                          tickMargin={8}
                          minTickGap={40}
                        />
                        <YAxis stroke={axisColor} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} width={36} label={{ value: 'Requests', angle: -90, position: 'insideLeft', fill: axisColor, fontSize: 11 }} />
                        <Tooltip
                          labelFormatter={(t: number) => `${formatBkkDateTime(t, { seconds: false })} (${bucketLabel(timeline.bucketMs)})`}
                          contentStyle={chartTooltipStyle}
                        />
                        <Legend wrapperStyle={{ fontSize: 12 }} />
                        <Bar dataKey="allowed" stackId="a" fill={isDark ? '#1e3a5f' : '#bfdbfe'} maxBarSize={28} name="Allowed" isAnimationActive={false} />
                        <Bar dataKey="limited" stackId="a" fill="#d97706" maxBarSize={28} name="Rate limited (429)" isAnimationActive={false} />
                        <Bar dataKey="blocked" stackId="a" fill="#dc2626" radius={[3, 3, 0, 0]} maxBarSize={28} name="Blocked (403)" isAnimationActive={false} />
                      </BarChart>
                    )}
                  </ResponsiveContainer>
                  )}
                </div>
              </div>
            </div>

            {/* Attack Types Breakdown */}
            <div className="dash-card overflow-hidden flex flex-col">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <ShieldAlert size={15} className="text-red-500" />
                  <div>
                    <h3>Requests by attack type</h3>
                    <p className="m-0 text-[12px] text-[var(--text-muted)]">
                      {attackTypeTotal.toLocaleString()} classified requests, top 10 types
                    </p>
                  </div>
                </div>
              </div>

              {/* Counts every request the WAF classified with an attack type,
                  including ones only logged; rate-limited requests carry no
                  type. So this total is not the blocked count on the left. */}
              <div className="p-4 flex-1 flex flex-col justify-center space-y-3 text-[12.5px]">
                {analytics?.attack_types && Object.keys(analytics.attack_types).length > 0 ? (
                  Object.entries(analytics.attack_types).map(([type, count]) => {
                    const totalAtks = attackTypeTotal || 1
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
                  <div>
                    <h3>Most blocked sources</h3>
                    <p className="m-0 text-[12px] text-[var(--text-muted)]">Top 5 IPs by blocked or flagged requests, all stored traffic</p>
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="dash-table">
                  <thead>
                    <tr>
                      <th>Client IP</th>
                      <th className="text-right">Blocked</th>
                      <th className="text-right">All requests</th>
                      <th className="hidden sm:table-cell text-right">Blocked share</th>
                      <th><span className="sr-only">Actions</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {isAnalyticsLoading ? (
                      <tr>
                        <td colSpan={5} className="py-8 text-center text-[var(--text-muted)] text-[13px]">Loading…</td>
                      </tr>
                    ) : analytics?.suspicious_ips && analytics.suspicious_ips.length > 0 ? (
                      analytics.suspicious_ips.map((item, idx) => {
                        // `total` is every request from the IP, `blocked` the
                        // blocked or flagged ones (api/analytics.py). No
                        // fallbacks: a missing number shows as "—".
                        const totalItem = item.total ?? item.count ?? null
                        const blockedItem = item.blocked ?? null
                        const ratio =
                          totalItem && blockedItem !== null ? Math.round((blockedItem / totalItem) * 100) : null

                        return (
                          <tr key={item.ip || idx}>
                            <td>
                              <div className="flex items-center gap-1.5">
                                <span className="font-mono font-semibold text-[12.5px] text-[var(--text-primary)]">
                                  {item.ip}
                                </span>
                                <button
                                  type="button"
                                  onClick={() => handleCopyIp(item.ip)}
                                  className="text-[var(--text-muted)] hover:text-[var(--text-primary)] p-1 rounded cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
                                  aria-label={`Copy IP ${item.ip}`}
                                >
                                  {copiedIp === item.ip ? <Check size={12} className="text-emerald-600" /> : <Copy size={12} />}
                                </button>
                              </div>
                            </td>
                            <td className="text-right">
                              <span className="font-mono font-semibold text-red-700 dark:text-red-400 tabular-nums">{blockedItem ?? '—'}</span>
                            </td>
                            <td className="text-right">
                              <span className="font-mono text-[var(--text-secondary)] tabular-nums">{totalItem ?? '—'}</span>
                            </td>
                            <td className="hidden sm:table-cell text-right">
                              <span className="font-mono text-[12px] text-[var(--text-secondary)] tabular-nums">{ratio === null ? '—' : `${ratio}%`}</span>
                            </td>
                            <td className="text-right whitespace-nowrap">
                              <div className="inline-flex items-center gap-1.5">
                                <Link
                                  to={logsSearchPath(item.ip)}
                                  className="inline-flex items-center h-7 px-2 rounded-md border border-[var(--bg-border)] text-[12px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                                  aria-label={`View requests from ${item.ip} in traffic logs`}
                                >
                                  Logs
                                </Link>
                                <BlockIpButton
                                  ip={item.ip}
                                  originId={selectedOrigin !== 'ALL' ? selectedOrigin : null}
                                  note="Most blocked sources (dashboard)"
                                />
                              </div>
                            </td>
                          </tr>
                        )
                      })
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-8 text-center text-[var(--text-muted)] text-[13px]">
                          No blocked requests recorded for this scope.
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
                                  {countryDisplayName(c.country, c.name)}
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
              <p className="px-4 py-2 text-[10px] text-[var(--text-dim)] font-mono border-t border-[var(--bg-border-subtle)]">
                Country is estimated from the client IP (approximate; VPNs and proxies show their exit location). IP
                geolocation by{' '}
                <a
                  href="https://db-ip.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline underline-offset-2 hover:text-[var(--text-secondary)]"
                >
                  DB-IP
                </a>
                .
              </p>
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
              color={systemStatus === undefined ? 'gray' : thNode.online && mainNode.online ? 'success' : 'danger'}
              dot
              pulse={systemStatus !== undefined && thNode.online && mainNode.online}
            >
              {systemStatus === undefined
                ? 'CHECKING STATUS...'
                : thNode.online && mainNode.online ? 'ALL SYSTEMS OPERATIONAL' : 'DEGRADED — CHECK NODE STATUS'}
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
                  <span className="text-[var(--text-muted)] block text-[11px]">Health check round trip</span>
                  <span className="font-semibold text-[var(--text-primary)]">{thNode.latencyLabel}</span>
                </div>
                <div>
                  <span className="text-[var(--text-muted)] block text-[11px]">Rule set</span>
                  <span className="font-semibold text-[var(--text-primary)]">OWASP CRS {CRS_VERSION}</span>
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
                {/* From the same /system/status probes as Stack diagnostics
                    (these two used to be fixed "Connected" / "Active"). */}
                {([
                  { key: 'clickhouse', label: 'Log store (ClickHouse)' },
                  { key: 'frps', label: 'Tunnel server (FRP)' },
                ] as const).map(({ key, label }) => {
                  const s = systemStatus?.services?.[key]?.status
                  return (
                    <div key={key}>
                      <span className="text-[var(--text-muted)] block text-[11px]">{label}</span>
                      <span className={`font-semibold ${s === 'online' ? 'text-emerald-700 dark:text-emerald-400' : s === 'offline' ? 'text-red-700 dark:text-red-400' : 'text-[var(--text-muted)]'}`}>
                        {s === 'online' ? 'Online' : s === 'offline' ? 'Offline' : 'Unknown'}
                      </span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard
