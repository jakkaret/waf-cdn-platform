import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { systemApi } from '../api/system'
import { analyticsApi } from '../api/analytics'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { StatCard } from '../components/ui/StatCard'
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
import {
  ShieldAlert,
  Activity,
  Globe,
  RefreshCw,
  ShieldCheck,
  Zap,
  Server,
  Terminal,
  Clock,
  Sparkles,
  Copy,
  Check,
  AlertOctagon,
  ArrowUpRight,
} from 'lucide-react'
import toast from 'react-hot-toast'

export const Dashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'security' | 'infrastructure'>('security')
  const [chartView, setChartView] = useState<'area' | 'bar'>('area')
  const [copiedIp, setCopiedIp] = useState<string | null>(null)
  const { theme } = useThemeStore()

  const { data: logs = [], isLoading: isLogsLoading, isFetching: isLogsFetching, refetch: refetchLogs } = useQuery({
    queryKey: ['logs-dashboard'],
    queryFn: () => logsApi.getRecentLogs(200),
    refetchInterval: 8000,
    enabled: activeTab === 'security',
  })

  const { data: analytics, isLoading: isAnalyticsLoading, isFetching: isAnalyticsFetching, refetch: refetchAnalytics } = useQuery({
    queryKey: ['analytics-summary'],
    queryFn: () => analyticsApi.getSummary(),
    refetchInterval: 8000,
    enabled: activeTab === 'security',
  })

  const { data: systemStatus, isFetching: isSystemFetching, refetch: refetchSystem } = useQuery({
    queryKey: ['system-status-dashboard'],
    queryFn: () => systemApi.getSystemStatus(),
    refetchInterval: 5000,
    enabled: activeTab === 'infrastructure',
  })

  const handleRefresh = () => {
    if (activeTab === 'security') {
      refetchLogs()
      refetchAnalytics()
      toast.success('Security analytics refreshed')
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

  // Time aggregated timeline
  const chartData = logs
    .reduce((acc, log) => {
      const time = new Date(log.datetime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
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
    <div className="space-y-6">
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
            <div className="flex rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-0.5">
              <button
                onClick={() => setActiveTab('security')}
                className={`px-3 py-1 text-[12px] font-semibold rounded-md transition-all font-mono ${
                  activeTab === 'security'
                    ? 'bg-orange-500 text-white shadow-sm'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                }`}
              >
                Security Analytics
              </button>
              <button
                onClick={() => setActiveTab('infrastructure')}
                className={`px-3 py-1 text-[12px] font-semibold rounded-md transition-all font-mono ${
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
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--bg-surface)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] text-[12px] font-mono font-medium text-[var(--text-primary)] rounded-md hover:bg-[var(--bg-hover)] shadow-sm transition-all cursor-pointer"
              title="Refresh telemetry"
            >
              <RefreshCw size={13} className={isSyncing ? 'animate-spin text-orange-500' : 'text-[var(--text-muted)]'} />
              <span className="hidden sm:inline">Sync</span>
            </button>
          </div>
        }
      />

      {activeTab === 'security' ? (
        <div className="space-y-6 animate-fade-in">
          {/* Top 4 KPI Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              label="Total Inbound Traffic"
              value={isAnalyticsLoading ? '—' : (analytics?.total_requests ?? totalRequests).toLocaleString()}
              color="blue"
              icon={<Activity size={16} />}
              sub="HTTP/S Requests Analyzed"
              trend={{
                value: 4.2,
                label: 'vs 1h ago',
                isPositive: true,
              }}
            />

            <StatCard
              label="Threats Mitigated"
              value={isAnalyticsLoading ? '—' : (analytics?.blocked_requests ?? blockedCount).toLocaleString()}
              color="red"
              icon={<ShieldAlert size={16} />}
              badgeText={`${blockRate}% Block Rate`}
              sub="OWASP CRS & Custom Rules"
              trend={{
                value: 12.8,
                label: 'anomaly burst',
                isPositive: false,
              }}
            />

            <StatCard
              label="Distinct Client IPs"
              value={isLogsLoading ? '—' : uniqueIPs.toLocaleString()}
              color="amber"
              icon={<Globe size={16} />}
              sub="Unique Origin Addresses"
              badgeText="Global Sources"
            />

            <StatCard
              label="Engine Health & SLA"
              value="100.0%"
              color="green"
              icon={<ShieldCheck size={16} />}
              badgeText={`${analytics?.average_latency_ms || 14}ms Latency`}
              sub="ModSec v3 + CRS 3.3.5 Active"
            />
          </div>

          {/* Main Traffic Graph & Attack Types Section */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Chart Area */}
            <div className="lg:col-span-2 dash-card overflow-hidden flex flex-col">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <Activity size={16} className="text-orange-500" />
                  <h3>Traffic & Threat Activity Timeline</h3>
                </div>

                <div className="flex items-center gap-2">
                  <div className="flex rounded border border-[var(--bg-border)] bg-[var(--bg-primary)] p-0.5 text-[11px] font-mono">
                    <button
                      onClick={() => setChartView('area')}
                      className={`px-2 py-0.5 rounded transition-colors ${
                        chartView === 'area' ? 'bg-orange-500 text-white font-semibold' : 'text-[var(--text-muted)]'
                      }`}
                    >
                      Area
                    </button>
                    <button
                      onClick={() => setChartView('bar')}
                      className={`px-2 py-0.5 rounded transition-colors ${
                        chartView === 'bar' ? 'bg-orange-500 text-white font-semibold' : 'text-[var(--text-muted)]'
                      }`}
                    >
                      Bar
                    </button>
                  </div>
                  <Badge color="gray" size="sm">
                    LIVE 10s
                  </Badge>
                </div>
              </div>

              <div className="p-4 sm:p-5 flex-1 flex flex-col justify-between">
                <div className="h-[280px] w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    {chartView === 'area' ? (
                      <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <defs>
                          <linearGradient id="colorAllowed" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor={isDark ? '#38bdf8' : '#0284c7'} stopOpacity={0.4} />
                            <stop offset="95%" stopColor={isDark ? '#38bdf8' : '#0284c7'} stopOpacity={0.0} />
                          </linearGradient>
                          <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="time" stroke={axisColor} fontSize={11} tickLine={false} tickMargin={8} />
                        <YAxis stroke={axisColor} fontSize={11} tickLine={false} axisLine={false} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: isDark ? '#101827' : '#ffffff',
                            borderColor: isDark ? '#2a374d' : '#e2e8f0',
                            borderRadius: '8px',
                            fontSize: '12px',
                            fontFamily: 'monospace',
                            boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.3)',
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
                      <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="time" stroke={axisColor} fontSize={11} tickLine={false} tickMargin={8} />
                        <YAxis stroke={axisColor} fontSize={11} tickLine={false} axisLine={false} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: isDark ? '#101827' : '#ffffff',
                            borderColor: isDark ? '#2a374d' : '#e2e8f0',
                            borderRadius: '8px',
                            fontSize: '12px',
                            fontFamily: 'monospace',
                          }}
                        />
                        <Bar
                          dataKey="allowed"
                          stackId="a"
                          fill={isDark ? '#1e3a5f' : '#cbd5e1'}
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

                {/* Legend & Summary Footer */}
                <div className="flex flex-wrap items-center justify-between gap-4 mt-4 pt-3 border-t border-[var(--bg-border-subtle)] text-[12px] font-mono">
                  <div className="flex items-center gap-4">
                    <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
                      <span className="w-2.5 h-2.5 rounded-full bg-sky-500" />
                      Clean / Allowed
                    </span>
                    <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                      WAF Blocked
                    </span>
                    <span className="flex items-center gap-1.5 text-[var(--text-secondary)]">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                      Rate Limited
                    </span>
                  </div>

                  <span className="text-[var(--text-muted)] text-[11px]">
                    Showing latest 20 telemetry sample intervals
                  </span>
                </div>
              </div>
            </div>

            {/* Attack Types & OWASP Vectors */}
            <div className="dash-card overflow-hidden flex flex-col">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <ShieldAlert size={16} className="text-red-500" />
                  <h3>Attack Classification</h3>
                </div>
                <Badge color="danger" size="sm">
                  OWASP TOP 10
                </Badge>
              </div>

              <div className="p-4 sm:p-5 flex-1 flex flex-col justify-between space-y-4">
                <div className="space-y-3">
                  {analytics && Object.keys(analytics.attack_types).length > 0 ? (
                    Object.entries(analytics.attack_types).map(([attack, count], i) => {
                      const totalAttacks = Object.values(analytics.attack_types).reduce((a, b) => a + b, 0)
                      const pct = totalAttacks > 0 ? Math.round((count / totalAttacks) * 100) : 0
                      const barColors = [
                        'bg-red-500',
                        'bg-orange-500',
                        'bg-amber-500',
                        'bg-rose-500',
                        'bg-violet-500',
                      ]
                      const barColor = barColors[i % barColors.length]

                      return (
                        <div key={attack} className="space-y-1">
                          <div className="flex justify-between items-center text-[12px]">
                            <span className="font-medium text-[var(--text-primary)] truncate">{attack}</span>
                            <div className="flex items-center gap-2 font-mono shrink-0">
                              <span className="text-[var(--text-secondary)] font-semibold">{count}</span>
                              <span className="text-[var(--text-muted)] text-[11px]">({pct}%)</span>
                            </div>
                          </div>
                          <div className="h-1.5 w-full bg-[var(--bg-primary)] rounded-full overflow-hidden">
                            <div className={`h-full ${barColor} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                      )
                    })
                  ) : (
                    <div className="py-8 text-center text-[var(--text-muted)] text-[12px] space-y-2">
                      <ShieldCheck size={28} className="mx-auto text-emerald-500 opacity-60" />
                      <p>No critical attack signatures identified in current window.</p>
                    </div>
                  )}
                </div>

                {/* AI Threat Intelligence Insight Box */}
                {analytics?.ai_summary && (
                  <div className="rounded-lg p-3.5 bg-gradient-to-br from-orange-500/[0.06] to-amber-500/[0.04] border border-orange-500/20 text-[12px] space-y-2">
                    <div className="flex items-center gap-1.5 text-orange-500 dark:text-orange-400 font-bold font-mono text-[11px] uppercase tracking-wide">
                      <Sparkles size={13} />
                      <span>FortiAI Threat Summary</span>
                    </div>
                    <p className="text-[var(--text-secondary)] leading-relaxed m-0 text-[12px]">
                      {analytics.ai_summary}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Attacker Matrix & Country Distribution */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Top Suspicious IPs */}
            <div className="dash-card overflow-hidden">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <Terminal size={15} className="text-orange-500" />
                  <h3>Top Suspicious Sources</h3>
                </div>
                <span className="text-[11px] text-[var(--text-muted)] font-mono">By Block Frequency</span>
              </div>

              <div className="overflow-x-auto">
                <table className="dash-table">
                  <thead>
                    <tr>
                      <th>Client IP</th>
                      <th>Mitigated</th>
                      <th>Total Requests</th>
                      <th className="text-right">Threat Ratio</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analytics?.suspicious_ips && analytics.suspicious_ips.length > 0 ? (
                      analytics.suspicious_ips.map((item, idx) => {
                        const ratio = item.total > 0 ? ((item.blocked / item.total) * 100).toFixed(0) : '0'
                        const isHighRisk = Number(ratio) >= 50

                        return (
                          <tr key={item.ip || idx}>
                            <td>
                              <div className="flex items-center gap-2">
                                <span className="font-mono font-bold text-[12px] text-[var(--text-primary)]">
                                  {item.ip}
                                </span>
                                <button
                                  onClick={() => handleCopyIp(item.ip)}
                                  className="text-[var(--text-muted)] hover:text-orange-500 transition-colors p-0.5 rounded cursor-pointer"
                                  title="Copy IP"
                                >
                                  {copiedIp === item.ip ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                                </button>
                              </div>
                            </td>
                            <td>
                              <span className="font-mono font-bold text-red-500">{item.blocked}</span>
                            </td>
                            <td>
                              <span className="font-mono text-[var(--text-secondary)]">{item.total}</span>
                            </td>
                            <td className="text-right">
                              <span
                                className={`inline-flex px-2 py-0.5 rounded text-[11px] font-mono font-semibold ${
                                  isHighRisk
                                    ? 'bg-red-500/10 text-red-500 border border-red-500/20'
                                    : 'bg-amber-500/10 text-amber-500 border border-amber-500/20'
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
                        <td colSpan={4} className="py-6 text-center text-[var(--text-muted)] text-[12px]">
                          No suspicious source IPs recorded.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Traffic & Threats by Country */}
            <div className="dash-card overflow-hidden">
              <div className="dash-card-header">
                <div className="flex items-center gap-2">
                  <Globe size={15} className="text-sky-500" />
                  <h3>Geographic Distribution</h3>
                </div>
                <span className="text-[11px] text-[var(--text-muted)] font-mono">Global Inbound</span>
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
                        const share = ((c.total / totalAll) * 100).toFixed(1)

                        return (
                          <tr key={c.country || i}>
                            <td>
                              <div className="flex items-center gap-2">
                                <span className="text-base leading-none">{c.flag || '🌐'}</span>
                                <span className="font-medium text-[12.5px] text-[var(--text-primary)]">
                                  {c.name || c.country}
                                </span>
                                <span className="text-[10.5px] font-mono text-[var(--text-muted)] uppercase">
                                  [{c.country}]
                                </span>
                              </div>
                            </td>
                            <td>
                              <span className="font-mono text-[var(--text-secondary)]">{c.total.toLocaleString()}</span>
                            </td>
                            <td>
                              <span className={`font-mono font-semibold ${c.blocked > 0 ? 'text-red-500' : 'text-[var(--text-muted)]'}`}>
                                {c.blocked}
                              </span>
                            </td>
                            <td className="text-right">
                              <div className="flex items-center justify-end gap-2">
                                <span className="font-mono text-[12px] text-[var(--text-secondary)]">{share}%</span>
                                <div className="w-12 h-1.5 bg-[var(--bg-primary)] rounded-full overflow-hidden hidden sm:block">
                                  <div
                                    className="h-full bg-sky-500 rounded-full"
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
                        <td colSpan={4} className="py-6 text-center text-[var(--text-muted)] text-[12px]">
                          No geographic telemetry available.
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
        <div className="space-y-6 animate-fade-in">
          {/* Cluster Status Header */}
          <div className="flex justify-between items-center bg-[var(--bg-surface)] border border-[var(--bg-border)] p-4 rounded-lg">
            <div>
              <h2 className="text-[15px] font-bold text-[var(--text-primary)] m-0 font-mono flex items-center gap-2">
                <Server size={17} className="text-orange-500" />
                Edge POP Nodes & Service Mesh
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                ModSecurity Reverse Proxy, Caddy SSL Termination, and ClickHouse OLAP Cluster
              </p>
            </div>
            <Badge color="success" dot pulse>
              ALL SYSTEMS OPERATIONAL
            </Badge>
          </div>

          {/* Edge POP Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {systemStatus?.cdn_nodes.map((node) => {
              const names: Record<string, string> = {
                SG: 'Singapore Edge POP',
                JP: 'Tokyo Edge POP',
                TH: 'Bangkok Edge POP',
              }
              const flags: Record<string, string> = { SG: '🇸🇬', JP: '🇯🇵', TH: '🇹🇭' }
              const isOnline = node.status === 'online'

              return (
                <div
                  key={node.region}
                  className={`dash-card p-4 flex flex-col justify-between border-t-2 ${
                    isOnline ? 'border-t-emerald-500' : 'border-t-red-500'
                  }`}
                >
                  <div>
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-2.5">
                        <span className="text-2xl">{flags[node.region] || '🌐'}</span>
                        <div>
                          <p className="font-bold text-[13.5px] text-[var(--text-primary)] m-0">
                            {names[node.region] || node.region}
                          </p>
                          <p className="text-[11px] font-mono text-[var(--text-muted)] m-0">
                            PORT {node.port} • TCP/HTTP
                          </p>
                        </div>
                      </div>
                      <Badge color={isOnline ? 'success' : 'danger'} dot>
                        {isOnline ? 'Online' : 'Unreachable'}
                      </Badge>
                    </div>

                    <div className="grid grid-cols-2 gap-2 mt-4 pt-3 border-t border-[var(--bg-border-subtle)] text-[11.5px] font-mono">
                      <div>
                        <span className="text-[var(--text-muted)] block text-[10px] uppercase">Latency</span>
                        <span className="font-bold text-[var(--text-primary)]">
                          {isOnline ? `${node.latency_ms} ms` : '—'}
                        </span>
                      </div>
                      <div>
                        <span className="text-[var(--text-muted)] block text-[10px] uppercase">WAF Engine</span>
                        <span className="font-bold text-emerald-500">Active</span>
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Microservices Health Table */}
          <div className="dash-card overflow-hidden">
            <div className="dash-card-header">
              <div className="flex items-center gap-2">
                <Zap size={16} className="text-amber-500" />
                <h3>Infrastructure Service Components</h3>
              </div>
              <span className="text-[11px] text-[var(--text-muted)] font-mono">Docker Container Mesh</span>
            </div>

            <div className="overflow-x-auto">
              <table className="dash-table">
                <thead>
                  <tr>
                    <th>Service Name</th>
                    <th>Port Mapping</th>
                    <th>Subsystem Role</th>
                    <th className="text-right">Health Status</th>
                  </tr>
                </thead>
                <tbody>
                  {systemStatus &&
                    Object.entries(systemStatus.services).map(([name, data]) => (
                      <tr key={name}>
                        <td>
                          <span className="font-mono font-bold text-[13px] text-[var(--text-primary)]">
                            {name}
                          </span>
                        </td>
                        <td>
                          <span className="font-mono text-[12px] text-sky-500">
                            {data.port}
                          </span>
                        </td>
                        <td>
                          <span className="text-[var(--text-secondary)] text-[12px]">
                            {data.desc}
                          </span>
                        </td>
                        <td className="text-right">
                          <Badge color={data.status === 'online' ? 'success' : 'danger'} dot>
                            {data.status === 'online' ? 'RUNNING (Healthy)' : 'STOPPED'}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Dashboard
