import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { systemApi } from '../api/system'
import { analyticsApi } from '../api/analytics'
import { TopBar } from '../components/layout/TopBar'
import { StatCard } from '../components/ui/StatCard'
import { Card, CardHeader } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { 
  ShieldAlert, 
  Activity, 
  Globe, 
  Database, 
  HardDrive, 
  Cpu, 
  Terminal, 
  CheckCircle, 
  XCircle, 
  RefreshCw,
  Server,
  Sparkles,
  ShieldCheck
} from 'lucide-react'

export const Dashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'security' | 'system'>('security')
  const [showRawJson, setShowRawJson] = useState(false)

  // 1. Fetch Security Logs for Security Tab
  const { data: logs = [], isLoading: isLogsLoading } = useQuery({
    queryKey: ['logs-dashboard'],
    queryFn: () => logsApi.getRecentLogs(200),
    refetchInterval: 10000,
    enabled: activeTab === 'security',
  })

  // 2. Fetch ClickHouse Real-time Analytics & AI Summary
  const { data: analytics, isLoading: isAnalyticsLoading } = useQuery({
    queryKey: ['analytics-summary'],
    queryFn: () => analyticsApi.getSummary(),
    refetchInterval: 10000,
    enabled: activeTab === 'security',
  })

  // 3. Fetch System Health Status for System Status Tab
  const { data: systemStatus, isLoading: isSystemLoading, refetch: refetchSystem, isRefetching: isSystemRefetching } = useQuery({
    queryKey: ['system-status-dashboard'],
    queryFn: () => systemApi.getSystemStatus(),
    refetchInterval: 5000, // Update status every 5 seconds
    enabled: activeTab === 'system',
  })

  // Basic stats calc (Security Tab)
  const blockedCount = logs.filter(l => l.status === 403 || l.status === 429).length
  const totalRequests = logs.length
  const uniqueIPs = new Set(logs.map(l => l.ip)).size
  
  // Format for chart (group by hour/min roughly)
  const chartData = logs.reduce((acc, log) => {
    const time = new Date(log.datetime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const existing = acc.find((d: any) => d.time === time)
    if (existing) {
      if (log.status === 403 || log.status === 429) existing.blocked++
      else existing.allowed++
    } else {
      acc.push({ time, blocked: (log.status === 403 || log.status === 429) ? 1 : 0, allowed: (log.status !== 403 && log.status !== 429) ? 1 : 0 })
    }
    return acc
  }, [] as any[]).slice(-20) // last 20 data points

  const CustomTooltipStyle = {
    backgroundColor: 'rgba(22,27,39,0.95)',
    borderColor: 'rgba(255,255,255,0.06)',
    borderRadius: '10px',
    backdropFilter: 'blur(12px)',
    boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
    padding: '10px 14px',
  }

  return (
    <div>
      <TopBar 
        title="Dashboard Overview" 
        subtitle="Real-time WAF activity and general status" 
        action={
          <div className="flex bg-white/[0.03] p-1 rounded-[10px] border border-white/[0.05]">
            <button
              onClick={() => setActiveTab('security')}
              className={`px-4 py-1.5 text-[12px] font-semibold rounded-lg transition-all duration-200 ${
                activeTab === 'security'
                  ? 'bg-accent/[0.12] text-accent-light shadow-[0_0_12px_rgba(102,126,234,0.1)]'
                  : 'text-white/25 hover:text-white/45'
              }`}
            >
              Security Overview
            </button>
            <button
              onClick={() => setActiveTab('system')}
              className={`px-4 py-1.5 text-[12px] font-semibold rounded-lg transition-all duration-200 ${
                activeTab === 'system'
                  ? 'bg-accent/[0.12] text-accent-light shadow-[0_0_12px_rgba(102,126,234,0.1)]'
                  : 'text-white/25 hover:text-white/45'
              }`}
            >
              System Health Monitor
            </button>
          </div>
        }
      />

      {activeTab === 'security' ? (
        /* ================== SECURITY TAB ================== */
        <>
          {/* AI Security Threat Summary Card */}
          {analytics && (
            <div className="mb-7 p-5 rounded-2xl border border-accent/[0.1] bg-gradient-to-r from-accent/[0.04] via-transparent to-accent-dark/[0.02] relative overflow-hidden animate-fade-in-up">
              <div className="absolute top-0 right-0 p-8 opacity-[0.03] text-accent">
                <Sparkles size={120} />
              </div>
              <div className="absolute top-0 right-1/4 w-48 h-48 bg-accent/[0.04] rounded-full blur-[80px] pointer-events-none" />
              <div className="flex gap-4 items-start relative z-10">
                <div className="p-2.5 rounded-[10px] bg-accent/[0.08] text-accent-light shrink-0 border border-accent/[0.08]">
                  <Sparkles size={20} className="animate-breathe" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 mb-2">
                    <h4 className="text-[12px] font-bold text-accent-light/70 uppercase tracking-[0.1em] font-heading">WAF AI Threat Summary</h4>
                    <Badge color="success">Live</Badge>
                  </div>
                  <p className="text-[13px] text-white/70 leading-relaxed font-medium">
                    {analytics.ai_summary}
                  </p>
                  <div className="flex gap-5 mt-3 text-[11px] text-white/25 font-medium">
                    <span>Source: <b className="text-accent-light/50 capitalize">{analytics.source}</b></span>
                    <span>Latency: <b className="text-white/50">{analytics.average_latency_ms} ms</b></span>
                    <span>Block Rate: <b className="text-danger/70">{((analytics.blocked_requests / (analytics.total_requests || 1)) * 100).toFixed(1)}%</b></span>
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-7">
            {[
              { label: 'Total Requests', value: isAnalyticsLoading ? '-' : (analytics?.total_requests ?? totalRequests), color: 'brand' as const, icon: <Activity size={18} />, delay: '0.05s' },
              { label: 'Blocked Requests', value: isAnalyticsLoading ? '-' : (analytics?.blocked_requests ?? blockedCount), color: 'danger' as const, icon: <ShieldAlert size={18} />, delay: '0.1s' },
              { label: 'Unique IPs', value: isLogsLoading ? '-' : uniqueIPs, color: 'info' as const, icon: <Globe size={18} />, delay: '0.15s' },
              { label: 'WAF AI Health', value: (analytics?.blocked_requests ?? 0) > 0 ? "Threat Blocked" : "Optimal", color: ((analytics?.blocked_requests ?? 0) > 0 ? "warning" : "success") as 'warning' | 'success', icon: <ShieldCheck size={18} />, delay: '0.2s' },
            ].map((stat, i) => (
              <div key={i} className="animate-fade-in-up" style={{ animationDelay: stat.delay }}>
                <StatCard 
                  label={stat.label} 
                  value={stat.value} 
                  color={stat.color}
                  icon={stat.icon}
                />
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-7">
            <Card className="lg:col-span-2 animate-fade-in-up stagger-3">
              <CardHeader title="Traffic & Blocks" subtitle="Last 20 data points" />
              <div className="h-[280px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <XAxis dataKey="time" stroke="rgba(255,255,255,0.1)" fontSize={11} tickMargin={10} />
                    <YAxis stroke="rgba(255,255,255,0.1)" fontSize={11} />
                    <Tooltip 
                      contentStyle={CustomTooltipStyle}
                      itemStyle={{ color: '#e4e8f0', fontSize: '12px' }}
                      cursor={{ fill: 'rgba(102,126,234,0.04)' }}
                    />
                    <Bar dataKey="allowed" stackId="a" fill="#667eea" radius={[0, 0, 4, 4]} />
                    <Bar dataKey="blocked" stackId="a" fill="#fc8181" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>

            <Card className="animate-fade-in-up stagger-4">
              <CardHeader title="Attack Type Breakdown" subtitle="ModSecurity blocks via ClickHouse" />
              <div className="space-y-3.5">
                {analytics && Object.entries(analytics.attack_types).map(([attack, count], i) => (
                  <div key={i} className="flex justify-between items-center pb-3 border-b border-white/[0.04] last:border-0 last:pb-0">
                    <div className="overflow-hidden mr-2">
                      <p className="text-[13px] font-semibold text-white/80 truncate">{attack}</p>
                      <p className="text-[10.5px] text-white/20 mt-0.5 font-medium">Matched Rules & Ingress</p>
                    </div>
                    <Badge color="danger">{count} blocks</Badge>
                  </div>
                ))}
                {(!analytics || Object.keys(analytics.attack_types).length === 0) && (
                  <div className="text-center text-white/20 text-[13px] py-8 font-medium">No attacks detected</div>
                )}
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-7">
            <Card className="lg:col-span-2 animate-fade-in-up stagger-5">
              <CardHeader title="Top Suspicious Host IPs" subtitle="Ranked by security violations" />
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-[10px] font-bold text-white/20 uppercase tracking-[0.08em]">
                      <th className="pb-3">Client IP</th>
                      <th className="pb-3">Blocked</th>
                      <th className="pb-3">Total</th>
                      <th className="pb-3 text-right">Violation %</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analytics?.suspicious_ips.map((ip, i) => (
                      <tr key={i} className="border-b border-white/[0.03] last:border-0 text-[13px] row-glow transition-colors">
                        <td className="py-3 font-mono font-semibold text-white/80 flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-danger shadow-[0_0_4px_rgba(252,129,129,0.4)]" />
                          {ip.ip}
                        </td>
                        <td className="py-3 font-mono text-danger/80 font-bold">{ip.blocked}</td>
                        <td className="py-3 font-mono text-white/25">{ip.total}</td>
                        <td className="py-3 text-right font-mono text-accent-light/70 font-bold">
                          {((ip.blocked / (ip.total || 1)) * 100).toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                    {(!analytics?.suspicious_ips.length) && (
                      <tr>
                        <td colSpan={4} className="text-center py-8 text-white/20 text-[13px] font-medium">
                          No suspicious traffic records
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            <Card className="animate-fade-in-up stagger-6">
              <CardHeader title="Top Countries" subtitle="Geographic origin" />
              <div className="space-y-3.5">
                {analytics?.top_countries?.map((c, i) => (
                  <div key={i} className="flex justify-between items-center pb-3 border-b border-white/[0.04] last:border-0 last:pb-0">
                    <div className="flex items-center gap-2.5 overflow-hidden mr-2">
                      <span className="text-lg">{c.flag || '🌐'}</span>
                      <div>
                        <p className="text-[13px] font-semibold text-white/80">{c.name || c.country}</p>
                        <p className="text-[10.5px] text-white/20 mt-0.5 font-medium">{c.total} requests</p>
                      </div>
                    </div>
                    <Badge color={c.blocked > 0 ? "warning" : "success"}>
                      {c.blocked} blocked
                    </Badge>
                  </div>
                ))}
                {(!analytics?.top_countries || analytics.top_countries.length === 0) && (
                  <div className="text-center text-white/20 text-[13px] py-8 font-medium">No geographic data</div>
                )}
              </div>
            </Card>

            <Card className="animate-fade-in-up stagger-7">
              <CardHeader title="Recent Blocks" subtitle="Latest firewall activity" />
              <div className="space-y-3.5">
                {logs.filter(l => l.status === 403 || l.status === 429).slice(0, 5).map((log, i) => (
                  <div key={i} className="flex justify-between items-start pb-3 border-b border-white/[0.04] last:border-0 last:pb-0">
                    <div className="overflow-hidden mr-2">
                      <p className="text-[12px] font-mono text-danger/80 truncate font-semibold">{log.ip}</p>
                      <p className="text-[10.5px] text-white/20 truncate mt-0.5">{log.url}</p>
                    </div>
                    <Badge color={log.status === 429 ? 'warning' : 'danger'}>
                      {log.status === 429 ? 'LIMIT' : 'WAF'}
                    </Badge>
                  </div>
                ))}
                {logs.filter(l => l.status === 403 || l.status === 429).length === 0 && (
                  <div className="text-center text-white/20 text-[13px] py-8 font-medium">No recent blocks</div>
                )}
              </div>
            </Card>
          </div>
        </>
      ) : (
        /* ================== SYSTEM HEALTH MONITOR TAB ================== */
        <>
          {/* Quick Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-7">
            {/* Database Status Card */}
            <Card className="flex flex-col justify-between animate-fade-in-up stagger-1">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.1em]">Database Service</p>
                  <h4 className="text-[20px] font-extrabold text-white mt-1.5 leading-tight font-heading">
                    {isSystemLoading ? 'Loading...' : systemStatus?.db.status === 'online' ? 'Online' : 'Offline'}
                  </h4>
                </div>
                <div className={`w-9 h-9 rounded-[10px] flex items-center justify-center ${systemStatus?.db.status === 'online' ? 'bg-success/[0.08] text-success' : 'bg-danger/[0.08] text-danger'}`}>
                  <Database size={18} />
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-white/[0.04] flex items-center gap-1.5 text-[11px] text-white/25 font-medium">
                <span className={`w-2 h-2 rounded-full ${systemStatus?.db.status === 'online' ? 'bg-success shadow-[0_0_4px_rgba(104,211,145,0.4)] animate-pulse' : 'bg-danger shadow-[0_0_4px_rgba(252,129,129,0.4)]'}`} />
                <span className="truncate">{systemStatus?.db.detail || 'Checking connection...'}</span>
              </div>
            </Card>

            {/* Disk Usage Card */}
            <Card className="flex flex-col justify-between animate-fade-in-up stagger-2">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.1em]">Disk Storage</p>
                  <h4 className="text-[20px] font-extrabold text-white mt-1.5 leading-tight font-heading">
                    {isSystemLoading ? '-' : `${systemStatus?.system.disk_used_gb} / ${systemStatus?.system.disk_total_gb} GB`}
                  </h4>
                </div>
                <div className="w-9 h-9 rounded-[10px] flex items-center justify-center bg-info/[0.08] text-info">
                  <HardDrive size={18} />
                </div>
              </div>
              <div className="mt-4">
                <div className="w-full bg-white/[0.04] rounded-full h-[5px] mb-2 overflow-hidden">
                  <div 
                    className={`h-[5px] rounded-full transition-all duration-700 ${
                      (systemStatus?.system.disk_used_percent || 0) > 85 ? 'bg-danger' : 'bg-info'
                    }`} 
                    style={{ width: `${systemStatus?.system.disk_used_percent || 0}%` }}
                  />
                </div>
                <div className="flex justify-between text-[10px] text-white/20 font-medium">
                  <span>{systemStatus?.system.disk_used_percent || 0}% Used</span>
                  <span>{systemStatus?.system.disk_free_gb || 0} GB Free</span>
                </div>
              </div>
            </Card>

            {/* Load Average Card */}
            <Card className="flex flex-col justify-between animate-fade-in-up stagger-3">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.1em]">CPU Load</p>
                  <h4 className="text-[20px] font-extrabold text-white mt-1.5 leading-tight font-heading">
                    {isSystemLoading ? '-' : systemStatus?.system.load_average[0].toFixed(2)}
                  </h4>
                </div>
                <div className="w-9 h-9 rounded-[10px] flex items-center justify-center bg-accent/[0.08] text-accent-light">
                  <Cpu size={18} />
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-white/[0.04] flex justify-between text-[10.5px] text-white/20 font-medium">
                <span>1m: <b className="text-white/40">{systemStatus?.system.load_average[0].toFixed(2)}</b></span>
                <span>5m: <b className="text-white/40">{systemStatus?.system.load_average[1].toFixed(2)}</b></span>
                <span>15m: <b className="text-white/40">{systemStatus?.system.load_average[2].toFixed(2)}</b></span>
              </div>
            </Card>

            {/* Refresh Monitor Card */}
            <Card className="flex flex-col justify-between animate-fade-in-up stagger-4">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.1em]">Monitor Engine</p>
                  <h4 className="text-[14px] font-bold text-white/70 mt-1.5 leading-tight">
                    Auto-refreshing (5s)
                  </h4>
                </div>
                <button 
                  onClick={() => refetchSystem()} 
                  className={`w-9 h-9 rounded-[10px] flex items-center justify-center bg-white/[0.04] text-white/40 hover:bg-white/[0.07] hover:text-white/60 transition-all duration-200 ${
                    isSystemRefetching ? 'animate-spin' : ''
                  }`}
                  title="Manual Refresh"
                >
                  <RefreshCw size={15} />
                </button>
              </div>
              <div className="mt-4 pt-3 border-t border-white/[0.04] flex items-center justify-between text-[10.5px] text-white/20 font-medium">
                <span>Status: <b className="text-success/70">Active</b></span>
                <span>Uptime: <b className="text-white/40">Normal</b></span>
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 mb-7">
            {/* Core Services Table */}
            <Card className="lg:col-span-2 animate-fade-in-up stagger-5">
              <CardHeader title="Core System Services" subtitle="Docker containers and internal services" />
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-white/[0.06] text-[10px] font-bold text-white/20 uppercase tracking-[0.08em]">
                      <th className="pb-3">Service</th>
                      <th className="pb-3">Port</th>
                      <th className="pb-3">Description</th>
                      <th className="pb-3 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {systemStatus && Object.entries(systemStatus.services).map(([name, data]) => (
                      <tr key={name} className="border-b border-white/[0.03] last:border-0 text-[13px] row-glow transition-colors">
                        <td className="py-3 font-semibold text-white/80 flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${data.status === 'online' ? 'bg-success shadow-[0_0_4px_rgba(104,211,145,0.4)]' : 'bg-danger shadow-[0_0_4px_rgba(252,129,129,0.4)]'}`} />
                          {name}
                        </td>
                        <td className="py-3 font-mono text-white/25 text-[12px]">{data.port}</td>
                        <td className="py-3 text-white/25 text-[12px]">{data.desc}</td>
                        <td className="py-3 text-right">
                          <Badge color={data.status === 'online' ? 'success' : 'danger'} dot>
                            {data.status === 'online' ? 'ONLINE' : 'OFFLINE'}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                    {isSystemLoading && (
                      <tr>
                        <td colSpan={4} className="text-center py-8 text-white/20 text-[13px] font-medium">
                          Loading services...
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            {/* Background Workers & Tasks */}
            <Card className="animate-fade-in-up stagger-6">
              <CardHeader title="Background Workers" subtitle="Internal process states" />
              <div className="space-y-4">
                {systemStatus && Object.entries(systemStatus.workers).map(([name, data]) => (
                  <div key={name} className="flex justify-between items-start pb-3.5 border-b border-white/[0.04] last:border-0 last:pb-0">
                    <div className="mr-3">
                      <p className="text-[13px] font-semibold text-white/80 m-0 flex items-center gap-1.5">
                        <Activity size={13} className={data.status === 'running' ? 'text-success animate-pulse' : 'text-white/15'} />
                        {name}
                      </p>
                      <p className="text-[11px] text-white/20 mt-1 mb-0 leading-tight font-medium">{data.desc}</p>
                    </div>
                    <Badge color={data.status === 'running' ? 'success' : 'danger'} dot>
                      {data.status === 'running' ? 'RUNNING' : 'STOPPED'}
                    </Badge>
                  </div>
                ))}
                {isSystemLoading && (
                  <div className="text-center py-8 text-white/20 text-[13px] font-medium">
                    Loading workers...
                  </div>
                )}
              </div>
            </Card>
          </div>

          {/* CDN Edge Nodes Health */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-7">
            {systemStatus?.cdn_nodes.map((node) => {
              const countryNames = { SG: 'Singapore', JP: 'Japan', TH: 'Thailand' } as any
              const countryFlags = { SG: '🇸🇬', JP: '🇯🇵', TH: '🇹🇭' } as any
              
              return (
                <Card key={node.region} className="animate-fade-in-up hover:border-white/[0.08] transition-all">
                  <div className="flex justify-between items-start">
                    <div className="flex items-center gap-2.5">
                      <span className="text-[22px]">{countryFlags[node.region] || '🌐'}</span>
                      <div>
                        <h4 className="text-[14px] font-bold text-white/90 m-0 font-heading">
                          {countryNames[node.region] || node.region} Edge
                        </h4>
                        <span className="text-[10px] text-white/20 font-medium">Region: {node.region} | Port: {node.port}</span>
                      </div>
                    </div>
                    <Badge color={node.status === 'online' ? 'success' : 'danger'} dot>
                      {node.status === 'online' ? 'ONLINE' : 'OFFLINE'}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mt-5 pt-4 border-t border-white/[0.04] text-[13px]">
                    <div>
                      <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.08em] m-0">Latency</p>
                      <p className="text-[15px] font-mono font-bold text-white/80 mt-1 mb-0">
                        {node.status === 'online' ? `${node.latency_ms} ms` : '-'}
                      </p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.08em] m-0">Engine</p>
                      <p className={`text-[13px] font-bold mt-1 mb-0 ${node.status === 'online' ? 'text-success/70' : 'text-danger/70'}`}>
                        {node.status === 'online' ? 'Active' : 'Down'}
                      </p>
                    </div>
                  </div>

                  {node.status === 'online' && node.health?.timestamp && (
                    <div className="mt-3.5 pt-2 text-[10px] text-white/15 font-mono bg-white/[0.02] p-2 rounded-lg border border-white/[0.04] truncate font-medium">
                      Health: {new Date(node.health.timestamp).toLocaleTimeString()} ✓
                    </div>
                  )}
                </Card>
              )
            })}
          </div>

          {/* Raw JSON Data Monitor (Developer Mode) */}
          <Card className="animate-fade-in-up stagger-8">
            <div className="flex justify-between items-center mb-4">
              <div>
                <h3 className="text-[14px] font-bold text-white/70 m-0 leading-tight flex items-center gap-2 font-heading">
                  <Terminal size={15} className="text-accent-light/50" />
                  Raw API Output
                </h3>
                <p className="text-[11px] text-white/15 mt-1 mb-0 font-medium">Developer inspection tool</p>
              </div>
              <button
                onClick={() => setShowRawJson(!showRawJson)}
                className="px-3 py-1.5 text-[11px] font-semibold rounded-lg bg-white/[0.03] border border-white/[0.06] text-white/40 hover:bg-white/[0.06] hover:text-white/60 transition-all duration-200"
              >
                {showRawJson ? 'Hide' : 'Show Data'}
              </button>
            </div>

            {showRawJson && (
              <div className="bg-black/30 border border-white/[0.04] rounded-xl p-4 font-mono text-[11px] text-accent-light/30 overflow-x-auto max-h-[300px] animate-scale-in">
                <pre>{JSON.stringify(systemStatus, null, 2)}</pre>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  )
}

export default Dashboard
