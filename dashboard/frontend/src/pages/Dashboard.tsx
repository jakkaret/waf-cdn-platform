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

  return (
    <div>
      <TopBar 
        title="Dashboard Overview" 
        subtitle="Real-time WAF activity and general status" 
        action={
          <div className="flex gap-2 bg-white/5 p-1 rounded-lg border border-white/10">
            <button
              onClick={() => setActiveTab('security')}
              className={`px-4 py-1.5 text-xs font-semibold rounded-md transition-all ${
                activeTab === 'security'
                  ? 'bg-accent text-white shadow-md'
                  : 'text-text-muted hover:text-text-primary'
              }`}
            >
              Security Overview
            </button>
            <button
              onClick={() => setActiveTab('system')}
              className={`px-4 py-1.5 text-xs font-semibold rounded-md transition-all ${
                activeTab === 'system'
                  ? 'bg-accent text-white shadow-md'
                  : 'text-text-muted hover:text-text-primary'
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
            <div className="mb-6 p-5 rounded-xl border border-accent/20 bg-gradient-to-r from-accent/10 to-brand/5 backdrop-blur-md shadow-lg flex gap-4 items-start relative overflow-hidden">
              <div className="absolute top-0 right-0 p-8 opacity-5 text-accent">
                <Sparkles size={120} />
              </div>
              <div className="p-2.5 rounded-lg bg-accent/20 text-accent-light shrink-0">
                <Sparkles size={22} className="animate-pulse" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <h4 className="text-[14px] font-bold text-accent-light uppercase tracking-wider">WAF AI Security Threat Summary</h4>
                  <Badge color="success">Real-time AI Auditor</Badge>
                </div>
                <p className="text-[13.5px] text-text-primary mt-2 leading-relaxed font-medium">
                  {analytics.ai_summary}
                </p>
                <div className="flex gap-4 mt-3 text-[11px] text-text-muted">
                  <span>Data Source: <b className="text-accent-light capitalize">{analytics.source}</b></span>
                  <span>Average Latency: <b className="text-white">{analytics.average_latency_ms} ms</b></span>
                  <span>WAF Block Rate: <b className="text-danger">{((analytics.blocked_requests / (analytics.total_requests || 1)) * 100).toFixed(1)}%</b></span>
                </div>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard 
              label="Total Requests" 
              value={isAnalyticsLoading ? '-' : (analytics?.total_requests ?? totalRequests)} 
              color="brand"
              icon={<Activity size={20} />}
            />
            <StatCard 
              label="Blocked Requests" 
              value={isAnalyticsLoading ? '-' : (analytics?.blocked_requests ?? blockedCount)} 
              color="danger"
              icon={<ShieldAlert size={20} />}
            />
            <StatCard 
              label="Unique IPs" 
              value={isLogsLoading ? '-' : uniqueIPs} 
              color="info"
              icon={<Globe size={20} />}
            />
            <StatCard 
              label="WAF AI Health Check" 
              value={(analytics?.blocked_requests ?? 0) > 0 ? "Threat Blocked" : "Optimal"} 
              color={(analytics?.blocked_requests ?? 0) > 0 ? "warning" : "success"}
              icon={<ShieldCheck size={20} />}
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            <Card className="lg:col-span-2">
              <CardHeader title="Traffic & Blocks (Last 20 events)" />
              <div className="h-[300px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                    <XAxis dataKey="time" stroke="rgba(255,255,255,0.2)" fontSize={12} tickMargin={10} />
                    <YAxis stroke="rgba(255,255,255,0.2)" fontSize={12} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1a1f36', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                      itemStyle={{ color: '#e4e8f0' }}
                    />
                    <Bar dataKey="allowed" stackId="a" fill="#667eea" radius={[0, 0, 4, 4]} />
                    <Bar dataKey="blocked" stackId="a" fill="#fc8181" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>

            <Card>
              <CardHeader title="AI Attack Type Breakdown" subtitle="Identified ModSecurity blocks in ClickHouse" />
              <div className="space-y-4">
                {analytics && Object.entries(analytics.attack_types).map(([attack, count], i) => (
                  <div key={i} className="flex justify-between items-center pb-3 border-b border-white/5 last:border-0 last:pb-0">
                    <div className="overflow-hidden mr-2">
                      <p className="text-[13.5px] font-bold text-white truncate">{attack}</p>
                      <p className="text-[11.5px] text-text-muted mt-0.5">Matched Rules & Ingress Logs</p>
                    </div>
                    <Badge color="danger">{count} blocks</Badge>
                  </div>
                ))}
                {(!analytics || Object.keys(analytics.attack_types).length === 0) && (
                  <div className="text-center text-text-muted text-sm py-8">No attacks detected</div>
                )}
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            <Card className="lg:col-span-2">
              <CardHeader title="Top Suspicious Host IPs" subtitle="Ranked by volume of security violations" />
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-white/10 text-[11px] font-bold text-text-muted uppercase tracking-[0.5px]">
                      <th className="pb-3">Client IP Address</th>
                      <th className="pb-3">Blocked Requests</th>
                      <th className="pb-3">Total Requests</th>
                      <th className="pb-3 text-right">Violation Ratio</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analytics?.suspicious_ips.map((ip, i) => (
                      <tr key={i} className="border-b border-white/5 last:border-0 text-[13.5px]">
                        <td className="py-3 font-mono font-bold text-white flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-danger" />
                          {ip.ip}
                        </td>
                        <td className="py-3 font-mono text-danger font-bold">{ip.blocked}</td>
                        <td className="py-3 font-mono text-text-muted">{ip.total}</td>
                        <td className="py-3 text-right font-mono text-accent-light font-bold">
                          {((ip.blocked / (ip.total || 1)) * 100).toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                    {(!analytics?.suspicious_ips.length) && (
                      <tr>
                        <td colSpan={4} className="text-center py-8 text-text-muted text-sm">
                          No suspicious traffic records found
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            <Card>
              <CardHeader title="Recent Block Logs" subtitle="Latest firewall activity" />
              <div className="space-y-4">
                {logs.filter(l => l.status === 403 || l.status === 429).slice(0, 5).map((log, i) => (
                  <div key={i} className="flex justify-between items-start pb-3 border-b border-white/5 last:border-0 last:pb-0">
                    <div className="overflow-hidden mr-2">
                      <p className="text-[13px] font-mono text-danger truncate">{log.ip}</p>
                      <p className="text-[11.5px] text-text-muted truncate mt-0.5">{log.url}</p>
                    </div>
                    <Badge color={log.status === 429 ? 'warning' : 'danger'}>
                      {log.status === 429 ? 'LIMIT' : 'WAF'}
                    </Badge>
                  </div>
                ))}
                {logs.filter(l => l.status === 403 || l.status === 429).length === 0 && (
                  <div className="text-center text-text-muted text-sm py-8">No recent blocks</div>
                )}
              </div>
            </Card>
          </div>
        </>
      ) : (
        /* ================== SYSTEM HEALTH MONITOR TAB ================== */
        <>
          {/* Quick Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            {/* Database Status Card */}
            <Card className="flex flex-col justify-between">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[11.5px] font-bold text-text-muted uppercase tracking-[1px]">Database Service</p>
                  <h4 className="text-[20px] font-extrabold text-white mt-1 leading-tight">
                    {isSystemLoading ? 'Loading...' : systemStatus?.db.status === 'online' ? 'Online' : 'Offline'}
                  </h4>
                </div>
                <div className={`p-2.5 rounded-lg ${systemStatus?.db.status === 'online' ? 'bg-success/10 text-success' : 'bg-danger/10 text-danger'}`}>
                  <Database size={20} />
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-white/5 flex items-center gap-1.5 text-[12px] text-text-muted">
                <span className={`w-2 h-2 rounded-full ${systemStatus?.db.status === 'online' ? 'bg-success animate-pulse' : 'bg-danger'}`} />
                <span className="truncate">{systemStatus?.db.detail || 'Checking connection...'}</span>
              </div>
            </Card>

            {/* Disk Usage Card */}
            <Card className="flex flex-col justify-between">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[11.5px] font-bold text-text-muted uppercase tracking-[1px]">System Disk Storage</p>
                  <h4 className="text-[20px] font-extrabold text-white mt-1 leading-tight">
                    {isSystemLoading ? '-' : `${systemStatus?.system.disk_used_gb} / ${systemStatus?.system.disk_total_gb} GB`}
                  </h4>
                </div>
                <div className="p-2.5 rounded-lg bg-info/10 text-info">
                  <HardDrive size={20} />
                </div>
              </div>
              <div className="mt-4">
                <div className="w-full bg-white/5 rounded-full h-1.5 mb-1.5">
                  <div 
                    className={`h-1.5 rounded-full ${
                      (systemStatus?.system.disk_used_percent || 0) > 85 ? 'bg-danger' : 'bg-info'
                    }`} 
                    style={{ width: `${systemStatus?.system.disk_used_percent || 0}%` }}
                  />
                </div>
                <div className="flex justify-between text-[11px] text-text-muted">
                  <span>{systemStatus?.system.disk_used_percent || 0}% Used</span>
                  <span>{systemStatus?.system.disk_free_gb || 0} GB Free</span>
                </div>
              </div>
            </Card>

            {/* Load Average Card */}
            <Card className="flex flex-col justify-between">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[11.5px] font-bold text-text-muted uppercase tracking-[1px]">CPU Load Average</p>
                  <h4 className="text-[20px] font-extrabold text-white mt-1 leading-tight">
                    {isSystemLoading ? '-' : systemStatus?.system.load_average[0].toFixed(2)}
                  </h4>
                </div>
                <div className="p-2.5 rounded-lg bg-brand/10 text-accent-light">
                  <Cpu size={20} />
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-white/5 flex justify-between text-[12px] text-text-muted">
                <span>1 min: <b>{systemStatus?.system.load_average[0].toFixed(2)}</b></span>
                <span>5 min: <b>{systemStatus?.system.load_average[1].toFixed(2)}</b></span>
                <span>15 min: <b>{systemStatus?.system.load_average[2].toFixed(2)}</b></span>
              </div>
            </Card>

            {/* Refresh Monitor Card */}
            <Card className="flex flex-col justify-between hover:border-white/10 transition-colors">
              <div className="flex justify-between items-start">
                <div>
                  <p className="text-[11.5px] font-bold text-text-muted uppercase tracking-[1px]">Monitor Engine</p>
                  <h4 className="text-[14px] font-bold text-white mt-1 leading-tight">
                    Auto-refreshing (5s)
                  </h4>
                </div>
                <button 
                  onClick={() => refetchSystem()} 
                  className={`p-2 rounded-lg bg-white/5 text-text-primary hover:bg-white/10 transition-all ${
                    isSystemRefetching ? 'animate-spin' : ''
                  }`}
                  title="Manual Refresh"
                >
                  <RefreshCw size={16} />
                </button>
              </div>
              <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-[12px] text-text-muted">
                <span>Status: <b className="text-success">Active</b></span>
                <span>Uptime: <b className="text-white">Normal</b></span>
              </div>
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            {/* Core Services Table */}
            <Card className="lg:col-span-2">
              <CardHeader title="Core System Services" subtitle="Status of Docker containers and internal services" />
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="border-b border-white/10 text-[11px] font-bold text-text-muted uppercase tracking-[0.5px]">
                      <th className="pb-3">Service Name</th>
                      <th className="pb-3">Port</th>
                      <th className="pb-3">Description</th>
                      <th className="pb-3 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {systemStatus && Object.entries(systemStatus.services).map(([name, data]) => (
                      <tr key={name} className="border-b border-white/5 last:border-0 text-[13.5px]">
                        <td className="py-3 font-bold text-white flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${data.status === 'online' ? 'bg-success' : 'bg-danger'}`} />
                          {name}
                        </td>
                        <td className="py-3 font-mono text-text-muted text-[12.5px]">{data.port}</td>
                        <td className="py-3 text-text-muted text-[13px]">{data.desc}</td>
                        <td className="py-3 text-right">
                          <Badge color={data.status === 'online' ? 'success' : 'danger'}>
                            {data.status === 'online' ? 'ONLINE' : 'OFFLINE'}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                    {isSystemLoading && (
                      <tr>
                        <td colSpan={4} className="text-center py-8 text-text-muted text-sm">
                          Loading services status...
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </Card>

            {/* Background Workers & Tasks */}
            <Card>
              <CardHeader title="Async Background Workers" subtitle="Internal Python process states" />
              <div className="space-y-5">
                {systemStatus && Object.entries(systemStatus.workers).map(([name, data]) => (
                  <div key={name} className="flex justify-between items-start pb-4 border-b border-white/5 last:border-0 last:pb-0">
                    <div className="mr-4">
                      <p className="text-[13.5px] font-bold text-white m-0 flex items-center gap-1.5">
                        <Activity size={14} className={data.status === 'running' ? 'text-success animate-pulse' : 'text-text-muted'} />
                        {name}
                      </p>
                      <p className="text-[12px] text-text-muted mt-1 mb-0 leading-tight">{data.desc}</p>
                    </div>
                    <Badge color={data.status === 'running' ? 'success' : 'danger'}>
                      {data.status === 'running' ? 'RUNNING' : 'STOPPED'}
                    </Badge>
                  </div>
                ))}
                {isSystemLoading && (
                  <div className="text-center py-8 text-text-muted text-sm">
                    Loading worker states...
                  </div>
                )}
              </div>
            </Card>
          </div>

          {/* CDN Edge Nodes Health */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            {systemStatus?.cdn_nodes.map((node) => {
              const countryNames = { SG: 'Singapore', JP: 'Japan', TH: 'Thailand' } as any
              const countryFlags = { SG: '🇸🇬', JP: '🇯🇵', TH: '🇹🇭' } as any
              
              return (
                <Card key={node.region} className="border border-white/5 hover:border-white/10 transition-all">
                  <div className="flex justify-between items-start">
                    <div className="flex items-center gap-2.5">
                      <span className="text-[24px]">{countryFlags[node.region] || '🌐'}</span>
                      <div>
                        <h4 className="text-[14.5px] font-bold text-white m-0">
                          {countryNames[node.region] || node.region} Edge
                        </h4>
                        <span className="text-[11.5px] text-text-muted">Region: {node.region} | Port: {node.port}</span>
                      </div>
                    </div>
                    <Badge color={node.status === 'online' ? 'success' : 'danger'} dot>
                      {node.status === 'online' ? 'ONLINE' : 'OFFLINE'}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mt-5 pt-4 border-t border-white/5 text-[13px]">
                    <div>
                      <p className="text-[11px] font-bold text-text-muted uppercase tracking-[0.5px] m-0">Latency</p>
                      <p className="text-[15px] font-mono font-bold text-white mt-1 mb-0">
                        {node.status === 'online' ? `${node.latency_ms} ms` : '-'}
                      </p>
                    </div>
                    <div>
                      <p className="text-[11px] font-bold text-text-muted uppercase tracking-[0.5px] m-0">Engine State</p>
                      <p className={`text-[13px] font-bold mt-1 mb-0 ${node.status === 'online' ? 'text-success' : 'text-danger'}`}>
                        {node.status === 'online' ? 'Active' : 'Down'}
                      </p>
                    </div>
                  </div>

                  {node.status === 'online' && node.health?.timestamp && (
                    <div className="mt-3.5 pt-2 text-[10.5px] text-text-muted font-mono bg-white/5 p-2 rounded border border-white/5 truncate">
                      Health Check: {new Date(node.health.timestamp).toLocaleTimeString()} OK
                    </div>
                  )}
                </Card>
              )
            })}
          </div>

          {/* Raw JSON Data Monitor (Developer Mode) */}
          <Card>
            <div className="flex justify-between items-center mb-4">
              <div>
                <h3 className="text-[15px] font-bold text-text-primary m-0 leading-tight flex items-center gap-2">
                  <Terminal size={16} className="text-accent-light" />
                  Raw API Output (Developer inspection tool)
                </h3>
                <p className="text-[12px] text-text-muted mt-1 mb-0">Collapsible inspectable JSON packet</p>
              </div>
              <button
                onClick={() => setShowRawJson(!showRawJson)}
                className="px-3.5 py-1.5 text-xs font-semibold rounded bg-white/5 border border-white/10 text-white hover:bg-white/10 transition-colors"
              >
                {showRawJson ? 'Hide Raw Data' : 'Show Raw Data'}
              </button>
            </div>

            {showRawJson && (
              <div className="bg-black/40 border border-white/10 rounded-lg p-4 font-mono text-[11px] text-[#869ab8] overflow-x-auto max-h-[300px]">
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
