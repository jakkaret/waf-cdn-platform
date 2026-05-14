import React, { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { cdnApi } from '../api/cdn'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader } from '../components/ui/Card'
import { StatCard } from '../components/ui/StatCard'
import { HealthDot } from '../components/ui/HealthDot'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { BarChart, Bar, PieChart, Pie, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, Legend, LineChart, Line } from 'recharts'
import { Activity, Globe, Ban, HardDrive, Trash2, Clock } from 'lucide-react'
import toast from 'react-hot-toast'

export const CDN: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const [purgePattern, setPurgePattern] = useState('/*')
  
  // Real-time polling
  const { data: nodes = [], isLoading: isLoadingNodes } = useQuery({
    queryKey: ['cdn-nodes'],
    queryFn: cdnApi.getNodes,
    refetchInterval: 10000,
  })

  const { data: stats = [], isLoading: isLoadingStats } = useQuery({
    queryKey: ['cdn-stats'],
    queryFn: cdnApi.getStats,
    refetchInterval: 10000,
  })

  const purgeMutation = useMutation({
    mutationFn: (pattern: string) => cdnApi.purgeCache('cdn-secret-token', pattern),
    onSuccess: () => toast.success('Purge command sent successfully'),
    onError: () => toast.error('Failed to purge cache')
  })

  const { data: latencyData, isLoading: isLoadingLatency } = useQuery({
    queryKey: ['cdn-latency'],
    queryFn: () => cdnApi.getLatency('ALL', '1h'),
    refetchInterval: 10000,
  })

  // Aggregation
  const totalRequests = stats.reduce((sum, s) => sum + s.request_count, 0)
  const totalHits = stats.reduce((sum, s) => sum + s.cache_hit, 0)
  const totalMisses = stats.reduce((sum, s) => sum + s.cache_miss, 0)
  const totalBypass = stats.reduce((sum, s) => sum + s.cache_bypass, 0)
  const totalBlocked = stats.reduce((sum, s) => sum + s.blocked_count, 0)
  const hitRatio = totalRequests > 0 ? ((totalHits / (totalRequests - totalBlocked - totalBypass)) * 100).toFixed(1) : 0
  const avgLatency = stats.length > 0 ? (stats.reduce((sum, s) => sum + s.avg_latency, 0) / stats.length).toFixed(0) : 0

  const pieData = [
    { name: 'HIT', value: totalHits, color: '#68d391' },
    { name: 'MISS', value: totalMisses, color: '#f6ad55' },
    { name: 'BYPASS', value: totalBypass, color: '#76e4f7' }
  ].filter(d => d.value > 0)

  return (
    <div>
      <TopBar 
        title="CDN Monitor" 
        subtitle="Global edge node status and caching performance"
      />

      {/* Global Aggregated Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard 
          label="Cache Hit Rate" 
          value={`${hitRatio}%`} 
          color="success"
          icon={<HardDrive size={20} />}
        />
        <StatCard 
          label="Total Requests" 
          value={totalRequests} 
          color="brand"
          icon={<Globe size={20} />}
        />
        <StatCard 
          label="Global Avg Latency" 
          value={`${avgLatency} ms`} 
          color="info"
          icon={<Activity size={20} />}
        />
        <StatCard 
          label="Blocked at Edge" 
          value={totalBlocked} 
          color="danger"
          icon={<Ban size={20} />}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Node Status Board */}
        <Card className="lg:col-span-1">
          <CardHeader title="Edge Nodes" subtitle="Real-time health status" />
          <div className="space-y-4">
            {isLoadingNodes ? (
              <div className="text-center text-text-muted">Checking nodes...</div>
            ) : nodes.length === 0 ? (
              <div className="text-center text-text-muted">No nodes found</div>
            ) : (
              nodes.map(node => (
                <div key={node.region} className="flex justify-between items-center p-3 bg-white/5 rounded-lg border border-white/5">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">{node.flag || '🌍'}</span>
                    <div>
                      <p className="text-[14px] font-bold m-0">{node.name || node.region}</p>
                      <p className="text-[11px] text-text-muted m-0 uppercase tracking-wider">PORT {node.port}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[12px] font-medium text-text-muted capitalize">{node.status}</span>
                    <HealthDot status={node.status} />
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>

        {/* Charts */}
        <Card className="lg:col-span-2">
          <CardHeader title="Traffic by Region & Cache Status" />
          <div className="h-[250px] flex gap-4">
            <div className="flex-1">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={stats} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <XAxis dataKey="region" stroke="rgba(255,255,255,0.2)" fontSize={12} />
                  <YAxis stroke="rgba(255,255,255,0.2)" fontSize={12} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1a1f36', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                    itemStyle={{ color: '#e4e8f0' }}
                    cursor={{ fill: 'rgba(255,255,255,0.05)' }}
                  />
                  <Bar dataKey="request_count" name="Requests" fill="#667eea" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="blocked_count" name="Blocked" fill="#fc8181" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="w-[200px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1a1f36', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-col gap-2 mt-2 px-4">
                {pieData.map(d => (
                  <div key={d.name} className="flex justify-between items-center text-[11px] font-bold">
                    <span className="flex items-center gap-1.5 text-text-muted">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }}></span>
                      {d.name}
                    </span>
                    <span>{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Latency Section */}
      <div className="mb-8">
        <h3 className="text-[16px] font-bold text-text-primary mb-4 flex items-center gap-2">
          <Clock size={18} className="text-accent" />
          Response Time (Latency)
        </h3>
        
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <Card className="lg:col-span-3">
            <CardHeader title="Latency Trend (ms)" subtitle="Real-time request processing time across regions" />
            <div className="h-[250px]">
              {isLoadingLatency ? (
                <div className="w-full h-full flex items-center justify-center text-text-muted">Loading latency data...</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={latencyData?.timeseries || []} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                    <XAxis dataKey="time" stroke="rgba(255,255,255,0.2)" fontSize={12} />
                    <YAxis stroke="rgba(255,255,255,0.2)" fontSize={12} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: '#1a1f36', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                      itemStyle={{ color: '#e4e8f0' }}
                    />
                    <Legend iconType="circle" wrapperStyle={{ fontSize: '12px' }} />
                    <Line type="monotone" dataKey="SG" name="Singapore (SG)" stroke="#fc8181" strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="JP" name="Japan (JP)" stroke="#667eea" strokeWidth={2} dot={false} />
                    <Line type="monotone" dataKey="TH" name="Thailand (TH)" stroke="#68d391" strokeWidth={2} dot={false} />
                  </LineChart>
                </ResponsiveContainer>
              )}
            </div>
          </Card>

          <div className="flex flex-col gap-4">
            {latencyData?.summary?.map(sum => (
              <Card key={sum.region} noPadding className="flex-1 flex flex-col justify-center p-4">
                <div className="flex justify-between items-center mb-2">
                  <span className="font-bold text-[14px]">{sum.region} Node</span>
                  <Badge color={sum.p95_ms > 200 ? 'danger' : sum.p95_ms > 100 ? 'warning' : 'success'}>
                    {sum.avg_ms} ms avg
                  </Badge>
                </div>
                <div className="flex justify-between text-[12px] text-text-muted mt-2">
                  <span>95th Percentile:</span>
                  <span className="font-mono text-white">{sum.p95_ms} ms</span>
                </div>
                <div className="flex justify-between text-[12px] text-text-muted mt-1">
                  <span>99th Percentile:</span>
                  <span className="font-mono text-white">{sum.p99_ms} ms</span>
                </div>
              </Card>
            ))}
            {!latencyData?.summary?.length && !isLoadingLatency && (
              <Card className="flex-1 flex items-center justify-center text-text-muted text-sm">
                No latency data available
              </Card>
            )}
          </div>
        </div>
      </div>

      {isAdmin && (
        <Card className="mb-8 border-warning/20 bg-warning/5">
          <CardHeader title="Cache Management (Admin)" subtitle="Force purge cached assets across all edge nodes" />
          <div className="flex gap-4 items-center">
            <input 
              type="text" 
              className="flex-1 bg-bg-surface border border-white/10 rounded-lg px-4 py-2.5 text-sm outline-none focus:border-warning"
              placeholder="Path to purge (e.g. /* or /images/*)"
              value={purgePattern}
              onChange={e => setPurgePattern(e.target.value)}
            />
            <Button 
              variant="outline" 
              className="border-warning/30 text-warning hover:bg-warning/10 whitespace-nowrap"
              icon={<Trash2 size={16} />}
              onClick={() => {
                if(window.confirm(`Purge cache for ${purgePattern}?`)) purgeMutation.mutate(purgePattern)
              }}
              isLoading={purgeMutation.isPending}
            >
              Purge Cache
            </Button>
          </div>
        </Card>
      )}

    </div>
  )
}

export default CDN
