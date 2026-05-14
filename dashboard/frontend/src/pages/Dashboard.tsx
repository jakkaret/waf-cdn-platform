import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { TopBar } from '../components/layout/TopBar'
import { StatCard } from '../components/ui/StatCard'
import { Card, CardHeader } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { ShieldAlert, Activity, Globe, Ban } from 'lucide-react'

export const Dashboard: React.FC = () => {
  const { data: logs = [], isLoading } = useQuery({
    queryKey: ['logs-dashboard'],
    queryFn: () => logsApi.getRecentLogs(200),
    refetchInterval: 10000,
  })

  // Basic stats calc
  const blockedCount = logs.filter(l => l.status === 403).length
  const totalRequests = logs.length
  const uniqueIPs = new Set(logs.map(l => l.ip)).size
  
  // Format for chart (group by hour/min roughly)
  const chartData = logs.reduce((acc, log) => {
    const time = new Date(log.datetime).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const existing = acc.find((d: any) => d.time === time)
    if (existing) {
      if (log.status === 403) existing.blocked++
      else existing.allowed++
    } else {
      acc.push({ time, blocked: log.status === 403 ? 1 : 0, allowed: log.status !== 403 ? 1 : 0 })
    }
    return acc
  }, [] as any[]).slice(-20) // last 20 data points

  return (
    <div>
      <TopBar 
        title="Dashboard Overview" 
        subtitle="Real-time WAF activity and general status" 
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard 
          label="Total Requests" 
          value={isLoading ? '-' : totalRequests} 
          color="brand"
          icon={<Activity size={20} />}
        />
        <StatCard 
          label="Blocked Requests" 
          value={isLoading ? '-' : blockedCount} 
          color="danger"
          icon={<ShieldAlert size={20} />}
        />
        <StatCard 
          label="Unique IPs" 
          value={isLoading ? '-' : uniqueIPs} 
          color="info"
          icon={<Globe size={20} />}
        />
        <StatCard 
          label="System Health" 
          value="Optimal" 
          color="success"
          icon={<Activity size={20} />}
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
          <CardHeader title="Recent Blocks" />
          <div className="space-y-4">
            {logs.filter(l => l.status === 403).slice(0, 5).map((log, i) => (
              <div key={i} className="flex justify-between items-center pb-3 border-b border-white/5 last:border-0">
                <div className="overflow-hidden">
                  <p className="text-[13px] font-mono text-danger truncate">{log.ip}</p>
                  <p className="text-[11.5px] text-text-muted truncate">{log.url}</p>
                </div>
                <Badge color="danger">WAF</Badge>
              </div>
            ))}
            {blockedCount === 0 && (
              <div className="text-center text-text-muted text-sm py-4">No recent blocks</div>
            )}
          </div>
        </Card>
      </div>
    </div>
  )
}

export default Dashboard
