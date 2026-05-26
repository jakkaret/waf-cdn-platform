import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { logsApi } from '../api/logs'
import { TopBar } from '../components/layout/TopBar'
import { Card } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { WafLog } from '../types'

export const Logs: React.FC = () => {
  const [filter, setFilter] = useState('')
  const { data: logs = [], isLoading } = useQuery({
    queryKey: ['logs'],
    queryFn: () => logsApi.getRecentLogs(100),
    refetchInterval: 8000,
  })

  const filteredLogs = logs.filter(l => 
    l.ip.includes(filter) || 
    (l.url && l.url.includes(filter)) || 
    (l.rule_id && l.rule_id.includes(filter))
  )

  const getStatusBadge = (status: number) => {
    if (status === 403) return <Badge color="danger">403</Badge>
    if (status >= 500) return <Badge color="warning">{status}</Badge>
    if (status >= 200 && status < 300) return <Badge color="success">{status}</Badge>
    return <Badge>{status}</Badge>
  }

  const getSeverityBadge = (severity?: string | null) => {
    if (!severity) return <Badge color="gray">None</Badge>
    const s = severity.toUpperCase()
    if (s === 'CRITICAL') return <Badge color="danger">{s}</Badge>
    if (s === 'HIGH') return <Badge color="warning">{s}</Badge>
    if (s === 'MEDIUM') return <Badge color="brand">{s}</Badge>
    return <Badge color="success">{s}</Badge>
  }

  return (
    <div>
      <TopBar title="Attack Logs" subtitle="Real-time WAF event viewer" />

      <Card className="mb-6" noPadding>
        <div className="p-4 border-b border-white/5 flex items-center justify-between">
          <input
            type="text"
            placeholder="Search IP, URL, Rule ID..."
            className="bg-bg-surface border border-white/10 rounded-lg px-4 py-2 text-sm text-white w-72 focus:border-accent focus:outline-none"
            value={filter}
            onChange={e => setFilter(e.target.value)}
          />
          <span className="text-text-muted text-sm">{filteredLogs.length} events found</span>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/5 text-text-muted text-[11px] uppercase tracking-wider">
              <tr>
                <th className="p-4 font-semibold">Time</th>
                <th className="p-4 font-semibold">Source IP</th>
                <th className="p-4 font-semibold">Method</th>
                <th className="p-4 font-semibold">URL</th>
                <th className="p-4 font-semibold">Status</th>
                <th className="p-4 font-semibold">Rule ID</th>
                <th className="p-4 font-semibold">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {isLoading ? (
                <tr><td colSpan={7} className="p-8 text-center text-text-muted">Loading logs...</td></tr>
              ) : filteredLogs.length === 0 ? (
                <tr><td colSpan={7} className="p-8 text-center text-text-muted">No logs found</td></tr>
              ) : (
                filteredLogs.map((log: WafLog, i: number) => (
                  <tr key={log.log_id || i} className={`hover:bg-white/5 transition-colors cursor-pointer ${log.status === 403 ? 'bg-danger/5' : ''}`}>
                    <td className="p-4 text-text-muted whitespace-nowrap text-[12px]">{log.datetime}</td>
                    <td className="p-4 font-mono text-[13px]">{log.ip}</td>
                    <td className="p-4"><Badge color="gray">{log.method}</Badge></td>
                    <td className="p-4 max-w-[200px] truncate" title={log.url}>{log.url}</td>
                    <td className="p-4">{getStatusBadge(log.status)}</td>
                    <td className="p-4 font-mono text-[12px] text-text-muted">{log.rule_id || '-'}</td>
                    <td className="p-4">{getSeverityBadge(log.severity)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

export default Logs
