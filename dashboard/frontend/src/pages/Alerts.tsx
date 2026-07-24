import React, { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { alertsApi } from '../api/alerts'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import toast from 'react-hot-toast'

export const Alerts: React.FC = () => {
  const queryClient = useQueryClient()
  const [code, setCode] = useState<string | null>(null)
  const [botUsername, setBotUsername] = useState<string>('WAF_Project_Bot')

  const { data: status, isLoading: isStatusLoading } = useQuery({
    queryKey: ['telegram-status'],
    queryFn: alertsApi.getConnectionStatus,
    refetchInterval: code ? 3000 : false // poll if we have a code
  })

  const { data: alerts = [], isLoading: isAlertsLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => alertsApi.getAlerts(50),
    refetchInterval: 10000
  })

  const connectMutation = useMutation({
    mutationFn: alertsApi.startConnection,
    onSuccess: (data) => {
      setCode(data.code)
      if (data.bot_username) {
        setBotUsername(data.bot_username)
      }
      toast.success('Connection started! Send code to the bot.')
    },
    onError: () => toast.error('Failed to start connection')
  })

  const disconnectMutation = useMutation({
    mutationFn: alertsApi.disconnect,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
      toast.success('Disconnected from Telegram')
    }
  })

  // Poll for connection success manually if query doesn't catch it fast enough
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>
    if (code) {
      interval = setInterval(async () => {
        try {
          const res = await alertsApi.pollConnection(code)
          if (res.status === 'connected') {
            setCode(null)
            queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
            toast.success('Telegram Connected!')
          } else if (res.status === 'expired') {
            setCode(null)
            toast.error('Code expired')
          }
        } catch (e) {
          // ignore
        }
      }, 3000)
    }
    return () => clearInterval(interval)
  }, [code, queryClient])

  return (
    <div>
      <TopBar title="Alerts" subtitle="WAF-triggered alerts forwarded to your Telegram" />

      <div className="bg-gradient-to-br from-[#0d1b2a] to-[#1a2a3a] border border-[#229ed9]/20 rounded-2xl p-7 mb-8 relative overflow-hidden">
        <div className="flex items-center gap-5 flex-wrap relative z-10">
          <div className="w-14 h-14 rounded-xl bg-[#229ed9]/10 border border-[#229ed9]/30 flex items-center justify-center text-[#229ed9]">
            <svg viewBox="0 0 24 24" fill="currentColor" className="w-7 h-7">
              <path d="M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.894 8.221l-1.97 9.28c-.145.658-.537.818-1.084.508l-3-2.21-1.447 1.394c-.16.16-.295.295-.605.295l.213-3.053 5.56-5.023c.242-.213-.054-.333-.373-.12l-6.871 4.326-2.962-.924c-.643-.204-.657-.643.136-.953l11.57-4.461c.537-.194 1.006.131.833.941z" />
            </svg>
          </div>

          <div className="flex-1">
            <h3 className="text-[16px] font-bold text-white m-0">Telegram Alert Bot</h3>
            <p className="text-[13.5px] text-white/50 m-0 mt-1">Receive notifications when WAF detects attacks</p>
            <div className="mt-2 text-sm font-medium">
              {status?.connected ? (
                <span className="text-success flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-success animate-pulse-dot"></span>
                  Connected {status.chat_id && `(Chat ID: ${status.chat_id})`}
                </span>
              ) : (
                <span className="text-warning flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-warning"></span>
                  Not Connected
                </span>
              )}
            </div>
          </div>

          <div className="flex gap-3">
            {!status?.connected && !code && (
              <Button onClick={() => connectMutation.mutate()} isLoading={connectMutation.isPending} className="bg-[#229ed9] hover:bg-[#1a8bbf] border-none text-white shadow-lg">
                Connect Telegram
              </Button>
            )}
            {status?.connected && (
              <Button variant="outline" className="border-danger/30 text-danger hover:bg-danger/10" onClick={() => disconnectMutation.mutate()}>
                Disconnect
              </Button>
            )}
          </div>
        </div>

        {code && (
          <div className="mt-6 pt-6 border-t border-white/10 relative z-10 animate-fade-in">
            <h4 className="text-sm font-bold text-white mb-2">Step 1: Copy this code</h4>
            <div className="flex items-center gap-4 mb-4">
              <div className="font-mono text-2xl font-bold tracking-widest text-[#229ed9] bg-[#229ed9]/10 border border-[#229ed9]/20 px-6 py-2 rounded-lg">
                {code}
              </div>
            </div>
            <h4 className="text-sm font-bold text-white mb-2">Step 2: Send code to bot</h4>
            <a href={`https://t.me/${botUsername}?start=${code}`} target="_blank" rel="noreferrer" className="text-[#229ed9] text-sm hover:underline">
              Open Telegram Bot →
            </a>
            <div className="mt-4 text-sm text-text-muted flex items-center gap-2">
              <svg className="animate-spin w-4 h-4 text-[#229ed9]" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>
              Waiting for confirmation from Telegram...
            </div>
          </div>
        )}
      </div>

  <Card noPadding>
    <CardHeader title="Recent Alerts" className="p-6 border-b border-white/5 mb-0" />
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="bg-white/5 text-text-muted text-[11px] uppercase tracking-wider">
          <tr>
            <th className="p-4 font-semibold">Alert ID</th>
            <th className="p-4 font-semibold">Source IP</th>
            <th className="p-4 font-semibold">URL</th>
            <th className="p-4 font-semibold">Status</th>
            <th className="p-4 font-semibold">Message</th>
            <th className="p-4 font-semibold">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-white/5">
          {isAlertsLoading ? (
            <tr><td colSpan={6} className="p-8 text-center text-text-muted">Loading alerts...</td></tr>
          ) : alerts.length === 0 ? (
            <tr><td colSpan={6} className="p-8 text-center text-text-muted">No alerts yet</td></tr>
          ) : (
            alerts.map((a, i) => (
              <tr key={a.alert_id || i} className="hover:bg-white/5 transition-colors">
                <td className="p-4 font-mono text-[11px] text-text-muted">{a.alert_id}</td>
                <td className="p-4 font-mono">{a.ip}</td>
                <td className="p-4 max-w-[200px] truncate" title={a.url}>{a.url}</td>
                <td className="p-4"><Badge color="danger">{a.status}</Badge></td>
                <td className="p-4 text-text-muted">{a.message}</td>
                <td className="p-4 text-[12px] text-text-muted whitespace-nowrap">{new Date(a.timestamp).toLocaleString()}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  </Card>
    </div >
  )
}

export default Alerts
