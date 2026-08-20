import React, { useEffect, useState } from 'react'
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
  RefreshCw,
} from 'lucide-react'
import toast from 'react-hot-toast'

export const Alerts: React.FC = () => {
  const queryClient = useQueryClient()
  const [code, setCode] = useState<string | null>(null)
  const [botUsername, setBotUsername] = useState<string>('WAF_Project_Bot')
  const [copiedCode, setCopiedCode] = useState(false)

  const { data: status, isLoading: isStatusLoading } = useQuery({
    queryKey: ['telegram-status'],
    queryFn: alertsApi.getConnectionStatus,
    refetchInterval: code ? 3000 : false,
  })

  const { data: alerts = [], isLoading: isAlertsLoading, refetch: refetchAlerts } = useQuery({
    queryKey: ['alerts'],
    queryFn: () => alertsApi.getAlerts(50),
    refetchInterval: 10000,
  })

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

  const disconnectMutation = useMutation({
    mutationFn: alertsApi.disconnect,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
      toast.success('Disconnected from Telegram Alert Bot')
    },
  })

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

  return (
    <div className="space-y-6 animate-fade-in">
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
      />

      {/* Telegram Bot Integration Card */}
      <div className="dash-card p-5 sm:p-6 border-l-2 border-l-[#229ed9] bg-gradient-to-r from-[#229ed9]/[0.05] via-transparent to-transparent">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-5">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-[#229ed9]/15 border border-[#229ed9]/30 flex items-center justify-center text-[#229ed9] shrink-0">
              <Send size={22} />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                  Telegram Incident Bot
                </h3>
                <Badge color={status?.connected ? 'success' : 'warning'} size="sm">
                  {status?.connected ? 'ACTIVE DISPATCH' : 'DISCONNECTED'}
                </Badge>
              </div>
              <p className="text-[12.5px] text-[var(--text-secondary)] m-0 mt-1">
                Receive instant alerts for SQL Injection, High-Paranoia attacks, and IP blacklist triggers.
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

      {/* Incident Alerts Table */}
      <div className="dash-card overflow-hidden">
        <div className="dash-card-header">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className="text-red-500" />
            <h3>Recent Dispatched Alerts</h3>
          </div>
          <span className="text-[11px] font-mono text-[var(--text-muted)]">Latest 50 incidents</span>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Source IP</th>
                <th>Target URI</th>
                <th>Status</th>
                <th>Detection Reason</th>
                <th className="text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {isAlertsLoading ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    <RefreshCw size={16} className="animate-spin inline mr-2 text-orange-500" />
                    Fetching incident alert history...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    <CheckCircle2 size={24} className="mx-auto mb-2 text-emerald-500 opacity-60" />
                    No security incident alerts recorded yet.
                  </td>
                </tr>
              ) : (
                alerts.map((a, i) => (
                  <tr key={a.alert_id || i} className="hover:bg-[var(--bg-hover)]">
                    <td>
                      <span className="font-mono font-bold text-[11px] text-[var(--text-muted)]">
                        {a.alert_id || `#ALT-${i + 1}`}
                      </span>
                    </td>
                    <td>
                      <span className="font-mono font-bold text-[12px] text-[var(--text-primary)]">
                        {a.ip}
                      </span>
                    </td>
                    <td className="font-mono text-[11.5px] max-w-[240px] truncate" title={a.url}>
                      {a.url}
                    </td>
                    <td>
                      <Badge color="danger">{a.status}</Badge>
                    </td>
                    <td>
                      <span className="text-[12px] text-[var(--text-secondary)]">
                        {a.message}
                      </span>
                    </td>
                    <td className="text-right font-mono text-[11px] text-[var(--text-muted)] whitespace-nowrap">
                      {new Date(a.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Alerts
