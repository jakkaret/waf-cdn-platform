import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { publicStatusApi, StatusComponent } from '../api/publicStatus'
import { ThemeToggle } from '../components/ui/ThemeToggle'
import { Shield, CheckCircle2, AlertTriangle, HelpCircle, Info } from 'lucide-react'

const STATUS_META: Record<StatusComponent['status'], { label: string; color: string; dot: string }> = {
  operational: { label: 'Operational', color: 'text-emerald-600 dark:text-emerald-400', dot: 'bg-emerald-500' },
  degraded: { label: 'Degraded', color: 'text-red-600 dark:text-red-400', dot: 'bg-red-500' },
  unknown: { label: 'Unknown', color: 'text-[var(--text-muted)]', dot: 'bg-[var(--text-muted)]' },
}

const dayColor = (pct: number | null): string => {
  if (pct === null) return 'bg-[var(--bg-border)]'
  if (pct >= 99.9) return 'bg-emerald-500'
  if (pct >= 95) return 'bg-yellow-500'
  return 'bg-red-500'
}

export const StatusPage: React.FC = () => {
  const { data: status, isLoading } = useQuery({
    queryKey: ['public-status'],
    queryFn: publicStatusApi.getStatus,
    refetchInterval: 30_000, // matches the backend's own 30s snapshot cache
  })

  const { data: history } = useQuery({
    queryKey: ['public-status-history'],
    queryFn: () => publicStatusApi.getHistory(90),
    staleTime: 5 * 60_000,
  })

  const overall = status?.overall_status ?? 'unknown'
  const overallMeta = STATUS_META[overall]

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-[var(--text-primary)]">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-10 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-orange-500/10 text-orange-500 flex items-center justify-center">
              <Shield size={18} />
            </div>
            <div>
              <h1 className="text-[16px] font-bold font-mono m-0">CloudWAF Status</h1>
              <p className="text-[11px] text-[var(--text-muted)] font-mono m-0">
                Live health of the WAF + CDN platform
              </p>
            </div>
          </div>
          <ThemeToggle />
        </div>

        {/* Overall banner */}
        <div
          className={`dash-card p-5 flex items-center gap-3 border-l-4 ${
            overall === 'operational'
              ? 'border-l-emerald-500'
              : overall === 'degraded'
              ? 'border-l-red-500'
              : 'border-l-[var(--bg-border)]'
          }`}
        >
          {overall === 'operational' ? (
            <CheckCircle2 size={22} className="text-emerald-500 shrink-0" />
          ) : overall === 'degraded' ? (
            <AlertTriangle size={22} className="text-red-500 shrink-0" />
          ) : (
            <HelpCircle size={22} className="text-[var(--text-muted)] shrink-0" />
          )}
          <div>
            <div className={`font-mono font-bold text-[14px] ${overallMeta.color}`}>
              {isLoading
                ? 'Checking...'
                : overall === 'operational'
                ? 'All systems operational'
                : overall === 'degraded'
                ? 'Some systems are degraded'
                : 'Status unknown'}
            </div>
            {status?.checked_at && (
              <div className="text-[10.5px] text-[var(--text-muted)] font-mono">
                Last checked: {new Date(status.checked_at).toLocaleString()}
              </div>
            )}
          </div>
        </div>

        {/* Component list */}
        <div className="dash-card divide-y divide-[var(--bg-border)]">
          {(status?.components ?? []).map((c) => {
            const meta = STATUS_META[c.status]
            const days = history?.[c.id] ?? []
            return (
              <div key={c.id} className="p-4 space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${meta.dot}`} />
                    <span className="font-mono font-semibold text-[13px]">{c.name}</span>
                  </div>
                  <span className={`font-mono text-[11.5px] font-bold ${meta.color}`}>{meta.label}</span>
                </div>
                {days.length > 0 && (
                  <div className="flex items-end gap-[2px]" title="Last 90 days">
                    {days.map((d) => (
                      <div
                        key={d.date}
                        title={`${d.date}: ${d.uptime_pct === null ? 'no data' : `${d.uptime_pct}% uptime`}`}
                        className={`h-6 flex-1 rounded-[1.5px] ${dayColor(d.uptime_pct)}`}
                      />
                    ))}
                  </div>
                )}
              </div>
            )
          })}
          {isLoading && (
            <div className="p-6 text-center text-[12px] text-[var(--text-muted)] font-mono">Loading...</div>
          )}
        </div>

        {/* About this page */}
        <div className="dash-card p-4 space-y-1.5 text-[11.5px] font-mono text-[var(--text-secondary)] leading-relaxed">
          <div className="flex items-center gap-1.5 font-bold text-[var(--text-primary)]">
            <Info size={13} className="text-sky-500" />
            <span>เกี่ยวกับหน้านี้</span>
          </div>
          <p className="m-0">
            หน้านี้เช็คสถานะจริงของแต่ละ component ทุก 30 วินาที (cache กันยิง health check ถี่เกินไป) แถบสี่เหลี่ยมด้านล่าง
            แต่ละแถวคือ uptime ย้อนหลัง 90 วัน สีเขียว = uptime ≥99.9% เหลือง = มีสะดุดบ้าง แดง = มีปัญหาชัดเจน เทา = ยังไม่มีข้อมูลวันนั้น
            (ระบบเพิ่งเริ่มเก็บ history วันนี้ ข้อมูลย้อนหลังจะค่อยๆ เต็มขึ้นเรื่อยๆ)
          </p>
        </div>
      </div>
    </div>
  )
}

export default StatusPage
