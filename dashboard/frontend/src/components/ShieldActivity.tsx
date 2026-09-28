import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getShieldEvents } from '../api/shieldEvents'
import { Badge } from './ui/Badge'
import { LoadingSpinner } from './ui/LoadingSpinner'

const RANGES = [
  { hours: 24, label: '24h' },
  { hours: 24 * 7, label: '7d' },
  { hours: 24 * 30, label: '30d' },
]

// Which outcomes read as a problem (wrong codes, blocked scripts) vs normal.
const BAD = new Set(['blocked_no_clearance', 'otp_wrong_code', 'otp_too_many_attempts', 'otp_rate_limited', 'otp_send_failed', 'otp_not_allowed'])

export const ShieldActivity: React.FC<{ originId: string }> = ({ originId }) => {
  const [hours, setHours] = useState(24)
  const { data, isLoading, isError } = useQuery({
    queryKey: ['shield-events', originId, hours],
    queryFn: async () => (await getShieldEvents(originId, hours)).data,
    refetchInterval: 30000,
  })

  return (
    <div className="dash-card p-5 space-y-4">
      <div className="flex justify-between items-center pb-3 border-b border-[var(--bg-border-subtle)]">
        <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">Shield Activity</h3>
        <div className="flex gap-1" role="group" aria-label="Time range">
          {RANGES.map((r) => (
            <button
              key={r.hours}
              onClick={() => setHours(r.hours)}
              aria-pressed={hours === r.hours}
              className={`px-2.5 py-1 rounded font-mono text-[11px] cursor-pointer border ${
                hours === r.hours
                  ? 'border-orange-500 text-orange-500'
                  : 'border-[var(--bg-border)] text-[var(--text-muted)]'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <LoadingSpinner />
      ) : isError || !data ? (
        <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">Activity is unavailable right now.</p>
      ) : (
        <>
          {data.counts.length === 0 ? (
            <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">No CAPTCHA/OTP activity in this period.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {data.counts
                .slice()
                .sort((a, b) => b.count - a.count)
                .map((c) => (
                  <div
                    key={`${c.kind}-${c.event}`}
                    className="px-3 py-2 rounded-md border border-[var(--bg-border-subtle)] font-mono"
                  >
                    <div className="text-[10.5px] uppercase text-[var(--text-muted)]">
                      {c.kind} · {c.label}
                    </div>
                    <div className={`text-[18px] font-bold ${BAD.has(c.event) ? 'text-red-500' : 'text-[var(--text-primary)]'}`}>
                      {c.count}
                    </div>
                  </div>
                ))}
            </div>
          )}

          {data.recent.length > 0 && (
            <div className="overflow-x-auto">
              <table className="dash-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Email</th>
                    <th>Client IP</th>
                    <th>Path</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent.map((e, i) => (
                    <tr key={`${e.timestamp}-${i}`}>
                      <td className="font-mono text-[11.5px] whitespace-nowrap">
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td>
                        <Badge color={BAD.has(e.event) ? 'danger' : e.event === 'otp_verified' ? 'success' : 'gray'}>
                          {e.kind.toUpperCase()} · {e.label}
                        </Badge>
                      </td>
                      <td className="font-mono text-[11.5px]">{e.email || '—'}</td>
                      <td className="font-mono text-[11.5px]">{e.client_ip}</td>
                      <td className="font-mono text-[11.5px] max-w-[200px] truncate">{e.path || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="text-[11px] text-[var(--text-muted)] font-mono m-0">
            Emails are shown masked; the full address is never stored.
          </p>
        </>
      )}
    </div>
  )
}
