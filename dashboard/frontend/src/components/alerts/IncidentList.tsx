import React, { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { ChevronDown, ShieldAlert } from 'lucide-react'
import { alertsApi } from '../../api/alerts'
import { Badge } from '../ui/Badge'
import { ReportText } from '../ai/ReportText'
import { Incident, attackTypeLabel, incidentMinutes, incidentSite, incidentTypes, incidentWhen } from '../../lib/incidents'

// Attack incidents for the Alert Center. A Telegram message links here with
// ?incident=<id>, which opens that incident even when it is older than the list.

const Detail: React.FC<{ inc: Incident }> = ({ inc }) => (
  <div className="grid gap-3 sm:grid-cols-3 px-4 pb-4 text-[12.5px]">
    <div className="min-w-0">
      <div className="text-[11px] text-[var(--text-muted)] mb-1">IP ที่ยิงมากสุด</div>
      <ul className="m-0 p-0 list-none space-y-0.5">
        {inc.top_ips.map(([ip, n]) => (
          <li key={ip} className="flex justify-between gap-2">
            <code className="font-mono break-all">{ip}</code>
            <span className="text-[var(--text-muted)] tabular-nums shrink-0">{n.toLocaleString()}</span>
          </li>
        ))}
      </ul>
      <Link to="/ip-rules" className="inline-block mt-1.5 text-orange-600 dark:text-orange-400 hover:underline">
        ไปหน้า IP access เพื่อบล็อก IP
      </Link>
    </div>
    <div className="min-w-0">
      <div className="text-[11px] text-[var(--text-muted)] mb-1">ประเภท</div>
      <ul className="m-0 p-0 list-none space-y-0.5">
        {inc.top_types.map(([t, n]) => (
          <li key={t} className="flex justify-between gap-2">
            <span className="min-w-0">{attackTypeLabel(t)}</span>
            <span className="text-[var(--text-muted)] tabular-nums shrink-0">{n.toLocaleString()}</span>
          </li>
        ))}
      </ul>
    </div>
    <div className="min-w-0">
      <div className="text-[11px] text-[var(--text-muted)] mb-1">path ที่ถูกเล็ง</div>
      <ul className="m-0 p-0 list-none space-y-0.5">
        {inc.top_paths.map(([p, n]) => (
          <li key={p} className="flex justify-between gap-2">
            <code className="font-mono break-all">{p}</code>
            <span className="text-[var(--text-muted)] tabular-nums shrink-0">{n.toLocaleString()}</span>
          </li>
        ))}
      </ul>
    </div>
    {inc.summary && (
      <div className="sm:col-span-3 rounded-md border border-[var(--bg-border)] bg-[var(--bg-primary)] p-3">
        <div className="text-[11px] text-[var(--text-muted)] mb-1">{inc.summary_by_ai ? 'สรุปโดย AI' : 'สรุป'}</div>
        <ReportText text={inc.summary} className="text-[12.5px]" />
      </div>
    )}
  </div>
)

export const IncidentList: React.FC = () => {
  const [searchParams] = useSearchParams()
  const linked = searchParams.get('incident')
  const [open, setOpen] = useState<string | null>(linked)
  useEffect(() => setOpen(linked), [linked])

  const { data: incidents = [], isLoading } = useQuery({
    queryKey: ['alert-incidents'],
    queryFn: () => alertsApi.getIncidents({ limit: 10 }),
    refetchInterval: 30000,
  })
  const { data: linkedRows = [] } = useQuery({
    queryKey: ['alert-incident', linked],
    queryFn: () => alertsApi.getIncidents({ incident: linked as string }),
    enabled: Boolean(linked) && !incidents.some((i) => i.incident_id === linked),
  })
  const rows = [...linkedRows.filter((l) => !incidents.some((i) => i.incident_id === l.incident_id)), ...incidents]
  const ongoing = rows.filter((i) => !i.closed_at)

  return (
    <div className="dash-card overflow-hidden mt-3.5">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-[var(--bg-border)]">
        <div className="min-w-0">
          <h3 className="m-0 text-[13.5px] font-bold text-[var(--text-primary)]">เหตุการณ์โจมตี</h3>
          <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
            เปิดเมื่อเว็บถูกบล็อก 50 ครั้งใน 5 นาที หรือ IP เดียว 30 ครั้ง · จบเมื่อเงียบ 30 นาที · Telegram แจ้งตอนเริ่มและตอนจบ
          </p>
        </div>
        {ongoing.length > 0 && (
          <Badge color="danger" dot pulse>
            กำลังเกิด {ongoing.length}
          </Badge>
        )}
      </div>

      {isLoading ? (
        <p className="m-0 px-4 py-5 text-[12.5px] text-[var(--text-muted)]">กำลังโหลด…</p>
      ) : rows.length === 0 ? (
        <div className="flex items-center gap-3 px-4 py-5 text-[12.5px] text-[var(--text-muted)]">
          <ShieldAlert size={16} className="shrink-0" />
          <span>ยังไม่มีเหตุการณ์ การบล็อกทั่วไปยังดูได้ในตารางด้านล่าง</span>
        </div>
      ) : (
        <ul className="m-0 p-0 list-none divide-y divide-[var(--bg-border)]">
          {rows.map((inc) => {
            const expanded = open === inc.incident_id
            return (
              <li key={inc.incident_id} className={inc.incident_id === linked ? 'bg-orange-500/[0.04]' : ''}>
                <button
                  type="button"
                  onClick={() => setOpen(expanded ? null : inc.incident_id)}
                  aria-expanded={expanded}
                  className="w-full text-left px-4 py-3 flex items-start gap-3 hover:bg-[var(--bg-hover)] cursor-pointer"
                >
                  <div className="shrink-0 pt-0.5">
                    {inc.closed_at ? <Badge color="success" size="sm">จบแล้ว</Badge> : <Badge color="danger" size="sm" dot pulse>กำลังเกิด</Badge>}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-semibold text-[var(--text-primary)] break-words">
                      {incidentSite(inc)} <span className="font-normal text-[var(--text-secondary)]">· {incidentTypes(inc)}</span>
                    </div>
                    <div className="text-[12px] text-[var(--text-muted)]">
                      {incidentWhen(inc)} น. ({incidentMinutes(inc)} นาที) · บล็อก {inc.blocked_count.toLocaleString()} ครั้ง · {inc.ip_count.toLocaleString()} IP
                    </div>
                  </div>
                  <ChevronDown size={15} className={`shrink-0 mt-1 text-[var(--text-muted)] transition-transform ${expanded ? 'rotate-180' : ''}`} />
                </button>
                {expanded && <Detail inc={inc} />}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

export default IncidentList
