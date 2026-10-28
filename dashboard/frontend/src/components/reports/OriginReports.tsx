import React, { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Copy, Download, FileText, Lock, Printer, Sparkles, X } from 'lucide-react'
import { createPostmortem, getPostmortem, getPostmortems } from '../../api/postmortems'
import type { Postmortem } from '../../types'
import { Button } from '../ui/Button'
import { LoadingSpinner } from '../ui/LoadingSpinner'
import { ReportText } from '../ai/ReportText'
import { DateRangePicker } from './DateRangePicker'
import { TimeSelect } from './TimeSelect'
import { ReportChart, ChartLegend } from './ReportChart'
import { usePrintReport } from './FormalReport'
import {
  type QuickRange,
  type ReportRange,
  QUICK_RANGES,
  dayLabelTh,
  daysInclusive,
  defaultTimes,
  durationMinutes,
  formatDurationTh,
  matchesQuickRange,
  nowBkk,
  quickRange,
  toApiTime,
  validateRange,
} from '../../lib/reportRange'
import { blockedShare, buildReportMarkdown, rangeFacts, reportFileBase, reportNumber, reportSeries } from '../../lib/reportExport'
import { formatBkkDateTime } from '../../lib/time'
import { useT } from '../../i18n'

// The origin's Reports tab: pick a period (quick ranges, or first and last
// day on a calendar and then the times), write an AI incident report for it,
// and export a saved report as a Markdown summary or a formal PDF.

interface Props {
  originId: string
  canWrite: boolean
}

const n = (v: number | undefined | null) => (v ?? 0).toLocaleString('en-US')

export const OriginReports: React.FC<Props> = ({ originId, canWrite }) => {
  const queryClient = useQueryClient()
  const { t, lang } = useT()
  const [now, setNow] = useState(() => nowBkk())
  const [range, setRange] = useState<ReportRange>(() => quickRange('24h', nowBkk()))
  const [custom, setCustom] = useState(false)
  const [touched, setTouched] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const { print, layer } = usePrintReport()

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ['origin-postmortems', originId],
    queryFn: () => getPostmortems(originId),
    enabled: canWrite,
  })
  const reports = listData?.data?.postmortems || []

  const { data: oneData, isLoading: oneLoading } = useQuery({
    queryKey: ['origin-postmortem', originId, selectedId],
    queryFn: () => getPostmortem(originId, selectedId!),
    enabled: !!selectedId,
  })
  const report: Postmortem | null = oneData?.data?.postmortem || null

  const create = useMutation({
    mutationFn: () => createPostmortem(originId, toApiTime(range.start!, range.startTime), toApiTime(range.end!, range.endTime)),
    onSuccess: (res) => {
      toast.success(t('Report created', 'สร้างรายงานแล้ว'))
      queryClient.invalidateQueries({ queryKey: ['origin-postmortems', originId] })
      queryClient.setQueryData(['origin-postmortem', originId, res.data.postmortem.id], res)
      setSelectedId(res.data.postmortem.id)
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Could not create the report', 'สร้างรายงานไม่สำเร็จ')),
  })

  const active: QuickRange | 'custom' = custom ? 'custom' : matchesQuickRange(range, now) ?? 'custom'
  const error = validateRange(range, now, lang)
  const minutes = durationMinutes(range)
  const days = range.start && range.end ? daysInclusive(range.start, range.end) : null

  const chooseQuick = (id: QuickRange | 'custom') => {
    const fresh = nowBkk()
    setNow(fresh)
    if (id === 'custom') {
      setCustom(true)
      return
    }
    setCustom(false)
    setRange(quickRange(id, fresh))
  }

  const onDays = (start: string | null, end: string | null, done: boolean) => {
    const fresh = nowBkk()
    setNow(fresh)
    setCustom(true)
    setTouched(true)
    if (done && end) {
      setRange({ start, end, ...defaultTimes(end, fresh) })
      window.setTimeout(() => document.getElementById('rep-start-h')?.focus(), 0)
    } else {
      setRange((r) => ({ ...r, start, end }))
    }
  }

  const exportMarkdown = (p: Postmortem) => {
    const blob = new Blob([buildReportMarkdown(p)], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${reportFileBase(p)}.md`
    document.body.appendChild(a)
    a.click()
    a.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const copySummary = async (p: Postmortem) => {
    try {
      await navigator.clipboard.writeText(buildReportMarkdown(p))
      toast.success(t('Summary copied', 'คัดลอกสรุปแล้ว'))
    } catch {
      toast.error(t('Could not copy; download the summary instead', 'คัดลอกไม่ได้ ใช้ดาวน์โหลดสรุปแทน'))
    }
  }

  const series = useMemo(() => (report ? reportSeries(report) : null), [report])

  if (!canWrite) {
    return (
      <section className="dash-card p-5">
        <div className="flex items-start gap-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] p-3.5 text-[13.5px]">
          <Lock size={17} className="mt-0.5 text-[var(--text-muted)]" />
          <div>
            <b className="block font-semibold text-[var(--text-primary)]">{t('Incident reports are for the Owner and Editors only', 'รายงานเหตุการณ์ดูได้เฉพาะ Owner และ Editor')}</b>
            <span className="text-[var(--text-secondary)]">{t('Reports include system changes a view-only account should not see. Ask this site’s Owner to create or send one.', 'รายงานรวมการเปลี่ยนแปลงในระบบที่บัญชีดูอย่างเดียวไม่ควรเห็น ขอให้ Owner ของเว็บนี้สร้างหรือส่งรายงานให้')}</span>
          </div>
        </div>
      </section>
    )
  }

  return (
    <div className="space-y-4">
      {layer}

      <section className="dash-card p-5">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h3 className="m-0 text-[15px] font-semibold text-[var(--text-primary)]">{t('Create an incident report', 'สร้างรายงานเหตุการณ์')}</h3>
          <span className="text-[13px] text-[var(--text-muted)]">{t('What was blocked and what changed in the system, for the period you pick', 'สรุปสิ่งที่ถูกบล็อกและการเปลี่ยนแปลงในระบบ ในช่วงเวลาที่เลือก')}</span>
        </div>

        <div className="mt-4 inline-flex max-w-full overflow-x-auto rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-[3px] gap-0.5" role="group" aria-label={t('Period', 'ช่วงเวลา')}>
          {[...QUICK_RANGES.map((q) => ({ id: q.id as QuickRange | 'custom', label: lang === 'en' ? q.labelEn : q.label })), { id: 'custom' as const, label: t('Custom', 'กำหนดเอง') }].map((q) => (
            <button
              key={q.id}
              type="button"
              onClick={() => chooseQuick(q.id)}
              aria-pressed={active === q.id}
              className={`h-8 px-3 rounded-md text-[13px] font-medium whitespace-nowrap cursor-pointer ${
                active === q.id ? 'bg-[var(--bg-surface-active)] text-[var(--text-primary)]' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              {q.label}
            </button>
          ))}
        </div>

        <div className="mt-4 grid gap-4">
          <DateRangePicker start={range.start} end={range.end} today={now.date} onChange={onDays} />

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 max-w-[560px]">
            <div className="grid gap-1">
              <label htmlFor="rep-start-h" className="text-[12.5px] font-medium text-[var(--text-secondary)]">
                {t('Start time', 'เวลาเริ่ม')}{range.start ? ` · ${dayLabelTh(range.start, lang)}` : ''}
              </label>
              <TimeSelect
                id="rep-start"
                label={t('Start time', 'เวลาเริ่ม')}
                value={range.startTime}
                disabled={!range.start}
                onChange={(v) => {
                  setCustom(true)
                  setTouched(true)
                  setRange((r) => ({ ...r, startTime: v }))
                }}
              />
            </div>
            <div className="grid gap-1">
              <label htmlFor="rep-end-h" className="text-[12.5px] font-medium text-[var(--text-secondary)]">
                {t('End time', 'เวลาสิ้นสุด')}{range.end ? ` · ${dayLabelTh(range.end, lang)}` : ''}
              </label>
              <TimeSelect
                id="rep-end"
                label={t('End time', 'เวลาสิ้นสุด')}
                value={range.endTime}
                disabled={!range.end}
                onChange={(v) => {
                  setCustom(true)
                  setTouched(true)
                  setRange((r) => ({ ...r, endTime: v }))
                }}
              />
            </div>
          </div>

          <div className="text-[13px]" aria-live="polite">
            {range.start && range.end ? (
              <p className="m-0 text-[var(--text-secondary)]">
                <span className="tabular-nums text-[var(--text-primary)] font-medium">
                  {t(
                    `${dayLabelTh(range.start, lang)} ${range.startTime} to ${dayLabelTh(range.end, lang)} ${range.endTime}`,
                    `${dayLabelTh(range.start)} ${range.startTime} น. ถึง ${dayLabelTh(range.end)} ${range.endTime} น.`,
                  )}
                </span>
                {days !== null && (
                  <span>
                    {' '}· <b className="font-semibold text-[var(--text-primary)]">{t(`${days} days`, `${days} วัน`)}</b>
                    {minutes !== null && t(` (${formatDurationTh(minutes, lang)} in total)`, ` (รวม ${formatDurationTh(minutes)})`)}
                  </span>
                )}
              </p>
            ) : (
              <p className="m-0 text-[var(--text-muted)]">{t('Pick the start and end days on the calendar, then adjust the times', 'เลือกวันเริ่มและวันสิ้นสุดบนปฏิทิน แล้วค่อยปรับเวลา')}</p>
            )}
            {error && (range.start && range.end ? true : touched) && (
              <p className="m-0 mt-1 text-[var(--danger)]">{error}</p>
            )}
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-[var(--bg-border-subtle)] flex flex-wrap items-center justify-end gap-2">
          <span className="mr-auto text-[12.5px] text-[var(--text-muted)]">{t('Takes about a minute. The summary is written by AI; review it before you pass it on.', 'ใช้เวลาราว 1 นาที บทสรุปเขียนโดย AI โปรดตรวจทานก่อนส่งต่อ')}</span>
          <Button
            variant="primary"
            icon={<Sparkles size={14} />}
            onClick={() => create.mutate()}
            disabled={!!error}
            isLoading={create.isPending}
          >
            {t('Create report', 'สร้างรายงาน')}
          </Button>
        </div>
      </section>

      <section className="dash-card p-5">
        <h3 className="m-0 text-[15px] font-semibold text-[var(--text-primary)]">{t('Saved reports', 'รายงานที่สร้างไว้')}</h3>
        {listLoading ? (
          <LoadingSpinner />
        ) : reports.length === 0 ? (
          <div className="mt-3 flex items-center gap-2.5 rounded-lg border border-dashed border-[var(--bg-border-hover)] p-3.5 text-[13px] text-[var(--text-muted)]">
            <FileText size={16} />
            {t('No reports yet. Pick a period above and create one.', 'ยังไม่มีรายงาน เลือกช่วงเวลาด้านบนแล้วกดสร้างรายงาน')}
          </div>
        ) : (
          <div className="mt-3 overflow-x-auto rounded-lg border border-[var(--bg-border)]">
            <table className="w-full border-collapse text-[13px]">
              <thead>
                <tr className="text-left text-[12px] text-[var(--text-muted)]">
                  <th className="px-3 py-2 font-medium border-b border-[var(--bg-border)]">{t('Period (Bangkok time)', 'ช่วงเวลา (เวลาไทย)')}</th>
                  <th className="px-3 py-2 font-medium border-b border-[var(--bg-border)] text-right">{t('Days', 'จำนวนวัน')}</th>
                  <th className="px-3 py-2 font-medium border-b border-[var(--bg-border)] text-right">{t('Blocked', 'ถูกบล็อก')}</th>
                  <th className="px-3 py-2 font-medium border-b border-[var(--bg-border)]">{t('Created by', 'ผู้จัดทำ')}</th>
                  <th className="px-3 py-2 font-medium border-b border-[var(--bg-border)]">{t('Created', 'สร้างเมื่อ')}</th>
                  <th className="px-3 py-2 border-b border-[var(--bg-border)]" />
                </tr>
              </thead>
              <tbody>
                {reports.map((p) => {
                  const f = rangeFacts(p)
                  return (
                    <tr key={p.id} className={selectedId === p.id ? 'bg-[var(--accent-subtle)]' : 'hover:bg-[var(--bg-hover)]'}>
                      <td className="px-3 py-2.5 border-b border-[var(--bg-border-subtle)] tabular-nums whitespace-nowrap text-[var(--text-primary)]">
                        {p.start_time.slice(0, 16)} → {p.end_time.slice(0, 16)}
                      </td>
                      <td className="px-3 py-2.5 border-b border-[var(--bg-border-subtle)] text-right tabular-nums">{f.days ?? '—'}</td>
                      <td className="px-3 py-2.5 border-b border-[var(--bg-border-subtle)] text-right tabular-nums">{n(p.stats?.total_alerts)}</td>
                      <td className="px-3 py-2.5 border-b border-[var(--bg-border-subtle)]">{p.created_by_username || '—'}</td>
                      <td className="px-3 py-2.5 border-b border-[var(--bg-border-subtle)] text-[var(--text-muted)] whitespace-nowrap">
                        {formatBkkDateTime(p.created_at, { seconds: false })}
                      </td>
                      <td className="px-3 py-2.5 border-b border-[var(--bg-border-subtle)] text-right">
                        <Button size="sm" variant="secondary" onClick={() => setSelectedId(p.id)}>
                          {t('Open', 'เปิด')}
                        </Button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selectedId && (
        <section className="dash-card p-5" aria-label={t('Open report', 'รายงานที่เปิดอยู่')}>
          {oneLoading ? (
            <LoadingSpinner />
          ) : !report ? (
            <p className="m-0 text-[13px] text-[var(--text-muted)]">{t('Report not found', 'ไม่พบรายงานนี้')}</p>
          ) : (
            <div className="space-y-5">
              <div className="flex flex-wrap items-start gap-3">
                <div className="min-w-0">
                  <p className="m-0 text-[12px] text-[var(--text-muted)] font-mono">{reportNumber(report)}</p>
                  <h3 className="m-0 text-[16px] font-semibold text-[var(--text-primary)] tabular-nums">
                    {report.start_time.slice(0, 16)} → {report.end_time.slice(0, 16)}
                  </h3>
                  <p className="m-0 text-[12.5px] text-[var(--text-muted)]">
                    {t(
                      `${rangeFacts(report, lang).days} days · ${rangeFacts(report, lang).duration} in total · created by ${report.created_by_username || '—'}`,
                      `${rangeFacts(report).days} วัน · รวม ${rangeFacts(report).duration} · จัดทำโดย ${report.created_by_username || '—'}`,
                    )}
                  </p>
                </div>
                <span className="flex-1" />
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="secondary" icon={<Copy size={14} />} onClick={() => copySummary(report)}>
                    {t('Copy summary', 'คัดลอกสรุป')}
                  </Button>
                  <Button size="sm" variant="secondary" icon={<Download size={14} />} onClick={() => exportMarkdown(report)}>
                    {t('Download summary (.md)', 'ดาวน์โหลดสรุป (.md)')}
                  </Button>
                  <Button size="sm" variant="primary" icon={<Printer size={14} />} onClick={() => print(report)} title={t('Opens the print dialog; choose Save as PDF', 'เปิดหน้าต่างพิมพ์ แล้วเลือก Save as PDF')}>
                    {t('Export PDF', 'ส่งออก PDF')}
                  </Button>
                  <Button size="sm" variant="ghost" icon={<X size={14} />} onClick={() => setSelectedId(null)} aria-label={t('Close report', 'ปิดรายงาน')} />
                </div>
              </div>

              <div className="grid grid-cols-2 lg:grid-cols-4 rounded-lg border border-[var(--bg-border)]">
                {[
                  [t('All requests', 'คำขอทั้งหมด'), n(report.stats?.total_requests)],
                  [t('Blocked or alerted', 'ถูกบล็อกหรือแจ้งเตือน'), n(report.stats?.total_alerts)],
                  [t('Share blocked', 'สัดส่วนที่ถูกบล็อก'), blockedShare(report)],
                  [t('System changes', 'การเปลี่ยนแปลงในระบบ'), t(`${n(report.audit_events?.length)} items`, `${n(report.audit_events?.length)} รายการ`)],
                ].map(([k, v], i) => (
                  <div key={k} className={`px-4 py-3 ${i ? 'border-l border-[var(--bg-border)]' : ''} ${i === 2 ? 'max-lg:border-l-0 max-lg:border-t' : ''} ${i === 3 ? 'max-lg:border-t' : ''}`}>
                    <div className="text-[12.5px] text-[var(--text-muted)]">{k}</div>
                    <div className="text-[20px] font-semibold text-[var(--text-primary)] tabular-nums">{v}</div>
                  </div>
                ))}
              </div>

              {series && series.points.length > 0 && (
                <div>
                  <div className="flex flex-wrap items-center gap-3 mb-2">
                    <span className="text-[13px] font-semibold text-[var(--text-primary)]">{t(`Requests per ${series.unit}`, `ปริมาณคำขอราย${series.unit === 'day' ? 'วัน' : 'ชั่วโมง'}`)}</span>
                    <span className="flex-1" />
                    <ChartLegend lang={lang} />
                  </div>
                  <div className="max-w-[760px]">
                    <ReportChart points={series.points} unit={series.unit} lang={lang} />
                  </div>
                </div>
              )}

              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-[13px] font-semibold text-[var(--text-primary)]">{t('Summary', 'บทสรุป')}</span>
                  <span className="rounded-md border border-[var(--bg-border)] px-1.5 text-[11.5px] text-[var(--text-muted)]">{t('Drafted by AI', 'ร่างโดย AI')}</span>
                  {report.ai_narrative_degraded && <span className="text-[12px] text-[var(--warning)]">{t('May be incomplete', 'อาจไม่ครบถ้วน')}</span>}
                </div>
                {report.ai_narrative ? (
                  <ReportText text={report.ai_narrative} className="text-[13px] rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border-subtle)] p-4" />
                ) : (
                  <p className="m-0 text-[13px] text-[var(--text-muted)]">{t('No AI summary for this report; use the figures above.', 'ไม่มีบทสรุปจาก AI สำหรับรายงานนี้ ใช้ตัวเลขด้านบนแทน')}</p>
                )}
              </div>

              <div className="grid gap-5 lg:grid-cols-2">
                <div>
                  <span className="text-[13px] font-semibold text-[var(--text-primary)]">{t('Most common attack types', 'ประเภทการโจมตีที่พบมากที่สุด')}</span>
                  {(report.stats?.top_attack_types || []).length ? (
                    <ul className="m-0 mt-2 p-0 list-none">
                      {report.stats.top_attack_types.map((at, i) => (
                        <li key={`${at.type}-${i}`} className="flex justify-between gap-3 py-1.5 border-b border-[var(--bg-border-subtle)] text-[13px]">
                          <span className="text-[var(--text-primary)] break-all">{at.type}</span>
                          <span className="tabular-nums text-[var(--text-secondary)]">{n(at.count)}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="m-0 mt-2 text-[13px] text-[var(--text-muted)]">{t('None in this period', 'ไม่พบในช่วงเวลานี้')}</p>
                  )}
                </div>
                <div>
                  <span className="text-[13px] font-semibold text-[var(--text-primary)]">{t('System changes', 'การเปลี่ยนแปลงในระบบ')}</span>
                  {(report.audit_events || []).length ? (
                    <ul className="m-0 mt-2 p-0 list-none">
                      {report.audit_events.map((ev) => (
                        <li key={ev.event_id} className="grid grid-cols-[auto_1fr] gap-x-3 py-1.5 border-b border-[var(--bg-border-subtle)] text-[13px]">
                          <span className="tabular-nums text-[var(--text-muted)] whitespace-nowrap">{formatBkkDateTime(ev.timestamp, { seconds: false })}</span>
                          <span className="text-[var(--text-primary)]">
                            {ev.summary || ev.action}
                            {ev.actor_username && <span className="text-[var(--text-muted)]"> · {ev.actor_username}</span>}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="m-0 mt-2 text-[13px] text-[var(--text-muted)]">{t('None in this period', 'ไม่มีในช่วงเวลานี้')}</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  )
}

export default OriginReports
