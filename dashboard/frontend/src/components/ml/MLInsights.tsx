import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ChevronDown, ChevronRight, Info, RefreshCw, ShieldAlert } from 'lucide-react'
import { api } from '../../api/axios'
import { getOrigins } from '../../api/origins'
import { useAuthStore } from '../../store/authStore'
import { useOriginFilterStore } from '../../store/originFilterStore'
import { useThemeStore } from '../../store/themeStore'
import { isOperator } from '../../lib/permissions'
import { formatBkkDateTime, formatBkkTime } from '../../lib/time'
import {
  detectorLabel, emptyReason, flaggedShare, histogramBars, InsightRequest, ListMode, MLInsights as Insights,
  RANGES, requestTarget, scorePoints, statusView, WATCH_FLOOR,
} from '../../lib/mlInsights'
import { VerdictActions } from './VerdictActions'
import { useT } from '../../i18n'

// Gen 3 scores of the selected origin's real traffic (nginx mirror, or the
// inline gate of an origin in ML enforce mode -> ML service -> ClickHouse
// ml_verdicts). This page only reads; the setting is Origin -> ML Protection.

const sectionTitle = 'm-0 text-[13px] font-semibold text-[var(--text-primary)]'
const muted = 'text-[12px] text-[var(--text-muted)]'

// Validated pairs (dataviz validate_palette.js): below / at-or-above the model threshold.
const COLORS = {
  light: { below: '#0284c7', flagged: '#dc2626', grid: '#e2e8f0', axis: '#94a3b8', ref: '#0f172a' },
  dark: { below: '#3b82f6', flagged: '#ef4444', grid: '#1a2436', axis: '#64748b', ref: '#f1f5f9' },
}

const STATUS_TONE: Record<string, string> = {
  ok: 'text-[var(--text-secondary)]',
  blocked: 'text-[var(--danger)]',
  error: 'text-[var(--warning)]',
  unknown: 'text-[var(--text-muted)]',
}

const ChartTip: React.FC<{ active?: boolean; payload?: any[]; title: (p: any) => string; rows: (p: any) => [string, string][] }> = ({
  active, payload, title, rows,
}) => {
  if (!active || !payload?.length) return null
  const p = payload[0].payload
  return (
    <div className="rounded-lg border border-[var(--chart-tooltip-border)] bg-[var(--chart-tooltip-bg)] px-3 py-2 text-[12px] shadow-lg">
      <p className="m-0 mb-1 font-medium text-[var(--text-primary)]">{title(p)}</p>
      {rows(p).map(([k, v]) => (
        <p key={k} className="m-0 flex justify-between gap-4 text-[var(--text-secondary)]">
          <span>{k}</span>
          <span className="tabular-nums text-[var(--text-primary)]">{v}</span>
        </p>
      ))}
    </div>
  )
}

const Tile: React.FC<{ label: string; value: string; sub?: string }> = ({ label, value, sub }) => (
  <div className="dash-card px-4 py-3">
    <p className="m-0 text-[12px] text-[var(--text-secondary)]">{label}</p>
    <p className="m-0 mt-1 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{value}</p>
    {sub && <p className={`m-0 mt-0.5 ${muted}`}>{sub}</p>}
  </div>
)

const RequestRow: React.FC<{ r: InsightRequest; showHost: boolean }> = ({ r, showHost }) => {
  const [open, setOpen] = useState(false)
  const { t, lang } = useT()
  const status = statusView(r.status_code, r.action, lang)
  const target = requestTarget(r)
  return (
    <>
      <tr className="border-t border-[var(--bg-border-subtle)] align-top hover:bg-[var(--bg-primary)]">
        <td className="py-2 pl-3 pr-2">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-label={open ? t('Hide details', 'ซ่อนรายละเอียด') : t('Show details', 'แสดงรายละเอียด')}
            className="flex h-6 w-6 items-center justify-center rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
          >
            {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        </td>
        <td className="py-2 pr-3 whitespace-nowrap text-[12px] tabular-nums text-[var(--text-secondary)]">
          {formatBkkDateTime(r.timestamp, { seconds: true })}
        </td>
        {showHost && <td className="py-2 pr-3 text-[12px] text-[var(--text-secondary)] max-w-[12rem] truncate" title={r.host}>{r.host}</td>}
        <td className="py-2 pr-3 max-w-[22rem]">
          <span className="font-mono text-[12px] text-[var(--text-primary)]">
            <span className="mr-1.5 text-[var(--text-muted)]">{r.method}</span>
            <span className="break-all line-clamp-2" title={target}>{target}</span>
          </span>
        </td>
        <td className="py-2 pr-3 whitespace-nowrap">
          <span className="flex items-center gap-2">
            <span className={`text-[13px] font-semibold tabular-nums ${r.is_attack ? 'text-[var(--danger)]' : 'text-[var(--text-primary)]'}`}>
              {scorePoints(r.score)}
            </span>
            <span className="relative block h-1.5 w-14 rounded-full bg-[var(--bg-border)]" aria-hidden="true">
              <span
                className={`absolute inset-y-0 left-0 rounded-full ${r.is_attack ? 'bg-[var(--danger)]' : 'bg-[var(--text-dim)]'}`}
                style={{ width: `${Math.min(100, r.score * 100)}%` }}
              />
            </span>
          </span>
        </td>
        <td className="py-2 pr-3">
          {r.detectors.length ? (
            <span className="flex flex-wrap gap-1">
              {r.detectors.map((d) => (
                <span key={d} className="rounded border border-[var(--bg-border)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">
                  {detectorLabel(d)}
                </span>
              ))}
            </span>
          ) : (
            <span className={muted} title={t('The model scored the shape of the request; no detector matched', 'โมเดลให้คะแนนจากโครงสร้างของ request ไม่มี detector ตัวไหนตรง')}>
              {t('Request shape', 'โครงสร้าง request')}
            </span>
          )}
        </td>
        <td className={`py-2 pr-3 whitespace-nowrap text-[12px] ${STATUS_TONE[status.tone]}`}>{status.text}</td>
      </tr>
      {open && (
        <tr className="bg-[var(--bg-primary)]">
          <td />
          <td colSpan={showHost ? 6 : 5} className="pb-3 pr-3 pt-1">
            <dl className="m-0 grid grid-cols-1 sm:grid-cols-[9rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12px]">
              <dt className="text-[var(--text-muted)]">Request</dt>
              <dd className="m-0 font-mono break-all text-[var(--text-primary)]">{r.method} {target}</dd>
              <dt className="text-[var(--text-muted)]">Host</dt>
              <dd className="m-0 text-[var(--text-primary)]">{r.host}</dd>
              <dt className="text-[var(--text-muted)]">{t('Score / threshold', 'คะแนน / threshold')}</dt>
              <dd className="m-0 tabular-nums text-[var(--text-primary)]">{scorePoints(r.score, 2)} / {scorePoints(r.threshold, 2)}</dd>
              <dt className="text-[var(--text-muted)]">{t('Body size', 'ขนาด body')}</dt>
              <dd className="m-0 tabular-nums text-[var(--text-primary)]">
                {r.body_length.toLocaleString()} bytes{' '}
                {r.has_body
                  ? t('(a masked copy is kept; the Owner and Editors can open it)', '(เก็บสำเนาแบบปิดบังไว้ Owner และ Editor เปิดดูได้)')
                  : t('(content not kept)', '(ไม่ได้เก็บเนื้อหา)')}
              </dd>
              <dt className="text-[var(--text-muted)]">{t('Client', 'ผู้ใช้')}</dt>
              <dd className="m-0 text-[var(--text-primary)]">{r.client_ip ?? '-'}{r.country ? ` (${r.country})` : ''}</dd>
              <dt className="text-[var(--text-muted)]">Request ID</dt>
              <dd className="m-0 font-mono break-all text-[var(--text-secondary)]">{r.request_id || '-'}</dd>
            </dl>
            <VerdictActions r={r} />
          </td>
        </tr>
      )}
    </>
  )
}

export const MLInsights: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = isOperator(user)
  const { selectedOrigin, selectedOriginLabel } = useOriginFilterStore()
  const { theme } = useThemeStore()
  const c = theme === 'dark' ? COLORS.dark : COLORS.light
  const [hours, setHours] = useState<number>(24)
  const [mode, setMode] = useState<ListMode>('flagged')
  const { t, lang } = useT()

  const { data: originsRes } = useQuery({ queryKey: ['origins'], queryFn: () => getOrigins() })
  const hasOrigins = (originsRes?.data?.origins ?? []).length > 0

  const { data, isLoading, isError, error, refetch, isFetching } = useQuery<Insights>({
    queryKey: ['ml-insights', selectedOrigin, hours, mode],
    queryFn: () =>
      api
        .get('/ml/insights', {
          params: { origin: selectedOrigin, hours, limit: 100, ...(mode === 'watch' ? { min_score: WATCH_FLOOR } : {}) },
        })
        .then((r) => r.data),
    refetchInterval: 30_000,
  })

  const summary = data?.summary
  const threshold = summary?.threshold ?? null
  const bars = data ? histogramBars(data.histogram, threshold) : []
  const thresholdBin = threshold !== null ? bars.find((b) => b.from <= threshold && threshold < b.to)?.label : undefined
  // 6-hour buckets span days, so they carry the date too ("10-27 06:00").
  const longRange = (data?.bucket_seconds ?? 3600) >= 21600
  const timeline = (data?.timeline ?? []).map((p) => ({
    ...p,
    label: longRange ? formatBkkDateTime(p.t, { seconds: false }).slice(5) : formatBkkTime(p.t),
  }))
  const maxDetector = Math.max(1, ...(data?.detectors ?? []).map((d) => d.count))
  const showHost = (summary?.hosts ?? 0) > 1 || selectedOrigin === 'ALL'
  const reason = summary ? emptyReason(summary, hasOrigins, isAdmin, lang) : ''

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex max-w-3xl items-start gap-2.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-3 py-2.5">
          <Info size={16} className="mt-0.5 shrink-0 text-[var(--accent)]" aria-hidden="true" />
          <p className="m-0 text-[12.5px] leading-relaxed text-[var(--text-secondary)]">
            <strong className="font-medium text-[var(--text-primary)]">{t('Log mode by default:', 'ค่าเริ่มต้นเป็นโหมดบันทึก log:')}</strong>{' '}
            {t(
              'the model scores every request that passes the WAF, body included, and only records the score. It',
              'โมเดลให้คะแนนทุก request ที่ผ่าน WAF รวม body และบันทึกคะแนนไว้เท่านั้น',
            )}{' '}
            <strong className="font-medium text-[var(--text-primary)]">{t('does not block', 'ไม่บล็อก')}</strong>.{' '}
            {t(
              "An Owner or Editor can turn on enforce mode in the origin's ML protection tab.",
              'Owner หรือ Editor เปิดโหมดบังคับใช้ได้ที่แท็บการป้องกันด้วย ML ของ origin',
            )}
            {(summary?.blocked ?? 0) + (summary?.challenged ?? 0) > 0 && (
              <>
                {' '}
                {t(
                  `In this period ML blocked ${(summary?.blocked ?? 0).toLocaleString()} and challenged ${(summary?.challenged ?? 0).toLocaleString()} requests.`,
                  `ช่วงนี้ ML บล็อก ${(summary?.blocked ?? 0).toLocaleString()} request และให้ทำด่านทดสอบ ${(summary?.challenged ?? 0).toLocaleString()} request`,
                )}
              </>
            )}{' '}
            {t(
              'A flagged request is an estimate, not a confirmed attack: read it together with its path and what was detected. Health checks and monitoring or telemetry calls (for example from Cloudflare Workers) can be flagged too and are usually safe.',
              'request ที่ถูกตั้งธงเป็นการประมาณ ไม่ใช่การโจมตีที่ยืนยันแล้ว ควรดูประกอบกับ path และสิ่งที่ตรวจพบ health check และการเรียกของระบบ monitoring หรือ telemetry (เช่นจาก Cloudflare Workers) ก็อาจถูกตั้งธงได้และมักปลอดภัย',
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="inline-flex rounded-md border border-[var(--bg-border)] bg-[var(--bg-primary)] p-0.5" role="group" aria-label={t('Time range', 'ช่วงเวลา')}>
            {RANGES.map((r) => (
              <button
                key={r.hours}
                type="button"
                aria-pressed={hours === r.hours}
                onClick={() => setHours(r.hours)}
                className={`h-8 px-3 rounded text-[12.5px] font-medium transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
                  hours === r.hours ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-sm' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                {lang === 'th' ? r.labelTh : r.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => refetch()}
            aria-label={t('Refresh', 'รีเฟรช')}
            className="flex h-9 w-9 items-center justify-center rounded-md border border-[var(--bg-border)] text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      <p className={`m-0 ${muted}`}>
        {t('Showing', 'กำลังแสดง')}{' '}
        <span className="text-[var(--text-secondary)]">
          {selectedOrigin === 'ALL'
            ? isAdmin
              ? t('every origin you can view', 'ทุก origin ที่คุณดูได้')
              : t('all your origins', 'ทุก origin ของคุณ')
            : selectedOriginLabel}
        </span>
        .{' '}
        {t('Change it with the origin picker at the top.', 'เปลี่ยนได้จากตัวเลือก origin ด้านบน')}
      </p>

      {isLoading && (
        <div className="dash-card flex min-h-[14rem] items-center justify-center gap-2 text-[13px] text-[var(--text-muted)]">
          <span className="h-4 w-4 rounded-full border-2 border-[var(--bg-border)] border-t-[var(--accent)] animate-spin" />
          {t('Loading ML insights…', 'กำลังโหลด ML insights…')}
        </div>
      )}

      {isError && (
        <div className="dash-card p-5 text-[13px] text-[var(--text-secondary)]">
          {(error as any)?.response?.status === 503
            ? t('The analytics store is unavailable right now. Try again in a minute.', 'ระบบเก็บข้อมูลวิเคราะห์ใช้งานไม่ได้ตอนนี้ ลองใหม่ในอีกหนึ่งนาที')
            : t('Could not load ML insights. Reload the page to try again.', 'โหลด ML insights ไม่สำเร็จ รีโหลดหน้าเพื่อลองใหม่')}
        </div>
      )}

      {data && summary && reason && (
        <div className="dash-card flex min-h-[12rem] flex-col items-center justify-center p-8 text-center">
          <ShieldAlert size={32} className="text-[var(--text-dim)]" aria-hidden="true" />
          <p className="mt-3 mb-1 text-[14px] font-medium text-[var(--text-primary)]">{t('No data yet', 'ยังไม่มีข้อมูล')}</p>
          <p className="m-0 max-w-md text-[12.5px] text-[var(--text-muted)]">{reason}</p>
        </div>
      )}

      {data && summary && !reason && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Tile
              label={t('Requests scored', 'request ที่ให้คะแนนแล้ว')}
              value={summary.total.toLocaleString()}
              sub={summary.last_seen ? t(`Latest ${formatBkkDateTime(summary.last_seen, { seconds: false })}`, `ล่าสุด ${formatBkkDateTime(summary.last_seen, { seconds: false })}`) : undefined}
            />
            <Tile
              label={t('Flagged by ML', 'ML ตั้งธง')}
              value={summary.flagged.toLocaleString()}
              sub={t(`${flaggedShare(summary)} of all scored`, `${flaggedShare(summary)} ของทั้งหมดที่ให้คะแนน`)}
            />
            <Tile
              label={t('Worth watching', 'ควรจับตา')}
              value={summary.watch.toLocaleString()}
              sub={t(`Score ${scorePoints(WATCH_FLOOR, 0)} or more, below the threshold`, `คะแนนตั้งแต่ ${scorePoints(WATCH_FLOOR, 0)} แต่ต่ำกว่า threshold`)}
            />
            <Tile label={t('Model threshold', 'threshold ของโมเดล')} value={scorePoints(threshold, 1)} sub={t('Scores at or above this are flagged', 'คะแนนตั้งแต่ค่านี้จะถูกตั้งธง')} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <section className="dash-card p-4 lg:col-span-8" aria-label={t('Score distribution', 'การกระจายของคะแนน')}>
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 className={sectionTitle}>{t('Score distribution', 'การกระจายของคะแนน')}</h2>
                <span className="flex items-center gap-3 text-[12px] text-[var(--text-secondary)]">
                  <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: c.below }} />{t('Below the threshold', 'ต่ำกว่า threshold')}</span>
                  <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: c.flagged }} />{t('At or above (flagged)', 'ตั้งแต่ threshold (ถูกตั้งธง)')}</span>
                </span>
              </div>
              <p className={`m-0 mt-0.5 ${muted}`}>
                {t("Requests per score band, 0 to 100. The vertical line is the model's threshold.", 'จำนวน request ในแต่ละช่วงคะแนน 0 ถึง 100 เส้นแนวตั้งคือ threshold ของโมเดล')}
              </p>
              <div className="mt-3 h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={bars.map((b) => ({ ...b, below: b.count - b.flagged }))} margin={{ top: 8, right: 4, left: -16, bottom: 0 }} barCategoryGap={2}>
                    <CartesianGrid stroke={c.grid} vertical={false} />
                    <XAxis dataKey="label" stroke={c.axis} fontSize={10} tickLine={false} interval={1} />
                    <YAxis stroke={c.axis} fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
                    <Tooltip
                      cursor={{ fill: 'var(--bg-border)', opacity: 0.4 }}
                      content={
                        <ChartTip
                          title={(p) => t(`Score ${p.label}`, `คะแนน ${p.label}`)}
                          rows={(p) => [[t('Requests', 'Request'), p.count.toLocaleString()], [t('Flagged', 'ถูกตั้งธง'), p.flagged.toLocaleString()]]}
                        />
                      }
                    />
                    {thresholdBin && <ReferenceLine x={thresholdBin} stroke={c.ref} strokeWidth={1.5} />}
                    <Bar dataKey="below" stackId="s" fill={c.below} maxBarSize={24} />
                    <Bar dataKey="flagged" stackId="s" fill={c.flagged} radius={[4, 4, 0, 0]} maxBarSize={24} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>

            <section className="dash-card p-4 lg:col-span-4" aria-label={t('What was detected in flagged requests', 'สิ่งที่ตรวจพบใน request ที่ถูกตั้งธง')}>
              <h2 className={sectionTitle}>{t('What was detected', 'สิ่งที่ตรวจพบ')}</h2>
              <p className={`m-0 mt-0.5 ${muted}`}>{t('In flagged requests', 'ใน request ที่ถูกตั้งธง')}</p>
              {data.detectors.length ? (
                <ul className="m-0 mt-3 p-0 list-none space-y-2.5">
                  {data.detectors.map((d) => (
                    <li key={d.detector}>
                      <span className="flex justify-between gap-2 text-[12.5px]">
                        <span className="text-[var(--text-primary)]">{detectorLabel(d.detector)}</span>
                        <span className="tabular-nums text-[var(--text-secondary)]">{d.count.toLocaleString()}</span>
                      </span>
                      <span className="mt-1 block h-1.5 rounded-full bg-[var(--bg-border)]" aria-hidden="true">
                        <span className="block h-full rounded-full" style={{ width: `${(d.count / maxDetector) * 100}%`, background: c.flagged }} />
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className={`m-0 mt-3 ${muted}`}>
                  {summary.flagged
                    ? t('No detector matched the flagged requests; the model judged them by their shape.', 'ไม่มี detector ตรงกับ request ที่ถูกตั้งธง โมเดลตัดสินจากโครงสร้างของ request')
                    : t('No flagged requests yet.', 'ยังไม่มี request ที่ถูกตั้งธง')}
                </p>
              )}
            </section>
          </div>

          <section className="dash-card p-4" aria-label={t('Flagged requests over time', 'request ที่ถูกตั้งธงตามเวลา')}>
            <h2 className={sectionTitle}>{t('Flagged over time', 'ที่ถูกตั้งธงตามเวลา')}</h2>
            <p className={`m-0 mt-0.5 ${muted}`}>
              {longRange ? t('Per 6 hours, Bangkok time', 'ทุก 6 ชั่วโมง เวลากรุงเทพฯ') : t('Per hour, Bangkok time', 'รายชั่วโมง เวลากรุงเทพฯ')}
            </p>
            <div className="mt-3 h-36">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={timeline} margin={{ top: 8, right: 4, left: -16, bottom: 0 }} barCategoryGap={2}>
                  <CartesianGrid stroke={c.grid} vertical={false} />
                  <XAxis dataKey="label" stroke={c.axis} fontSize={10} tickLine={false} minTickGap={24} />
                  <YAxis stroke={c.axis} fontSize={10} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: 'var(--bg-border)', opacity: 0.4 }}
                    content={
                      <ChartTip
                        title={(p) => formatBkkDateTime(p.t)}
                        rows={(p) => [[t('Flagged', 'ถูกตั้งธง'), p.flagged.toLocaleString()], [t('All requests', 'Request ทั้งหมด'), p.count.toLocaleString()]]}
                      />
                    }
                  />
                  <Bar dataKey="flagged" fill={c.flagged} radius={[4, 4, 0, 0]} maxBarSize={24} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section className="dash-card p-0 overflow-hidden" aria-label={t('Requests', 'Request')}>
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
              <div>
                <h2 className={sectionTitle}>{t('Latest requests', 'request ล่าสุด')}</h2>
                <p className={`m-0 mt-0.5 ${muted}`}>
                  {t(
                    'Sensitive query values (token, password) are masked. For requests scoring 50 or more a masked copy of the body is kept for 7 days.',
                    'ค่าที่อ่อนไหวใน query (token, password) ถูกปิดบัง request ที่ได้คะแนนตั้งแต่ 50 จะเก็บสำเนา body แบบปิดบังไว้ 7 วัน',
                  )}
                </p>
              </div>
              <div className="inline-flex rounded-md border border-[var(--bg-border)] bg-[var(--bg-primary)] p-0.5" role="group" aria-label={t('Which requests', 'request ที่จะแสดง')}>
                {([
                  ['flagged', t('Flagged', 'ถูกตั้งธง')],
                  ['watch', t(`Score ${scorePoints(WATCH_FLOOR, 0)} or more`, `คะแนนตั้งแต่ ${scorePoints(WATCH_FLOOR, 0)}`)],
                ] as const).map(([m, label]) => (
                  <button
                    key={m}
                    type="button"
                    aria-pressed={mode === m}
                    onClick={() => setMode(m)}
                    className={`h-8 px-3 rounded text-[12.5px] font-medium transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
                      mode === m ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-sm' : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            {data.requests.length ? (
              <div className="mt-3 overflow-x-auto">
                <table className="w-full min-w-[46rem] border-collapse text-left">
                  <thead>
                    <tr className="text-[11.5px] font-medium text-[var(--text-muted)]">
                      <th className="w-8 py-2 pl-3" aria-label={t('Details', 'รายละเอียด')} />
                      <th className="py-2 pr-3 font-medium">{t('Time', 'เวลา')}</th>
                      {showHost && <th className="py-2 pr-3 font-medium">Host</th>}
                      <th className="py-2 pr-3 font-medium">Request</th>
                      <th className="py-2 pr-3 font-medium">{t('Score', 'คะแนน')}</th>
                      <th className="py-2 pr-3 font-medium">{t('Detected', 'ตรวจพบ')}</th>
                      <th className="py-2 pr-3 font-medium">{t('WAF answer', 'WAF ตอบ')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.requests.map((r, i) => <RequestRow key={`${r.request_id}-${i}`} r={r} showHost={showHost} />)}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className={`m-0 px-4 py-8 text-center ${muted}`}>
                {mode === 'flagged'
                  ? t('No flagged requests in this period.', 'ช่วงนี้ไม่มี request ที่ถูกตั้งธง')
                  : t('No requests scored 50 or more in this period.', 'ช่วงนี้ไม่มี request ที่ได้คะแนนตั้งแต่ 50')}
              </p>
            )}
          </section>
        </>
      )}
    </div>
  )
}

export default MLInsights
