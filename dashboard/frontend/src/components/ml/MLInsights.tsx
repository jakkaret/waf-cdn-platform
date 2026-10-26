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

// Gen 3 scores of the selected origin's real traffic (nginx mirror -> ML
// service -> ClickHouse ml_verdicts). Shadow only: nothing here blocks.

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
  const status = statusView(r.status_code)
  const target = requestTarget(r)
  return (
    <>
      <tr className="border-t border-[var(--bg-border-subtle)] align-top hover:bg-[var(--bg-primary)]">
        <td className="py-2 pl-3 pr-2">
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-label={open ? 'ซ่อนรายละเอียด' : 'ดูรายละเอียด'}
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
            <span className={muted} title="โมเดลให้คะแนนจากโครงสร้างของ request ไม่มี detector ตัวไหนตรง">โครงสร้าง</span>
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
              <dt className="text-[var(--text-muted)]">คะแนน / เกณฑ์</dt>
              <dd className="m-0 tabular-nums text-[var(--text-primary)]">{scorePoints(r.score, 2)} / {scorePoints(r.threshold, 2)}</dd>
              <dt className="text-[var(--text-muted)]">ขนาด body</dt>
              <dd className="m-0 tabular-nums text-[var(--text-primary)]">{r.body_length.toLocaleString()} bytes (ไม่ได้เก็บเนื้อหา)</dd>
              <dt className="text-[var(--text-muted)]">ผู้ส่ง</dt>
              <dd className="m-0 text-[var(--text-primary)]">{r.client_ip ?? '-'}{r.country ? ` · ${r.country}` : ''}</dd>
              <dt className="text-[var(--text-muted)]">Request ID</dt>
              <dd className="m-0 font-mono break-all text-[var(--text-secondary)]">{r.request_id || '-'}</dd>
            </dl>
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
  const reason = summary ? emptyReason(summary, hasOrigins, isAdmin) : ''

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex max-w-3xl items-start gap-2.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-3 py-2.5">
          <Info size={16} className="mt-0.5 shrink-0 text-[var(--accent)]" aria-hidden="true" />
          <p className="m-0 text-[12.5px] leading-relaxed text-[var(--text-secondary)]">
            <strong className="font-medium text-[var(--text-primary)]">โหมด log:</strong> โมเดล Gen 3 ให้คะแนนทุก request ที่ผ่าน WAF
            (รวม body) แล้วบันทึกไว้เท่านั้น <strong className="font-medium text-[var(--text-primary)]">ไม่ได้บล็อก</strong> request
            ที่ถูกตั้งข้อสังเกตอาจไม่ใช่การโจมตีจริงเสมอไป ให้ดูประกอบกับ path และสิ่งที่ตรวจพบ
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="inline-flex rounded-md border border-[var(--bg-border)] bg-[var(--bg-primary)] p-0.5" role="group" aria-label="ช่วงเวลา">
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
                {r.label}
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => refetch()}
            aria-label="รีเฟรช"
            className="flex h-9 w-9 items-center justify-center rounded-md border border-[var(--bg-border)] text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      <p className={`m-0 ${muted}`}>
        กำลังดู: <span className="text-[var(--text-secondary)]">{selectedOrigin === 'ALL' ? (isAdmin ? 'ทุก origin ที่ดูได้' : 'ทุก origin ของคุณ') : selectedOriginLabel}</span>
        {' '}· เปลี่ยน origin ได้ที่ตัวเลือกด้านบนขวา
      </p>

      {isLoading && (
        <div className="dash-card flex min-h-[14rem] items-center justify-center gap-2 text-[13px] text-[var(--text-muted)]">
          <span className="h-4 w-4 rounded-full border-2 border-[var(--bg-border)] border-t-[var(--accent)] animate-spin" />
          กำลังโหลด ML Insights...
        </div>
      )}

      {isError && (
        <div className="dash-card p-5 text-[13px] text-[var(--text-secondary)]">
          {(error as any)?.response?.status === 503
            ? 'ระบบเก็บข้อมูล analytics ใช้งานไม่ได้ชั่วคราว ลองใหม่อีกครั้งในสักครู่'
            : 'โหลด ML Insights ไม่สำเร็จ ลองรีเฟรชหน้านี้'}
        </div>
      )}

      {data && summary && reason && (
        <div className="dash-card flex min-h-[12rem] flex-col items-center justify-center p-8 text-center">
          <ShieldAlert size={32} className="text-[var(--text-dim)]" aria-hidden="true" />
          <p className="mt-3 mb-1 text-[14px] font-medium text-[var(--text-primary)]">ยังไม่มีข้อมูล</p>
          <p className="m-0 max-w-md text-[12.5px] text-[var(--text-muted)]">{reason}</p>
        </div>
      )}

      {data && summary && !reason && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <Tile label="Request ที่ให้คะแนนแล้ว" value={summary.total.toLocaleString()} sub={summary.last_seen ? `ล่าสุด ${formatBkkDateTime(summary.last_seen, { seconds: false })}` : undefined} />
            <Tile label="ML ตั้งข้อสังเกต" value={summary.flagged.toLocaleString()} sub={`${flaggedShare(summary)} ของทั้งหมด`} />
            <Tile label="ควรจับตา" value={summary.watch.toLocaleString()} sub={`คะแนน ${scorePoints(WATCH_FLOOR, 0)} ขึ้นไป แต่ยังไม่ถึงเกณฑ์`} />
            <Tile label="เกณฑ์ของโมเดล" value={scorePoints(threshold, 1)} sub="คะแนนตั้งแต่นี้ขึ้นไปถูกตั้งข้อสังเกต" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <section className="dash-card p-4 lg:col-span-8" aria-label="การกระจายคะแนน">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 className={sectionTitle}>การกระจายคะแนน</h2>
                <span className="flex items-center gap-3 text-[12px] text-[var(--text-secondary)]">
                  <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: c.below }} />ต่ำกว่าเกณฑ์</span>
                  <span className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-sm" style={{ background: c.flagged }} />ถึงเกณฑ์ (ตั้งข้อสังเกต)</span>
                </span>
              </div>
              <p className={`m-0 mt-0.5 ${muted}`}>จำนวน request ในแต่ละช่วงคะแนน 0-100 เส้นตั้งคือเกณฑ์ของโมเดล</p>
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
                          title={(p) => `คะแนน ${p.label}`}
                          rows={(p) => [['request', p.count.toLocaleString()], ['ตั้งข้อสังเกต', p.flagged.toLocaleString()]]}
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

            <section className="dash-card p-4 lg:col-span-4" aria-label="สิ่งที่ตรวจพบใน request ที่ถูกตั้งข้อสังเกต">
              <h2 className={sectionTitle}>สิ่งที่ตรวจพบ</h2>
              <p className={`m-0 mt-0.5 ${muted}`}>ใน request ที่ถูกตั้งข้อสังเกต</p>
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
                  {summary.flagged ? 'request ที่ถูกตั้งข้อสังเกตไม่มี detector ตัวไหนตรง โมเดลตัดสินจากโครงสร้างของ request' : 'ยังไม่มี request ที่ถูกตั้งข้อสังเกต'}
                </p>
              )}
            </section>
          </div>

          <section className="dash-card p-4" aria-label="จำนวนที่ถูกตั้งข้อสังเกตตามเวลา">
            <h2 className={sectionTitle}>ที่ถูกตั้งข้อสังเกตตามเวลา</h2>
            <p className={`m-0 mt-0.5 ${muted}`}>ต่อ{longRange ? ' 6 ชั่วโมง' : 'ชั่วโมง'} (เวลาไทย)</p>
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
                        rows={(p) => [['ตั้งข้อสังเกต', p.flagged.toLocaleString()], ['request ทั้งหมด', p.count.toLocaleString()]]}
                      />
                    }
                  />
                  <Bar dataKey="flagged" fill={c.flagged} radius={[4, 4, 0, 0]} maxBarSize={24} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </section>

          <section className="dash-card p-0 overflow-hidden" aria-label="รายการ request">
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 pt-4">
              <div>
                <h2 className={sectionTitle}>Request ล่าสุด</h2>
                <p className={`m-0 mt-0.5 ${muted}`}>ไม่เก็บ body ค่าที่อ่อนไหวใน query (เช่น token, password) ถูกซ่อน</p>
              </div>
              <div className="inline-flex rounded-md border border-[var(--bg-border)] bg-[var(--bg-primary)] p-0.5" role="group" aria-label="รายการที่แสดง">
                {([['flagged', 'ถูกตั้งข้อสังเกต'], ['watch', `คะแนน ${scorePoints(WATCH_FLOOR, 0)} ขึ้นไป`]] as const).map(([m, label]) => (
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
                      <th className="w-8 py-2 pl-3" aria-label="รายละเอียด" />
                      <th className="py-2 pr-3 font-medium">เวลา</th>
                      {showHost && <th className="py-2 pr-3 font-medium">Host</th>}
                      <th className="py-2 pr-3 font-medium">Request</th>
                      <th className="py-2 pr-3 font-medium">คะแนน</th>
                      <th className="py-2 pr-3 font-medium">สิ่งที่ตรวจพบ</th>
                      <th className="py-2 pr-3 font-medium">WAF ตอบ</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.requests.map((r, i) => <RequestRow key={`${r.request_id}-${i}`} r={r} showHost={showHost} />)}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className={`m-0 px-4 py-8 text-center ${muted}`}>
                {mode === 'flagged' ? 'ไม่มี request ที่ถูกตั้งข้อสังเกตในช่วงเวลานี้' : 'ไม่มี request ที่คะแนนถึง 50 ในช่วงเวลานี้'}
              </p>
            )}
          </section>
        </>
      )}
    </div>
  )
}

export default MLInsights
