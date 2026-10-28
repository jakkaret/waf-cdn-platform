import React from 'react'
import type { SeriesPoint } from '../../lib/reportExport'
import type { Lang } from '../../i18n'

// Requests and blocked requests per hour (or per day for long ranges), drawn
// as plain SVG so the same chart prints in the PDF. Blocked bars sit inside
// their hour's request bar, on one shared scale.

interface Props {
  points: SeriesPoint[]
  unit: 'hour' | 'day'
  colors?: { requests: string; alerts: string; axis: string; grid: string; text: string }
  height?: number
  lang?: Lang
}

const SCREEN = {
  requests: 'var(--bg-border-hover)',
  alerts: 'var(--danger)',
  axis: 'var(--bg-border)',
  grid: 'var(--bg-border-subtle)',
  text: 'var(--text-muted)',
}

const niceMax = (v: number) => {
  if (v <= 5) return 5
  const p = Math.pow(10, Math.floor(Math.log10(v)))
  const m = v / p
  return (m <= 1 ? 1 : m <= 2 ? 2 : m <= 5 ? 5 : 10) * p
}

const label = (key: string, unit: 'hour' | 'day') =>
  unit === 'day' ? `${Number(key.slice(8, 10))}/${Number(key.slice(5, 7))}` : `${key.slice(11, 13)}:00`

export const ReportChart: React.FC<Props> = ({ points, unit, colors = SCREEN, height = 180, lang = 'th' }) => {
  const en = lang === 'en'
  if (!points.length) return null
  const W = 640
  const H = height
  const left = 40
  const bottom = 26
  const top = 8
  const plotW = W - left - 8
  const plotH = H - top - bottom
  const max = niceMax(Math.max(1, ...points.map((p) => p.requests)))
  const step = plotW / points.length
  const barW = Math.max(1.5, Math.min(22, step * 0.7))
  const every = Math.max(1, Math.ceil(points.length / 12))
  const y = (v: number) => top + plotH - (v / max) * plotH
  const ticks = [0, max / 2, max]

  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={en ? `Requests and blocked requests per ${unit}` : `คำขอและคำขอที่ถูกบล็อก ราย${unit === 'day' ? 'วัน' : 'ชั่วโมง'}`} style={{ display: 'block' }}>
      {ticks.map((t) => (
        <g key={t}>
          <line x1={left} x2={W - 8} y1={y(t)} y2={y(t)} stroke={t === 0 ? colors.axis : colors.grid} strokeWidth={1} />
          <text x={left - 6} y={y(t) + 4} textAnchor="end" fontSize={11} fill={colors.text}>
            {Number.isInteger(t) ? t.toLocaleString('en-US') : t.toFixed(1)}
          </text>
        </g>
      ))}
      {points.map((p, i) => {
        const x = left + i * step + (step - barW) / 2
        return (
          <g key={p.key}>
            <title>{`${p.key}${unit === 'hour' ? ':00' : ''} · ${en ? 'requests' : 'คำขอ'} ${p.requests.toLocaleString('en-US')} · ${en ? 'blocked' : 'ถูกบล็อก'} ${p.alerts.toLocaleString('en-US')}`}</title>
            {p.requests > 0 && <rect x={x} y={y(p.requests)} width={barW} height={top + plotH - y(p.requests)} fill={colors.requests} rx={1} />}
            {p.alerts > 0 && <rect x={x} y={y(p.alerts)} width={barW} height={top + plotH - y(p.alerts)} fill={colors.alerts} rx={1} />}
            {i % every === 0 && (
              <text x={x + barW / 2} y={H - 8} textAnchor="middle" fontSize={11} fill={colors.text}>
                {label(p.key, unit)}
              </text>
            )}
          </g>
        )
      })}
    </svg>
  )
}

export const ChartLegend: React.FC<{ colors?: Props['colors']; lang?: Lang }> = ({ colors = SCREEN, lang = 'th' }) => (
  <div className="flex items-center gap-4 text-[12px]" style={{ color: colors.text }}>
    <span className="inline-flex items-center gap-1.5">
      <span style={{ width: 10, height: 10, borderRadius: 2, background: colors.requests, display: 'inline-block' }} />
      {lang === 'en' ? 'All requests' : 'คำขอทั้งหมด'}
    </span>
    <span className="inline-flex items-center gap-1.5">
      <span style={{ width: 10, height: 10, borderRadius: 2, background: colors.alerts, display: 'inline-block' }} />
      {lang === 'en' ? 'Blocked or alerted' : 'ถูกบล็อกหรือแจ้งเตือน'}
    </span>
  </div>
)

export default ReportChart
