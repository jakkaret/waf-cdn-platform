// Every time on the dashboard is shown in Bangkok time (Asia/Bangkok, UTC+7),
// whatever the viewer's browser is set to. The backend stores UTC; ClickHouse
// returns offset-less strings ("2026-10-25 06:14:00") that are UTC as well.

export const BKK_TZ = 'Asia/Bangkok'
export const BKK_LABEL = 'Bangkok'

type TimeInput = string | number | Date | null | undefined

// Offset-less strings are UTC; epoch numbers may be seconds or milliseconds.
export function parseServerTime(raw: TimeInput): Date | null {
  if (raw === null || raw === undefined || raw === '') return null
  let d: Date
  if (raw instanceof Date) d = raw
  else if (typeof raw === 'number') d = new Date(raw < 1e12 ? raw * 1000 : raw)
  else {
    let s = String(raw).trim()
    if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s = s.replace(' ', 'T') + 'Z'
    d = new Date(s)
  }
  return isNaN(d.getTime()) ? null : d
}

const partsOf = (d: Date, withDate: boolean, withSeconds: boolean): Record<string, string> => {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: BKK_TZ,
    ...(withDate ? { year: 'numeric', month: '2-digit', day: '2-digit' } : {}),
    hour: '2-digit',
    minute: '2-digit',
    ...(withSeconds ? { second: '2-digit' } : {}),
    hourCycle: 'h23',
  }).formatToParts(d)
  return Object.fromEntries(parts.map((p) => [p.type, p.value]))
}

// "2026-10-25 21:34:02"
export function formatBkkDateTime(raw: TimeInput, opts: { seconds?: boolean } = {}): string {
  const d = parseServerTime(raw)
  if (!d) return raw ? String(raw) : '—'
  const seconds = opts.seconds ?? true
  const p = partsOf(d, true, seconds)
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}${seconds ? `:${p.second}` : ''}`
}

// "21:34" or "21:34:02"
export function formatBkkTime(raw: TimeInput, opts: { seconds?: boolean } = {}): string {
  const d = parseServerTime(raw)
  if (!d) return raw ? String(raw) : '—'
  const p = partsOf(d, false, !!opts.seconds)
  return `${p.hour}:${p.minute}${opts.seconds ? `:${p.second}` : ''}`
}

// "2026-10-25": the Bangkok calendar day, also for date inputs and file names.
export function bkkDateKey(raw: TimeInput = new Date()): string {
  const d = parseServerTime(raw)
  if (!d) return ''
  const p = partsOf(d, true, false)
  return `${p.year}-${p.month}-${p.day}`
}
