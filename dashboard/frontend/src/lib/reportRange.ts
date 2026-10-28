// Date-range logic for the origin Reports tab (an Agoda-style picker: pick
// the first and last day on a calendar, then the times). Days are Bangkok
// calendar days written "YYYY-MM-DD"; arithmetic runs on UTC midnights so the
// browser's own time zone never shifts a day. Times are "HH:MM", Bangkok.

import { bkkDateKey, formatBkkTime } from './time'
import type { Lang } from '../i18n'

export type DateKey = string

export interface ReportRange {
  start: DateKey | null
  end: DateKey | null
  startTime: string
  endTime: string
}

// access_logs keep this many days (services/clickhouse_service.py
// ACCESS_LOGS_RETENTION_DAYS); older days have no rows to report on.
export const RETENTION_DAYS = 30

const KEY_RE = /^(\d{4})-(\d{2})-(\d{2})$/
const TIME_RE = /^([01]\d|2[0-3]):([0-5]\d)$/

const toUtc = (key: DateKey): number => {
  const m = KEY_RE.exec(key)
  if (!m) return NaN
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))
}

const fromUtc = (ms: number): DateKey => new Date(ms).toISOString().slice(0, 10)

export const isDateKey = (v: unknown): v is DateKey => typeof v === 'string' && KEY_RE.test(v) && !isNaN(toUtc(v))
export const isTime = (v: unknown): v is string => typeof v === 'string' && TIME_RE.test(v)

export const addDays = (key: DateKey, n: number): DateKey => fromUtc(toUtc(key) + n * 86_400_000)

// Calendar days a range touches, counting both ends: the same day is 1.
// null when the end is before the start.
export function daysInclusive(start: DateKey, end: DateKey): number | null {
  const diff = Math.round((toUtc(end) - toUtc(start)) / 86_400_000)
  return diff < 0 ? null : diff + 1
}

const minutesOf = (time: string): number => {
  const m = TIME_RE.exec(time)
  return m ? Number(m[1]) * 60 + Number(m[2]) : NaN
}

// Exact length of start-day startTime .. end-day endTime, in minutes.
// null when either bound is missing or the end is not after the start.
export function durationMinutes(r: ReportRange): number | null {
  if (!r.start || !r.end || !isTime(r.startTime) || !isTime(r.endTime)) return null
  const mins = (toUtc(r.end) - toUtc(r.start)) / 60_000 + minutesOf(r.endTime) - minutesOf(r.startTime)
  return mins > 0 ? mins : null
}

// "2 วัน 3 ชม. 15 นาที", "45 นาที", "1 วัน" ("2 days 3 h 15 min" in English)
export function formatDurationTh(minutes: number, lang: Lang = 'th'): string {
  const d = Math.floor(minutes / 1440)
  const h = Math.floor((minutes % 1440) / 60)
  const m = minutes % 60
  const en = lang === 'en'
  const parts: string[] = []
  if (d) parts.push(en ? `${d} day${d === 1 ? '' : 's'}` : `${d} วัน`)
  if (h) parts.push(en ? `${h} h` : `${h} ชม.`)
  if (m || !parts.length) parts.push(en ? `${m} min` : `${m} นาที`)
  return parts.join(' ')
}

// What the backend reads as Bangkok wall time (api/ai_summary.py _TIME_FORMATS).
export const toApiTime = (key: DateKey, time: string): string => `${key}T${time}:00`

export function nowBkk(now: Date = new Date()): { date: DateKey; time: string } {
  return { date: bkkDateKey(now), time: formatBkkTime(now) }
}

export const earliestDay = (today: DateKey): DateKey => addDays(today, -RETENTION_DAYS)

export type QuickRange = '24h' | '7d' | '30d'

export const QUICK_RANGES: { id: QuickRange; label: string; labelEn: string; days: number }[] = [
  { id: '24h', label: '24 ชั่วโมง', labelEn: '24 hours', days: 1 },
  { id: '7d', label: '7 วัน', labelEn: '7 days', days: 7 },
  { id: '30d', label: '30 วัน', labelEn: '30 days', days: 30 },
]

// The last N days up to now, e.g. 24h = yesterday 14:05 to today 14:05.
export function quickRange(id: QuickRange, now: { date: DateKey; time: string }): ReportRange {
  const days = QUICK_RANGES.find((q) => q.id === id)?.days ?? 1
  return { start: addDays(now.date, -days), end: now.date, startTime: now.time, endTime: now.time }
}

export function matchesQuickRange(r: ReportRange, now: { date: DateKey; time: string }): QuickRange | null {
  for (const q of QUICK_RANGES) {
    const c = quickRange(q.id, now)
    if (c.start === r.start && c.end === r.end && c.startTime === r.startTime && c.endTime === r.endTime) return q.id
  }
  return null
}

// One click on a calendar day. The first click starts a range, the second
// ends it; a click before the start, or after a finished range, starts over.
export function pickDay(
  sel: { start: DateKey | null; end: DateKey | null },
  day: DateKey,
): { start: DateKey | null; end: DateKey | null; done: boolean } {
  if (!sel.start || sel.end) return { start: day, end: null, done: false }
  if (day < sel.start) return { start: day, end: null, done: false }
  return { start: sel.start, end: day, done: true }
}

// Default times once days are chosen: the whole first and last day, but not
// past now when the last day is today.
export function defaultTimes(end: DateKey, now: { date: DateKey; time: string }): { startTime: string; endTime: string } {
  return { startTime: '00:00', endTime: end === now.date ? now.time : '23:59' }
}

// A sentence saying what is wrong, or null when the range can be sent.
export function validateRange(r: ReportRange, now: { date: DateKey; time: string }, lang: Lang = 'th'): string | null {
  const t = (en: string, th: string) => (lang === 'en' ? en : th)
  if (!r.start || !r.end) return t('Pick a start day and an end day first', 'เลือกวันเริ่มและวันสิ้นสุดก่อน')
  if (!isTime(r.startTime) || !isTime(r.endTime)) return t('Enter both a start time and an end time', 'ใส่เวลาเริ่มและเวลาสิ้นสุดให้ครบ')
  if (durationMinutes(r) === null) return t('The end time must be after the start time', 'เวลาสิ้นสุดต้องอยู่หลังเวลาเริ่ม')
  if (r.end > now.date || (r.end === now.date && r.endTime > now.time)) return t('The end time is in the future; pick a time up to now', 'เวลาสิ้นสุดเลยเวลาปัจจุบัน เลือกให้ไม่เกินตอนนี้')
  if (r.start < earliestDay(now.date))
    return t(`Logs are kept for ${RETENTION_DAYS} days; pick a start day within that`, `ระบบเก็บ log ไว้ ${RETENTION_DAYS} วัน เลือกวันเริ่มให้ไม่เก่ากว่านั้น`)
  return null
}

// Weeks of one month, Sunday first, as in Thai wall calendars. Days outside
// the month are null.
export function monthGrid(month: DateKey): (DateKey | null)[][] {
  const first = `${month.slice(0, 7)}-01`
  const lead = new Date(toUtc(first)).getUTCDay()
  const days: (DateKey | null)[] = Array(lead).fill(null)
  for (let d = first; d.slice(0, 7) === first.slice(0, 7); d = addDays(d, 1)) days.push(d)
  while (days.length % 7) days.push(null)
  const weeks: (DateKey | null)[][] = []
  for (let i = 0; i < days.length; i += 7) weeks.push(days.slice(i, i + 7))
  return weeks
}

export const monthOf = (key: DateKey): DateKey => `${key.slice(0, 7)}-01`

export function addMonths(month: DateKey, n: number): DateKey {
  const y = Number(month.slice(0, 4))
  const m = Number(month.slice(5, 7)) - 1 + n
  return fromUtc(Date.UTC(y + Math.floor(m / 12), ((m % 12) + 12) % 12, 1))
}

const thFmt = (opts: Intl.DateTimeFormatOptions, lang: Lang = 'th') =>
  new Intl.DateTimeFormat(lang === 'en' ? 'en-GB' : 'th-TH', { timeZone: 'UTC', ...opts })

// "ตุลาคม 2569" ("October 2026")
export const monthLabelTh = (month: DateKey, lang: Lang = 'th'): string => thFmt({ month: 'long', year: 'numeric' }, lang).format(toUtc(month))

// "อ. 28 ต.ค." ("Tue 28 Oct")
export const dayLabelTh = (key: DateKey, lang: Lang = 'th'): string =>
  thFmt({ weekday: 'short', day: 'numeric', month: 'short' }, lang).format(toUtc(key))

// "28 ตุลาคม 2569", for formal documents
export const longDateTh = (key: DateKey): string => thFmt({ day: 'numeric', month: 'long', year: 'numeric' }).format(toUtc(key))

export const WEEKDAYS_TH = ['อา', 'จ', 'อ', 'พ', 'พฤ', 'ศ', 'ส']
export const WEEKDAYS_EN = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa']

// Split a backend "YYYY-MM-DD HH:MM:SS" (Bangkok) into a day and "HH:MM".
export function splitBkk(text: string | null | undefined): { date: DateKey; time: string } | null {
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})/.exec(text ?? '')
  return m ? { date: m[1], time: m[2] } : null
}
