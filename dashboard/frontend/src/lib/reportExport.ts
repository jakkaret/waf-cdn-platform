// Turns a saved incident report (api/ai_summary.py create_postmortem) into
// what the Reports tab exports: a chart series, a Markdown summary and the
// fields of the formal PDF. Times in a report are Bangkok wall time already.
// The AI narrative is untrusted text (it can quote attacker-controlled paths):
// it only ever goes out as text, never as HTML.

import type { Postmortem } from '../types'
import { addDays, daysInclusive, durationMinutes, formatDurationTh, splitBkk } from './reportRange'
import { bkkDateKey, formatBkkDateTime } from './time'

export interface SeriesPoint {
  key: string // "2026-10-27 09" (hour) or "2026-10-27" (day)
  requests: number
  alerts: number
}

const MAX_HOURLY_POINTS = 72

// Report number shown on the PDF: IR-<day it was written>-<first 8 of its id>.
export function reportNumber(p: Pick<Postmortem, 'id' | 'created_at'>): string {
  const day = bkkDateKey(p.created_at).replace(/-/g, '') || '00000000'
  return `IR-${day}-${String(p.id || '').replace(/-/g, '').slice(0, 8).toUpperCase()}`
}

export function reportFileBase(p: Pick<Postmortem, 'origin_label' | 'start_time' | 'end_time'>): string {
  const site = (p.origin_label || 'origin').toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '') || 'origin'
  const s = splitBkk(p.start_time)?.date ?? 'start'
  const e = splitBkk(p.end_time)?.date ?? 'end'
  return `incident-report_${site}_${s}_${e}`
}

export function rangeFacts(p: Pick<Postmortem, 'start_time' | 'end_time'>): { days: number | null; duration: string | null } {
  const s = splitBkk(p.start_time)
  const e = splitBkk(p.end_time)
  if (!s || !e) return { days: null, duration: null }
  const mins = durationMinutes({ start: s.date, end: e.date, startTime: s.time, endTime: e.time })
  return { days: daysInclusive(s.date, e.date), duration: mins === null ? null : formatDurationTh(mins) }
}

// Every hour of the range, zero-filled (the backend sends only hours that
// had traffic). Ranges longer than three days become one point per day.
export function reportSeries(p: Pick<Postmortem, 'start_time' | 'end_time' | 'hourly_buckets'>): { unit: 'hour' | 'day'; points: SeriesPoint[] } {
  const s = splitBkk(p.start_time)
  const e = splitBkk(p.end_time)
  const byHour = new Map<string, { requests: number; alerts: number }>()
  for (const b of p.hourly_buckets || []) {
    const k = String(b.hour).slice(0, 13)
    const prev = byHour.get(k) || { requests: 0, alerts: 0 }
    byHour.set(k, { requests: prev.requests + (b.requests || 0), alerts: prev.alerts + (b.alerts || 0) })
  }
  if (!s || !e) {
    return { unit: 'hour', points: [...byHour.entries()].map(([key, v]) => ({ key, ...v })) }
  }
  const days = daysInclusive(s.date, e.date) ?? 1
  const hours: string[] = []
  for (let d = s.date, i = 0; i < days; d = addDays(d, 1), i++) {
    const from = d === s.date ? Number(s.time.slice(0, 2)) : 0
    const to = d === e.date ? Number(e.time.slice(0, 2)) : 23
    for (let h = from; h <= to; h++) hours.push(`${d} ${String(h).padStart(2, '0')}`)
  }
  if (hours.length <= MAX_HOURLY_POINTS) {
    return { unit: 'hour', points: hours.map((key) => ({ key, ...(byHour.get(key) || { requests: 0, alerts: 0 }) })) }
  }
  const byDay = new Map<string, SeriesPoint>()
  for (const key of hours) {
    const day = key.slice(0, 10)
    const v = byHour.get(key) || { requests: 0, alerts: 0 }
    const prev = byDay.get(day) || { key: day, requests: 0, alerts: 0 }
    byDay.set(day, { key: day, requests: prev.requests + v.requests, alerts: prev.alerts + v.alerts })
  }
  return { unit: 'day', points: [...byDay.values()] }
}

export function blockedShare(p: Pick<Postmortem, 'stats'>): string {
  const total = p.stats?.total_requests ?? 0
  const blocked = p.stats?.total_alerts ?? 0
  if (!total) return '—'
  return `${((blocked / total) * 100).toFixed(1)}%`
}

const n = (v: number | undefined | null) => (v ?? 0).toLocaleString('en-US')

// A Markdown table cell must not break the row.
const cell = (t: string) => String(t ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ')

export function buildReportMarkdown(p: Postmortem, printedAt: Date = new Date()): string {
  const facts = rangeFacts(p)
  const lines: string[] = []
  lines.push(`# รายงานสรุปเหตุการณ์ด้านความปลอดภัย (Incident Report)`)
  lines.push('')
  lines.push(`| รายการ | รายละเอียด |`)
  lines.push(`| --- | --- |`)
  lines.push(`| เลขที่รายงาน | ${reportNumber(p)} |`)
  lines.push(`| เว็บไซต์ | ${cell(p.origin_label)} |`)
  lines.push(`| ช่วงเวลา (เวลาไทย) | ${cell(p.start_time)} ถึง ${cell(p.end_time)} |`)
  if (facts.days !== null) lines.push(`| จำนวนวัน | ${facts.days} วัน${facts.duration ? ` (รวม ${facts.duration})` : ''} |`)
  lines.push(`| จัดทำโดย | ${cell(p.created_by_username || '—')} |`)
  lines.push(`| วันที่จัดทำ | ${formatBkkDateTime(p.created_at, { seconds: false })} |`)
  lines.push(`| วันที่ส่งออก | ${formatBkkDateTime(printedAt, { seconds: false })} |`)
  lines.push('')
  lines.push(`## 1. สถิติในช่วงเวลา`)
  lines.push('')
  lines.push(`| ตัวชี้วัด | ค่า |`)
  lines.push(`| --- | ---: |`)
  lines.push(`| คำขอทั้งหมด | ${n(p.stats?.total_requests)} |`)
  lines.push(`| ถูกบล็อกหรือแจ้งเตือน | ${n(p.stats?.total_alerts)} |`)
  lines.push(`| สัดส่วนที่ถูกบล็อก | ${blockedShare(p)} |`)
  lines.push('')
  lines.push(`## 2. ประเภทการโจมตีที่พบมากที่สุด`)
  lines.push('')
  const types = p.stats?.top_attack_types || []
  if (types.length) {
    lines.push(`| ลำดับ | ประเภท | จำนวน |`)
    lines.push(`| ---: | --- | ---: |`)
    types.forEach((t, i) => lines.push(`| ${i + 1} | ${cell(t.type)} | ${n(t.count)} |`))
  } else {
    lines.push(`ไม่พบประเภทการโจมตีในช่วงเวลานี้`)
  }
  lines.push('')
  lines.push(`## 3. บทสรุป (ร่างโดย AI โปรดตรวจทานก่อนเผยแพร่)`)
  lines.push('')
  lines.push(p.ai_narrative ? p.ai_narrative.trim() : 'ไม่มีบทสรุปจาก AI สำหรับรายงานนี้')
  if (p.ai_narrative_degraded) lines.push('', '_หมายเหตุ: บทสรุปจาก AI อาจไม่ครบถ้วน_')
  lines.push('')
  lines.push(`## 4. การเปลี่ยนแปลงในระบบช่วงเวลาเดียวกัน (audit log)`)
  lines.push('')
  const events = p.audit_events || []
  if (events.length) {
    lines.push(`| เวลา | ผู้ดำเนินการ | รายการ |`)
    lines.push(`| --- | --- | --- |`)
    events.forEach((ev) =>
      lines.push(`| ${formatBkkDateTime(ev.timestamp, { seconds: false })} | ${cell(ev.actor_username || '—')} | ${cell(ev.summary || ev.action)} |`),
    )
  } else {
    lines.push(`ไม่มีการเปลี่ยนแปลงในช่วงเวลานี้`)
  }
  lines.push('')
  lines.push(`---`)
  lines.push(`ตัวเลขทั้งหมดมาจาก log ของระบบ WAF โดยตรง ส่วนบทสรุปร่างโดย AI`)
  return lines.join('\n') + '\n'
}
