import { describe, it, expect } from 'vitest'
import type { Postmortem } from '../types'
import { blockedShare, buildReportMarkdown, rangeFacts, reportFileBase, reportNumber, reportSeries } from './reportExport'

const base: Postmortem = {
  id: '1a2b3c4d-5e6f-7a8b-9c0d-112233445566',
  origin_id: 'o1',
  origin_label: 'demo-final.originweb.site',
  created_by_username: 'ecommerapp',
  created_at: '2026-10-28T07:00:00+00:00',
  start_time: '2026-10-27 09:00:00',
  end_time: '2026-10-28 12:00:00',
  stats: { total_requests: 493, total_alerts: 31, top_attack_types: [{ type: 'SQL Injection', count: 12 }] },
  has_ai_narrative: true,
  hourly_buckets: [
    { hour: '2026-10-27 09:00:00', requests: 10, alerts: 1 },
    { hour: '2026-10-28 11:00:00', requests: 5, alerts: 2 },
  ],
  audit_events: [],
  ai_narrative: '**สรุป**\n- พบ SQLi | ทดสอบ <script>alert(1)</script>',
  ai_narrative_degraded: false,
}

describe('reportNumber and file name', () => {
  it('uses the Bangkok day it was written and the id prefix', () => {
    expect(reportNumber(base)).toBe('IR-20261028-1A2B3C4D')
  })
  it('makes a safe file name', () => {
    expect(reportFileBase({ ...base, origin_label: 'My Shop/../x' })).toBe('incident-report_my-shop-..-x_2026-10-27_2026-10-28')
  })
})

describe('rangeFacts', () => {
  it('counts calendar days and the exact span', () => {
    expect(rangeFacts(base)).toEqual({ days: 2, duration: '1 วัน 3 ชม.' })
  })
})

describe('reportSeries', () => {
  it('fills every hour of a short range with zeros', () => {
    const s = reportSeries(base)
    expect(s.unit).toBe('hour')
    expect(s.points).toHaveLength(28) // 09..23 on day 1 (15) + 00..12 on day 2 (13)
    expect(s.points[0]).toEqual({ key: '2026-10-27 09', requests: 10, alerts: 1 })
    expect(s.points.find((p) => p.key === '2026-10-28 11')).toEqual({ key: '2026-10-28 11', requests: 5, alerts: 2 })
    expect(s.points.find((p) => p.key === '2026-10-27 15')).toEqual({ key: '2026-10-27 15', requests: 0, alerts: 0 })
  })
  it('switches to days past three days', () => {
    const s = reportSeries({ ...base, start_time: '2026-10-20 00:00:00', end_time: '2026-10-28 12:00:00' })
    expect(s.unit).toBe('day')
    expect(s.points).toHaveLength(9)
    expect(s.points.find((p) => p.key === '2026-10-27')).toEqual({ key: '2026-10-27', requests: 10, alerts: 1 })
  })
})

describe('blockedShare', () => {
  it('is a percentage, or a dash with no traffic', () => {
    expect(blockedShare(base)).toBe('6.3%')
    expect(blockedShare({ stats: { total_requests: 0, total_alerts: 0, top_attack_types: [] } })).toBe('—')
  })
})

describe('buildReportMarkdown', () => {
  const md = buildReportMarkdown(base, new Date('2026-10-28T09:30:00Z'))
  it('carries the header facts', () => {
    expect(md).toContain('IR-20261028-1A2B3C4D')
    expect(md).toContain('| จำนวนวัน | 2 วัน (รวม 1 วัน 3 ชม.) |')
    expect(md).toContain('| วันที่ส่งออก | 2026-10-28 16:30 |')
  })
  it('keeps the AI narrative as text and marks it as AI-drafted', () => {
    expect(md).toContain('ร่างโดย AI')
    expect(md).toContain('<script>alert(1)</script>') // plain text in a .md file, never rendered here
  })
  it('escapes pipes inside table cells', () => {
    const m = buildReportMarkdown({ ...base, stats: { ...base.stats, top_attack_types: [{ type: 'a|b', count: 1 }] } })
    expect(m).toContain('| 1 | a\\|b | 1 |')
  })
})
