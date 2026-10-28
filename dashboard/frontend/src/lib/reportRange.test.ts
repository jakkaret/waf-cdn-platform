import { describe, it, expect } from 'vitest'
import {
  addDays,
  addMonths,
  daysInclusive,
  defaultTimes,
  durationMinutes,
  formatDurationTh,
  matchesQuickRange,
  monthGrid,
  monthLabelTh,
  pickDay,
  quickRange,
  splitBkk,
  toApiTime,
  validateRange,
} from './reportRange'

const NOW = { date: '2026-10-28', time: '14:05' }

describe('daysInclusive', () => {
  it('counts the same day as one day', () => {
    expect(daysInclusive('2026-10-28', '2026-10-28')).toBe(1)
  })
  it('counts both ends across a month boundary', () => {
    expect(daysInclusive('2026-10-30', '2026-11-02')).toBe(4)
  })
  it('crosses a year and a leap day', () => {
    expect(daysInclusive('2027-12-31', '2028-03-01')).toBe(62)
  })
  it('is null when the end is before the start', () => {
    expect(daysInclusive('2026-10-28', '2026-10-27')).toBeNull()
  })
})

describe('durationMinutes and formatDurationTh', () => {
  it('measures across days', () => {
    const m = durationMinutes({ start: '2026-10-27', end: '2026-10-28', startTime: '09:00', endTime: '12:15' })
    expect(m).toBe(27 * 60 + 15)
    expect(formatDurationTh(m!)).toBe('1 วัน 3 ชม. 15 นาที')
  })
  it('is null for an empty or backwards range', () => {
    expect(durationMinutes({ start: '2026-10-28', end: '2026-10-28', startTime: '10:00', endTime: '10:00' })).toBeNull()
    expect(durationMinutes({ start: '2026-10-28', end: '2026-10-28', startTime: '10:00', endTime: '09:59' })).toBeNull()
    expect(durationMinutes({ start: null, end: '2026-10-28', startTime: '10:00', endTime: '11:00' })).toBeNull()
  })
  it('formats short and whole-day spans', () => {
    expect(formatDurationTh(45)).toBe('45 นาที')
    expect(formatDurationTh(1440)).toBe('1 วัน')
    expect(formatDurationTh(0)).toBe('0 นาที')
  })
})

describe('pickDay', () => {
  it('starts, then ends a range', () => {
    const a = pickDay({ start: null, end: null }, '2026-10-20')
    expect(a).toEqual({ start: '2026-10-20', end: null, done: false })
    expect(pickDay(a, '2026-10-24')).toEqual({ start: '2026-10-20', end: '2026-10-24', done: true })
  })
  it('allows a single-day range', () => {
    expect(pickDay({ start: '2026-10-20', end: null }, '2026-10-20')).toEqual({ start: '2026-10-20', end: '2026-10-20', done: true })
  })
  it('restarts on a click before the start', () => {
    expect(pickDay({ start: '2026-10-20', end: null }, '2026-10-18')).toEqual({ start: '2026-10-18', end: null, done: false })
  })
  it('restarts after a finished range', () => {
    expect(pickDay({ start: '2026-10-20', end: '2026-10-22' }, '2026-10-25')).toEqual({ start: '2026-10-25', end: null, done: false })
  })
})

describe('quick ranges', () => {
  it('ends now and reaches back whole days', () => {
    expect(quickRange('24h', NOW)).toEqual({ start: '2026-10-27', end: '2026-10-28', startTime: '14:05', endTime: '14:05' })
    expect(quickRange('30d', NOW).start).toBe('2026-09-28')
  })
  it('recognises a range it produced', () => {
    expect(matchesQuickRange(quickRange('7d', NOW), NOW)).toBe('7d')
    expect(matchesQuickRange({ ...quickRange('7d', NOW), endTime: '14:00' }, NOW)).toBeNull()
  })
})

describe('defaultTimes', () => {
  it('covers whole days but stops at now on today', () => {
    expect(defaultTimes('2026-10-27', NOW)).toEqual({ startTime: '00:00', endTime: '23:59' })
    expect(defaultTimes('2026-10-28', NOW)).toEqual({ startTime: '00:00', endTime: '14:05' })
  })
})

describe('validateRange', () => {
  const ok = { start: '2026-10-27', end: '2026-10-28', startTime: '09:00', endTime: '12:00' }
  it('accepts a past range', () => {
    expect(validateRange(ok, NOW)).toBeNull()
  })
  it('accepts every quick range', () => {
    expect(validateRange(quickRange('30d', NOW), NOW)).toBeNull()
  })
  it('rejects missing days, a backwards range, the future and expired days', () => {
    expect(validateRange({ ...ok, end: null }, NOW)).toMatch('เลือกวัน')
    expect(validateRange({ ...ok, start: '2026-10-28', endTime: '08:00' }, NOW)).toMatch('หลังเวลาเริ่ม')
    expect(validateRange({ ...ok, endTime: '14:06' }, NOW)).toMatch('เลยเวลาปัจจุบัน')
    expect(validateRange({ ...ok, end: '2026-10-29' }, NOW)).toMatch('เลยเวลาปัจจุบัน')
    expect(validateRange({ ...ok, start: '2026-09-27' }, NOW)).toMatch('30 วัน')
  })
})

describe('calendar helpers', () => {
  it('lays a month out Sunday first', () => {
    const weeks = monthGrid('2026-10-01')
    // 1 Oct 2026 is a Thursday.
    expect(weeks[0]).toEqual([null, null, null, null, '2026-10-01', '2026-10-02', '2026-10-03'])
    expect(weeks.flat().filter(Boolean)).toHaveLength(31)
    expect(weeks.every((w) => w.length === 7)).toBe(true)
  })
  it('steps months across a year', () => {
    expect(addMonths('2026-12-01', 1)).toBe('2027-01-01')
    expect(addMonths('2026-01-01', -1)).toBe('2025-12-01')
  })
  it('names months in the Thai calendar', () => {
    expect(monthLabelTh('2026-10-01')).toBe('ตุลาคม 2569')
  })
  it('adds days across a month', () => {
    expect(addDays('2026-10-30', 3)).toBe('2026-11-02')
  })
})

describe('backend time text', () => {
  it('sends Bangkok wall time the API parses', () => {
    expect(toApiTime('2026-10-27', '09:00')).toBe('2026-10-27T09:00:00')
  })
  it('splits a stored report bound', () => {
    expect(splitBkk('2026-10-27 09:00:00')).toEqual({ date: '2026-10-27', time: '09:00' })
    expect(splitBkk('garbage')).toBeNull()
  })
})
