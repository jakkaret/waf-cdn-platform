import { describe, expect, it } from 'vitest'
import { bkkDateKey, formatBkkDateTime, formatBkkTime, parseServerTime } from './time'

describe('Bangkok time', () => {
  it('reads offset-less server strings as UTC', () => {
    expect(parseServerTime('2026-10-25 06:14:00')?.toISOString()).toBe('2026-10-25T06:14:00.000Z')
    expect(parseServerTime('2026-10-25T06:14:00')?.toISOString()).toBe('2026-10-25T06:14:00.000Z')
    expect(parseServerTime('2026-10-25T06:14:00+00:00')?.toISOString()).toBe('2026-10-25T06:14:00.000Z')
    expect(parseServerTime(1792942033)?.toISOString()).toBe('2026-10-25T15:27:13.000Z')
    expect(parseServerTime('not a date')).toBeNull()
  })

  it('shows UTC+7 whatever the browser zone is', () => {
    expect(formatBkkDateTime('2026-10-25 18:30:05')).toBe('2026-10-26 01:30:05')
    expect(formatBkkDateTime('2026-10-25T18:30:05Z', { seconds: false })).toBe('2026-10-26 01:30')
    expect(formatBkkTime('2026-10-25 00:05:00')).toBe('07:05')
    expect(formatBkkTime('2026-10-25 00:05:09', { seconds: true })).toBe('07:05:09')
  })

  it('uses the Bangkok calendar day', () => {
    // 20:00 UTC on the 24th is already the 25th in Bangkok
    expect(bkkDateKey('2026-10-24T20:00:00Z')).toBe('2026-10-25')
    expect(bkkDateKey('2026-10-24T16:59:59Z')).toBe('2026-10-24')
  })

  it('keeps empty and unreadable values readable', () => {
    expect(formatBkkDateTime(null)).toBe('—')
    expect(formatBkkDateTime('soon')).toBe('soon')
  })
})
