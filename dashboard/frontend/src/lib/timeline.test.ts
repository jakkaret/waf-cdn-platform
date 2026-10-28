import { describe, expect, it } from 'vitest'
import { bucketLabel, bucketSizeFor, buildTimeline } from './timeline'

describe('buildTimeline', () => {
  it('is empty without rows', () => {
    expect(buildTimeline([]).buckets).toEqual([])
  })

  it('keeps empty buckets so the x axis follows real time', () => {
    // 11:55:01 then 12:03:33 UTC: eight empty minutes in between.
    const { buckets, bucketMs } = buildTimeline([
      { datetime: '2026-10-28 11:55:01', status: 200 },
      { datetime: '2026-10-28 12:03:33', status: 403 },
    ])
    expect(bucketMs).toBe(60_000)
    expect(buckets).toHaveLength(9)
    expect(buckets[0]).toMatchObject({ allowed: 1, blocked: 0 })
    expect(buckets[8]).toMatchObject({ allowed: 0, blocked: 1 })
    expect(buckets.slice(1, 8).every((b) => b.allowed + b.blocked + b.limited === 0)).toBe(true)
    expect(buckets[1].t - buckets[0].t).toBe(60_000)
  })

  it('separates blocked (403) and rate limited (429)', () => {
    const { buckets } = buildTimeline([
      { datetime: '2026-10-28 10:00:10', status: 403 },
      { datetime: '2026-10-28 10:00:20', status: 429 },
      { datetime: '2026-10-28 10:00:30', status: 404 },
    ])
    expect(buckets).toEqual([{ t: Date.UTC(2026, 9, 28, 10, 0), allowed: 1, blocked: 1, limited: 1 }])
  })

  it('skips rows whose time cannot be read', () => {
    expect(buildTimeline([{ datetime: 'nonsense', status: 200 }]).buckets).toEqual([])
  })
})

describe('bucketSizeFor', () => {
  it('grows with the span to keep the bucket count bounded', () => {
    expect(bucketSizeFor(10 * 60_000)).toBe(60_000)
    expect(bucketSizeFor(5 * 3600_000)).toBe(5 * 60_000)
    expect(bucketSizeFor(3 * 86400_000)).toBe(3600_000)
    expect(bucketLabel(5 * 60_000)).toBe('per 5 min')
    expect(bucketLabel(3600_000)).toBe('per 1 h')
  })
})
