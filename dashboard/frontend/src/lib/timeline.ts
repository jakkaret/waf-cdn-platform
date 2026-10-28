import { parseServerTime } from './time'

// The dashboard's traffic timeline, built from the latest log rows. Rows are
// counted into fixed time buckets and every bucket between the first and last
// row is kept, empty ones included, so the x axis is proportional to time: a
// gap of eight minutes looks like eight minutes, not like the next tick.

export interface TimelineBucket {
  t: number // bucket start, epoch ms
  allowed: number
  blocked: number
  limited: number
}

interface LogLike {
  datetime: string
  status: number
}

const MINUTE = 60_000
const STEPS = [MINUTE, 5 * MINUTE, 15 * MINUTE, 60 * MINUTE, 6 * 60 * MINUTE, 24 * 60 * MINUTE]
const MAX_BUCKETS = 120

// The smallest step that keeps the span under MAX_BUCKETS buckets.
export function bucketSizeFor(spanMs: number): number {
  return STEPS.find((s) => spanMs / s <= MAX_BUCKETS) ?? STEPS[STEPS.length - 1]
}

export function buildTimeline(logs: LogLike[]): { buckets: TimelineBucket[]; bucketMs: number; from: number | null; to: number | null } {
  const points = logs
    .map((l) => ({ t: parseServerTime(l.datetime)?.getTime(), status: l.status }))
    .filter((p): p is { t: number; status: number } => typeof p.t === 'number')
  if (points.length === 0) return { buckets: [], bucketMs: MINUTE, from: null, to: null }

  const from = Math.min(...points.map((p) => p.t))
  const to = Math.max(...points.map((p) => p.t))
  const bucketMs = bucketSizeFor(to - from)
  const start = Math.floor(from / bucketMs) * bucketMs
  const count = Math.floor((to - start) / bucketMs) + 1
  const buckets: TimelineBucket[] = Array.from({ length: count }, (_, i) => ({
    t: start + i * bucketMs,
    allowed: 0,
    blocked: 0,
    limited: 0,
  }))
  for (const p of points) {
    const b = buckets[Math.floor((p.t - start) / bucketMs)]
    if (p.status === 403) b.blocked++
    else if (p.status === 429) b.limited++
    else b.allowed++
  }
  return { buckets, bucketMs, from, to }
}

export function bucketLabel(bucketMs: number): string {
  if (bucketMs >= 24 * 60 * MINUTE) return 'per day'
  if (bucketMs >= 60 * MINUTE) return `per ${bucketMs / (60 * MINUTE)} h`
  return `per ${bucketMs / MINUTE} min`
}
