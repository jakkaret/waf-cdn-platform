// Helpers for a site's IP access list and rate limits (components/OriginIpAccess.tsx,
// components/OriginRateLimits.tsx). The backend re-checks everything.

export const DURATIONS: { label: string; labelTh: string; hours: number | null }[] = [
  { label: 'Permanent', labelTh: 'ถาวร', hours: null },
  { label: '1 hour', labelTh: '1 ชั่วโมง', hours: 1 },
  { label: '24 hours', labelTh: '24 ชั่วโมง', hours: 24 },
  { label: '7 days', labelTh: '7 วัน', hours: 24 * 7 },
  { label: '30 days', labelTh: '30 วัน', hours: 24 * 30 },
]

// A quick check before sending: an IPv4/IPv6 address, optionally with a /prefix.
export function looksLikeIp(value: string): boolean {
  const v = value.trim()
  const [addr, prefix, extra] = v.split('/')
  if (extra !== undefined || !addr) return false
  if (prefix !== undefined && !/^\d{1,3}$/.test(prefix)) return false
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr)
  if (v4) return v4.slice(1).every((n) => Number(n) <= 255) && (prefix === undefined || Number(prefix) <= 32)
  return addr.includes(':') && /^[0-9a-fA-F:.]+$/.test(addr) && (prefix === undefined || Number(prefix) <= 128)
}

export function looksLikePathPattern(value: string): boolean {
  const v = value.trim()
  return v === '*' || (v.startsWith('/') && !/\s/.test(v) && v.length <= 200)
}

// "60 / 1 min", "10 / 30 s", "100 / 1 h"
export function rateText(limit: number, windowSeconds: number): string {
  const w = windowSeconds % 3600 === 0 ? `${windowSeconds / 3600} h`
    : windowSeconds % 60 === 0 ? `${windowSeconds / 60} min`
    : `${windowSeconds} s`
  return `${limit} / ${w}`
}
