// Helpers for acting on an alert or a log row (UX reorganization 2026-10-28).
import { looksLikeIp } from './siteAccess'

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

// The severity the detection recorded, or null when it recorded none. The
// HTTP status (403, 429...) is the WAF's answer to the client, not a threat
// level, so it is never used to guess one.
export function alertSeverity(severity: string | null | undefined): Severity | null {
  const s = String(severity ?? '').trim().toUpperCase()
  return (SEVERITIES as string[]).includes(s) ? (s as Severity) : null
}

// Traffic logs filtered to one client IP. Logs reads ?search= on load.
export const logsSearchPath = (query: string) => `/logs?${new URLSearchParams({ search: query }).toString()}`

// A single IPv4/IPv6 address the IP access form accepts as a prefill. Anything
// else (empty, "unknown", a host name, a range) is not offered as a block target.
export function isBlockableIp(value: string | null | undefined): boolean {
  const v = String(value ?? '').trim()
  return v !== '' && !v.includes('/') && looksLikeIp(v)
}
