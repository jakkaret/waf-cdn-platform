import React, { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQueries, useQuery } from '@tanstack/react-query'
import { ExternalLink, Search } from 'lucide-react'
import { getOrigins } from '../../api/origins'
import { getTenantRules } from '../../api/wafRules'
import { getSiteIpRules, getSiteRateRules } from '../../api/siteAccess'
import { useAuthStore } from '../../store/authStore'
import { rateText } from '../../lib/siteAccess'
import { originTabPath, type OriginTabId } from '../layout/navigation'
import { Badge } from '../ui/Badge'
import type { Origin } from '../../types'

// Every rule of every origin the person can open, in one table (UX
// reorganization 2026-10-28; this page used to say "your rules live on each
// origin" and stop). Rules are still created and edited on the origin's own
// tab, which checks the person's role there; each row links to it.
//
// Three read endpoints per origin, the same ones the origin tabs use, so the
// numbers here are the ones those tabs show.

export type RuleKind = 'waf' | 'ip' | 'rate'

export interface RuleRow {
  key: string
  kind: RuleKind
  originId: string
  originLabel: string
  title: string
  detail: string
  action: string
  enabled: boolean
  tab: OriginTabId
}

const KIND_LABEL: Record<RuleKind, string> = { waf: 'WAF rule', ip: 'IP access', rate: 'Rate limit' }
const KIND_TAB: Record<RuleKind, OriginTabId> = { waf: 'waf', ip: 'ip-access', rate: 'rate-limits' }

// Beyond this many origins the per-origin requests get heavy; the table says
// it is partial instead of silently dropping rows.
export const MAX_ORIGINS = 25

export const OriginRulesTable: React.FC = () => {
  const user = useAuthStore((s) => s.user)
  const [kind, setKind] = useState<RuleKind | 'all'>('all')
  const [originFilter, setOriginFilter] = useState('all')
  const [query, setQuery] = useState('')

  const originsQuery = useQuery({
    queryKey: ['origins-selector-list', user?.user_id],
    queryFn: () => getOrigins().then((r) => r.data?.origins || []),
    enabled: !!user,
  })
  const allOrigins: Origin[] = useMemo(
    () => (originsQuery.data ?? []).filter((o) => o?.origin_id && (o.status || '').toLowerCase() !== 'archived'),
    [originsQuery.data],
  )
  const origins = allOrigins.slice(0, MAX_ORIGINS)

  const results = useQueries({
    queries: origins.flatMap((o) => [
      { queryKey: ['tenant-rules', o.origin_id], queryFn: () => getTenantRules(o.origin_id).then((r) => r.data.rules) },
      { queryKey: ['site-ip-rules', o.origin_id], queryFn: () => getSiteIpRules(o.origin_id) },
      { queryKey: ['site-rate-limits', o.origin_id], queryFn: () => getSiteRateRules(o.origin_id) },
    ]),
  })

  const loading = originsQuery.isLoading || results.some((r) => r.isLoading)
  const failedOrigins = origins.filter((_, i) => results.slice(i * 3, i * 3 + 3).some((r) => r.isError))

  const rows: RuleRow[] = useMemo(() => {
    const out: RuleRow[] = []
    origins.forEach((o, i) => {
      const label = o.label || o.ip
      const [waf, ip, rate] = results.slice(i * 3, i * 3 + 3)
      for (const r of (waf?.data as any[] | undefined) ?? []) {
        out.push({
          key: `waf-${o.origin_id}-${r.id}`, kind: 'waf', originId: o.origin_id, originLabel: label,
          title: r.message || `Rule ${r.id}`, detail: `${r.variable} ${r.operator}`,
          action: String(r.action || '').toLowerCase(), enabled: !!r.enabled, tab: KIND_TAB.waf,
        })
      }
      for (const r of (ip?.data as any[] | undefined) ?? []) {
        out.push({
          key: `ip-${o.origin_id}-${r.id}`, kind: 'ip', originId: o.origin_id, originLabel: label,
          title: r.ip, detail: r.note || (r.expires_at ? 'Temporary' : 'Permanent'),
          action: r.action, enabled: true, tab: KIND_TAB.ip,
        })
      }
      for (const r of (rate?.data as any[] | undefined) ?? []) {
        out.push({
          key: `rate-${o.origin_id}-${r.id}`, kind: 'rate', originId: o.origin_id, originLabel: label,
          title: r.name || r.path_pattern, detail: `${r.method} ${r.path_pattern}, ${rateText(r.limit_count, r.window_seconds)}`,
          action: 'throttle', enabled: !!r.enabled, tab: KIND_TAB.rate,
        })
      }
    })
    return out
    // results is a new array each render; its data identities are what matter.
  },[origins.map((o) => o.origin_id).join(','), ...results.map((r) => r.data)])

  const q = query.trim().toLowerCase()
  const shown = rows.filter(
    (r) =>
      (kind === 'all' || r.kind === kind) &&
      (originFilter === 'all' || r.originId === originFilter) &&
      (!q || `${r.title} ${r.detail} ${r.originLabel}`.toLowerCase().includes(q)),
  )
  const counts = { waf: 0, ip: 0, rate: 0 } as Record<RuleKind, number>
  rows.forEach((r) => counts[r.kind]++)

  if (originsQuery.isError) {
    return <p className="m-0 text-[13px] text-red-600 dark:text-red-400">Could not load your origins. Reload the page to try again.</p>
  }

  if (!originsQuery.isLoading && allOrigins.length === 0) {
    return (
      <div className="dash-card p-6 text-[13px] text-[var(--text-secondary)] space-y-2">
        <p className="m-0 font-semibold text-[var(--text-primary)]">No origins yet</p>
        <p className="m-0">
          Rules belong to an origin. <Link to="/origins" className="text-[var(--accent)] hover:underline">Add an origin</Link> to
          create WAF rules, IP access entries and rate limits for it.
        </p>
      </div>
    )
  }

  return (
    <section className="space-y-3" aria-labelledby="origin-rules-heading">
      <h2 id="origin-rules-heading" className="sr-only">Rules on your origins</h2>
      <div className="flex flex-col lg:flex-row lg:items-center gap-3">
        <div role="group" aria-label="Rule type" className="flex flex-wrap gap-1">
          {(['all', 'waf', 'ip', 'rate'] as const).map((k) => (
            <button
              key={k}
              type="button"
              aria-pressed={kind === k}
              onClick={() => setKind(k)}
              className={`h-9 px-3 rounded-md text-[13px] cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
                kind === k ? 'bg-[var(--nav-active)] font-medium text-[var(--text-primary)]' : 'text-[var(--text-secondary)] hover:bg-[var(--nav-hover)]'
              }`}
            >
              {k === 'all' ? 'All' : KIND_LABEL[k]}{' '}
              <span className="tabular-nums text-[var(--text-muted)]">{k === 'all' ? rows.length : counts[k]}</span>
            </button>
          ))}
        </div>
        <div className="flex flex-1 flex-col sm:flex-row gap-2 lg:justify-end">
          <label className="sr-only" htmlFor="rules-origin-filter">Origin</label>
          <select
            id="rules-origin-filter"
            value={originFilter}
            onChange={(e) => setOriginFilter(e.target.value)}
            className="dash-input h-9 text-[13px] cursor-pointer sm:w-56"
          >
            <option value="all">All origins ({origins.length})</option>
            {origins.map((o) => (
              <option key={o.origin_id} value={o.origin_id}>{o.label || o.ip}</option>
            ))}
          </select>
          <label className="relative block sm:w-72">
            <span className="sr-only">Search rules</span>
            <Search size={14} aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search rule, IP or path"
              className="dash-input h-9 w-full pl-8 text-[13px]"
            />
          </label>
        </div>
      </div>

      {allOrigins.length > MAX_ORIGINS && (
        <p className="m-0 text-[12.5px] text-amber-700 dark:text-amber-400">
          Showing the rules of the first {MAX_ORIGINS} of {allOrigins.length} origins. Filter by origin on its own page for the rest.
        </p>
      )}
      {failedOrigins.length > 0 && (
        <p className="m-0 text-[12.5px] text-red-600 dark:text-red-400">
          Some rules could not be loaded for {failedOrigins.map((o) => o.label || o.ip).join(', ')}. The list below may be incomplete.
        </p>
      )}

      <div className="dash-card overflow-x-auto">
        <table className="dash-table">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Type</th>
              <th>Origin</th>
              <th className="hidden md:table-cell">Action</th>
              <th className="hidden md:table-cell">State</th>
              <th><span className="sr-only">Open</span></th>
            </tr>
          </thead>
          <tbody>
            {loading && rows.length === 0 ? (
              <tr><td colSpan={6} className="py-8 text-center text-[13px] text-[var(--text-muted)]">Loading rules…</td></tr>
            ) : shown.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-[13px] text-[var(--text-muted)]">
                  {rows.length === 0
                    ? 'None of your origins has its own rules yet. The managed rule set (OWASP CRS) still protects every origin.'
                    : 'No rule matches these filters.'}
                </td>
              </tr>
            ) : (
              shown.map((r) => (
                <tr key={r.key}>
                  <td className="max-w-[360px]">
                    <span className={`block truncate text-[13px] text-[var(--text-primary)] ${r.kind === 'ip' ? 'font-mono' : ''}`}>{r.title}</span>
                    <span className="block truncate font-mono text-[11.5px] text-[var(--text-muted)]" title={r.detail}>{r.detail}</span>
                  </td>
                  <td className="whitespace-nowrap text-[12.5px] text-[var(--text-secondary)]">{KIND_LABEL[r.kind]}</td>
                  <td className="whitespace-nowrap text-[12.5px]">
                    <Link to={`/origins/${encodeURIComponent(r.originId)}`} className="text-[var(--text-primary)] hover:text-[var(--accent)] hover:underline">
                      {r.originLabel}
                    </Link>
                  </td>
                  <td className="hidden md:table-cell">
                    <Badge color={r.action === 'block' ? 'danger' : r.action === 'allow' ? 'success' : 'gray'}>
                      {r.action ? r.action.charAt(0).toUpperCase() + r.action.slice(1) : '—'}
                    </Badge>
                  </td>
                  <td className="hidden md:table-cell text-[12.5px] text-[var(--text-secondary)]">{r.enabled ? 'On' : 'Off'}</td>
                  <td className="text-right whitespace-nowrap">
                    <Link
                      to={originTabPath(r.originId, r.tab)}
                      className="inline-flex items-center gap-1 text-[12.5px] font-medium text-[var(--accent)] hover:underline"
                      aria-label={`Open ${KIND_LABEL[r.kind]} ${r.title} on ${r.originLabel}`}
                    >
                      Open
                      <ExternalLink size={12} aria-hidden="true" />
                    </Link>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default OriginRulesTable
