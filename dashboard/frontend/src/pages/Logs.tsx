import React, { useState, useMemo, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useInfiniteQuery } from '@tanstack/react-query'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { logsApi, LogCursor, HistogramBucket } from '../api/logs'
import { useOriginFilterStore } from '../store/originFilterStore'
import { useThemeStore } from '../store/themeStore'
import { TopBar } from '../components/layout/TopBar'
import { Drawer } from '../components/ui/Drawer'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { BlockIpButton } from '../components/BlockIpButton'
import { Download, Search, Copy, Check, RefreshCw, Code, Shield, X, Sparkles } from 'lucide-react'
import { WafLog } from '../types'
import toast from 'react-hot-toast'
import { useDebouncedValue } from '../lib/useDebouncedValue'
import { confidenceLabel, LogExplanation, toLogExplanation } from '../lib/logExplanation'
import { BKK_LABEL, bkkDateKey, formatBkkDateTime, formatBkkTime } from '../lib/time'
import { OUTCOME_LABEL, logOutcome, realRuleId } from '../lib/logRow'

type RangePreset = '15m' | '1h' | '24h' | '7d' | 'all'
const RANGE_LABEL: Record<RangePreset, string> = { '15m': 'Last 15 min', '1h': 'Last hour', '24h': 'Last 24 h', '7d': 'Last 7 days', all: 'All' }

export const Logs: React.FC = () => {
  // Filter-first at scale: a time range narrows the search, and we never
  // deep-page -- a cursor 'load more' walks newest->older in place (F: log UX).
  // ?search= comes from "View in traffic logs" links (alerts, dashboard).
  const [searchParams] = useSearchParams()
  const linkedSearch = searchParams.get('search') ?? ''
  const [rangePreset, setRangePreset] = useState<RangePreset>(linkedSearch ? '7d' : '24h')
  const [search, setSearch] = useState(linkedSearch)
  useEffect(() => {
    if (linkedSearch) setSearch(linkedSearch)
  }, [linkedSearch])
  const debouncedSearch = useDebouncedValue(search)
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [methodFilter, setMethodFilter] = useState('ALL')
  // Static files (framework bundles, images, fonts) drown out the requests
  // worth reading; hidden on request by the backend (exclude_static).
  const [hideStatic, setHideStatic] = useState(true)
  const [selectedLog, setSelectedLog] = useState<WafLog | null>(null)
  const [copiedText, setCopiedText] = useState<string | null>(null)
  const { theme } = useThemeStore()
  const isDark = theme === 'dark'

  const [explanation, setExplanation] = useState<LogExplanation | null>(null)
  const [isExplaining, setIsExplaining] = useState(false)
  const [maskedPayload, setMaskedPayload] = useState<string | null>(null)
  const [isMasking, setIsMasking] = useState(false)
  const range = useMemo(() => {
    if (rangePreset === 'all') return { from: null as number | null, to: null as number | null }
    const now = Math.floor(Date.now() / 1000)
    const span = { '15m': 900, '1h': 3600, '24h': 86400, '7d': 604800 }[rangePreset]
    return { from: now - span, to: null as number | null }
  }, [rangePreset])
  // histogram bucket chosen from the span so the bar chart stays readable
  const bucketSeconds = rangePreset === '15m' ? 60 : rangePreset === '1h' ? 300 : rangePreset === '24h' ? 3600 : 86400

  const { selectedOrigin, selectedOriginLabel, setSelectedOrigin } = useOriginFilterStore()

  const { data: filterOptions } = useQuery({
    queryKey: ['log-filters'],
    queryFn: () => logsApi.getFilterOptions(),
    staleTime: 30000,
  })

  const commonFilters = {
    search: debouncedSearch,
    status_filter: statusFilter,
    method_filter: methodFilter,
    origin: selectedOrigin,
    from_ts: range.from,
    to_ts: range.to,
    exclude_static: hideStatic,
  }

  const { data, isLoading, isError, isFetching, refetch, fetchNextPage, hasNextPage, isFetchingNextPage } =
    useInfiniteQuery({
      queryKey: ['logs-stream', debouncedSearch, statusFilter, methodFilter, selectedOrigin, range.from, range.to, hideStatic],
      queryFn: ({ pageParam }) => logsApi.getLogStream({ ...commonFilters, limit: 50, cursor: pageParam as LogCursor | null }),
      initialPageParam: null as LogCursor | null,
      getNextPageParam: (lastPage) => (lastPage.has_more ? lastPage.next_cursor : undefined),
      refetchInterval: 8000,
    })

  const logs = data?.pages.flatMap((pg) => pg.logs) ?? []
  const total = logs.length

  const { data: histogram = [], isLoading: histoLoading, isError: histoError } = useQuery<HistogramBucket[]>({
    queryKey: ['logs-histogram', debouncedSearch, statusFilter, methodFilter, selectedOrigin, range.from, range.to, bucketSeconds, hideStatic],
    queryFn: () => logsApi.getHistogram({ ...commonFilters, bucket_seconds: bucketSeconds }),
    refetchInterval: 15000,
  })
  const histoTotal = histogram.reduce((a, b) => a + b.total, 0)
  const histoBlocked = histogram.reduce((a, b) => a + b.blocked, 0)
  // Numeric time axis: bars sit at their real time, gaps stay gaps.
  const histoData = histogram.map((b) => ({ t: b.bucket * 1000, passed: b.total - b.blocked, blocked: b.blocked }))
  const bucketText = bucketSeconds >= 86400 ? 'per day' : bucketSeconds >= 3600 ? 'per hour' : `per ${bucketSeconds / 60} min`

  const handleExplainLog = async (logId: string) => {
    try {
      setIsExplaining(true)
      const res = await logsApi.explainLog(logId)
      setExplanation(toLogExplanation(res))
    } catch (err) {
      toast.error('Could not generate an explanation. Try again.')
    } finally {
      setIsExplaining(false)
    }
  }

  const handleMaskPreview = async (logUrl: string) => {
    try {
      setIsMasking(true)
      const res = await logsApi.maskPreview(logUrl)
      setMaskedPayload(res.masked_text || res.masked_payload || JSON.stringify(res))
    } catch (err) {
      toast.error('Could not mask the URL. Try again.')
    } finally {
      setIsMasking(false)
    }
  }

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(text)
    toast.success(`Copied ${label}`)
    setTimeout(() => setCopiedText(null), 2000)
  }

  const exportToCSV = () => {
    if (logs.length === 0) return
    const headers = ['datetime_bkk', 'ip', 'method', 'url', 'status', 'result', 'rule_id', 'attack_type']
    const csvRows = [
      headers.join(','),
      ...logs.map((log) => [
        `"${formatBkkDateTime(log.datetime)}"`,
        `"${log.ip}"`,
        `"${log.method}"`,
        `"${(log.url || '').replace(/"/g, '""')}"`,
        log.status,
        `"${OUTCOME_LABEL[logOutcome(log.status)]}"`,
        `"${realRuleId(log.rule_id) ?? ''}"`,
        `"${(log.attack_type || '').replace(/"/g, '""')}"`,
      ].join(',')),
    ]
    const blob = new Blob([csvRows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const a = document.createElement('a')
    a.href = window.URL.createObjectURL(blob)
    a.download = `waf_traffic_logs_${bkkDateKey()}.csv`
    a.click()
    toast.success('Downloaded the loaded rows as CSV')
  }

  const statusText = (status: number) =>
    status >= 500 ? 'Server error' : status >= 400 ? 'Client error' : status >= 300 ? 'Redirect' : 'OK'

  const outcomeBadge = (status: number) => {
    const o = logOutcome(status)
    const color = o === 'blocked' ? 'danger' : o === 'rate_limited' ? 'warning' : o === 'error' ? 'warning' : 'gray'
    return <Badge color={color}>{OUTCOME_LABEL[o]}</Badge>
  }

  const selectClass =
    'w-full h-9 px-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[13px] text-[var(--text-primary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] cursor-pointer'
  const axisColor = isDark ? '#94a3b8' : '#64748b'

  return (
    <div className="animate-fade-in pb-8">
      <TopBar
        scope
        title="Traffic logs"
        subtitle={`Every request that reached your sites through the WAF, newest first. Times are ${BKK_LABEL}.`}
        action={
          <div className="flex items-center gap-2">
            <Button variant="secondary" onClick={exportToCSV} disabled={logs.length === 0} icon={<Download size={13} />} title="Export the loaded rows to CSV">
              <span className="hidden sm:inline">Export CSV</span>
            </Button>
            <Button
              variant="secondary"
              onClick={() => refetch()}
              disabled={isFetching}
              icon={<RefreshCw size={13} className={isFetching ? 'animate-spin motion-reduce:animate-none' : ''} />}
              title="Refresh"
            >
              <span className="hidden sm:inline">Refresh</span>
            </Button>
          </div>
        }
      />

      {selectedOrigin !== 'ALL' && (
        <div className="mb-4 px-3.5 py-2.5 rounded-lg bg-[var(--bg-surface)] border border-[var(--bg-border)] flex items-center justify-between gap-3 text-[13px]">
          <span className="flex items-center gap-2 truncate text-[var(--text-secondary)]">
            <Shield size={15} className="shrink-0 text-[var(--text-muted)]" aria-hidden="true" />
            <span className="truncate">Only <strong className="text-[var(--text-primary)]">{selectedOriginLabel}</strong></span>
          </span>
          <button
            type="button"
            onClick={() => setSelectedOrigin('ALL', 'All Managed Origins (ทั้งหมด)')}
            className="flex items-center gap-1 h-8 px-2.5 rounded-md border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] text-[12.5px] cursor-pointer shrink-0"
          >
            <X size={12} aria-hidden="true" />
            Show all origins
          </button>
        </div>
      )}

      {/* Time range + activity histogram */}
      <section className="dash-card p-4 mb-4" aria-labelledby="logs-histo-heading">
        <div className="flex items-center justify-between mb-3 gap-2 flex-wrap">
          <div role="group" aria-label="Time range" className="flex flex-wrap items-center gap-1.5">
            {(['15m', '1h', '24h', '7d', 'all'] as const).map((r) => (
              <button
                key={r}
                type="button"
                aria-pressed={rangePreset === r}
                onClick={() => setRangePreset(r)}
                className={`h-8 px-2.5 rounded-md text-[12.5px] border transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
                  rangePreset === r
                    ? 'border-[var(--accent)] bg-[var(--nav-active)] text-[var(--text-primary)] font-medium'
                    : 'border-[var(--bg-border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]'
                }`}
              >
                {RANGE_LABEL[r]}
              </button>
            ))}
          </div>
          <p id="logs-histo-heading" className="m-0 text-[12.5px] text-[var(--text-muted)]">
            {histoTotal.toLocaleString()} requests, {histoBlocked.toLocaleString()} blocked or rate limited, counted {bucketText}
          </p>
        </div>
        <div className="h-28">
          {histoLoading ? (
            <div className="h-full flex items-center justify-center text-[12.5px] text-[var(--text-muted)]">Loading…</div>
          ) : histoError ? (
            <div className="h-full flex items-center justify-center text-[12.5px] text-red-600 dark:text-red-400">Could not load the activity chart.</div>
          ) : histoData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-[12.5px] text-[var(--text-muted)]">No requests in this range</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={histoData} margin={{ top: 4, right: 8, left: 0, bottom: 0 }} barCategoryGap={1}>
                <CartesianGrid stroke={isDark ? '#1a2436' : '#e2e8f0'} strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="t"
                  type="number"
                  scale="time"
                  domain={[`dataMin - ${(bucketSeconds * 1000) / 2}`, `dataMax + ${(bucketSeconds * 1000) / 2}`]}
                  tickFormatter={(t: number) => (bucketSeconds >= 86400 ? bkkDateKey(t).slice(5) : formatBkkTime(t))}
                  stroke={axisColor}
                  fontSize={11}
                  tickLine={false}
                  minTickGap={36}
                />
                <YAxis stroke={axisColor} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} width={36} />
                <Tooltip
                  labelFormatter={(t: number) => formatBkkDateTime(t, { seconds: false })}
                  contentStyle={{ backgroundColor: isDark ? '#101827' : '#fff', borderColor: isDark ? '#2a374d' : '#e2e8f0', borderRadius: 8, fontSize: 12 }}
                />
                <Bar dataKey="passed" stackId="a" name="Passed" fill={isDark ? '#334155' : '#cbd5e1'} isAnimationActive={false} />
                <Bar dataKey="blocked" stackId="a" name="Blocked or rate limited" fill="#dc2626" isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </section>

      {/* Filters */}
      <section className="dash-card p-4 mb-4" aria-label="Filters">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-[2fr_1fr_1fr_auto] gap-3 items-center">
          <label className="relative block">
            <span className="sr-only">Search</span>
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] pointer-events-none" size={14} aria-hidden="true" />
            <input
              type="search"
              placeholder="Search IP, URL, rule ID, attack type"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full h-9 pl-9 pr-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)] text-[13px] text-[var(--text-primary)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
            />
          </label>

          <label className="block">
            <span className="sr-only">WAF result and HTTP status</span>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={selectClass}>
              <option value="ALL">Any result or status</option>
              <option value="BLOCKED">Blocked or rate limited (403, 429)</option>
              <option value="ALLOWED">Passed with 2xx</option>
              {filterOptions?.status_codes?.map((code) => (
                <option key={code} value={String(code)}>
                  HTTP {code}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="sr-only">HTTP method</span>
            <select value={methodFilter} onChange={(e) => setMethodFilter(e.target.value)} className={selectClass}>
              <option value="ALL">Any method</option>
              {filterOptions?.methods?.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </label>

          <label className="inline-flex items-center gap-2 text-[13px] text-[var(--text-secondary)] cursor-pointer select-none">
            <input
              type="checkbox"
              checked={hideStatic}
              onChange={(e) => setHideStatic(e.target.checked)}
              className="h-4 w-4 accent-[var(--accent)] cursor-pointer"
            />
            Hide static files
            <span className="sr-only">(blocked requests to static files stay visible)</span>
          </label>
        </div>
        <p className="m-0 mt-2 text-[12px] text-[var(--text-muted)]">
          Hiding static files never hides a blocked request. The log does not record a threat severity per request, so
          rows show what the WAF did and the HTTP status instead.
        </p>
      </section>

      {/* Main table */}
      <div className="dash-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>Time ({BKK_LABEL})</th>
                <th>Client IP</th>
                <th className="hidden md:table-cell">Method</th>
                <th>Path</th>
                <th>Result</th>
                <th className="hidden sm:table-cell">HTTP</th>
                <th className="hidden lg:table-cell">Rule</th>
                <th><span className="sr-only">Details</span></th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)] text-[13px]">
                    Loading requests…
                  </td>
                </tr>
              ) : isError ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-red-600 dark:text-red-400 text-[13px]">
                    Could not load the logs. They will retry in a few seconds.
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-[var(--text-muted)] text-[13px]">
                    No requests match these filters{hideStatic ? ' (static files are hidden)' : ''}.
                  </td>
                </tr>
              ) : (
                logs.map((log, idx) => {
                  const rule = realRuleId(log.rule_id)
                  return (
                    <tr
                      key={log.log_id || log.request_id || `log-${idx}`}
                      onClick={() => setSelectedLog(log)}
                      className="hover:bg-[var(--bg-hover)] transition-colors cursor-pointer"
                    >
                      <td className="font-mono text-[12px] text-[var(--text-secondary)] whitespace-nowrap">
                        {formatBkkDateTime(log.datetime)}
                      </td>
                      <td className="font-mono text-[12.5px] font-semibold text-[var(--text-primary)] whitespace-nowrap">{log.ip}</td>
                      <td className="hidden md:table-cell font-mono text-[12px] text-[var(--text-secondary)]">{log.method}</td>
                      <td className="font-mono text-[12px] text-[var(--text-primary)] max-w-[300px] truncate" title={log.url}>
                        {log.url || '/'}
                      </td>
                      <td className="whitespace-nowrap">{outcomeBadge(log.status)}</td>
                      <td className="hidden sm:table-cell font-mono text-[12px] text-[var(--text-secondary)] whitespace-nowrap">{log.status}</td>
                      <td className="hidden lg:table-cell font-mono text-[12px] text-[var(--text-secondary)] whitespace-nowrap">
                        {rule ?? (logOutcome(log.status) === 'blocked' ? <span className="text-[var(--text-muted)]">not recorded</span> : '—')}
                      </td>
                      <td className="text-right whitespace-nowrap">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedLog(log)
                          }}
                          aria-label={`Details of the request from ${log.ip} at ${formatBkkDateTime(log.datetime)}`}
                          className="h-7 px-2 rounded-md border border-[var(--bg-border)] text-[12px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Load-more footer (keyset -- no deep paging) */}
        <div className="p-3.5 border-t border-[var(--bg-border)] flex flex-col sm:flex-row items-center justify-between gap-3 text-[12.5px] text-[var(--text-muted)]">
          <div>
            {total.toLocaleString()} requests loaded{hasNextPage ? ', more available' : ', end of range'}
          </div>
          <Button variant="secondary" onClick={() => fetchNextPage()} disabled={!hasNextPage || isFetchingNextPage}>
            {isFetchingNextPage ? 'Loading…' : hasNextPage ? 'Load more' : 'No more'}
          </Button>
        </div>
      </div>

      {/* Log Detail */}
      <Drawer
        open={!!selectedLog}
        onClose={() => {
          setSelectedLog(null)
          setExplanation(null)
          setMaskedPayload(null)
        }}
        size="lg"
        title={
          <span className="inline-flex items-center gap-2">
            <Code size={16} className="text-[var(--text-muted)] shrink-0" aria-hidden="true" />
            <span>Request details</span>
          </span>
        }
      >
        {selectedLog && (() => {
          const rule = realRuleId(selectedLog.rule_id)
          const outcome = logOutcome(selectedLog.status)
          return (
            <div className="space-y-4 text-[13px]">
              <div className="flex flex-wrap items-center gap-2">
                {outcomeBadge(selectedLog.status)}
                <span className="text-[12.5px] text-[var(--text-muted)]">
                  HTTP {selectedLog.status} {statusText(selectedLog.status)}
                </span>
              </div>

              <dl className="m-0 grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)]">
                  <dt className="text-[12px] text-[var(--text-muted)]">Time ({BKK_LABEL})</dt>
                  <dd className="m-0 font-mono text-[var(--text-primary)]">{formatBkkDateTime(selectedLog.datetime)}</dd>
                </div>
                <div className="p-3 rounded-lg bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)]">
                  <dt className="text-[12px] text-[var(--text-muted)]">Client IP</dt>
                  <dd className="m-0 flex items-center gap-1.5">
                    <span className="font-mono font-semibold text-[var(--text-primary)]">{selectedLog.ip}</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(selectedLog.ip, 'IP')}
                      className="p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
                      aria-label="Copy IP"
                    >
                      {copiedText === selectedLog.ip ? <Check size={13} className="text-emerald-600" /> : <Copy size={13} />}
                    </button>
                  </dd>
                </div>
                <div className="sm:col-span-2 p-3 rounded-lg bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)]">
                  <dt className="text-[12px] text-[var(--text-muted)]">{selectedLog.method} request</dt>
                  <dd className="m-0 font-mono text-[12.5px] text-[var(--text-primary)] break-all">{selectedLog.url}</dd>
                </div>
                <div className="p-3 rounded-lg bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)]">
                  <dt className="text-[12px] text-[var(--text-muted)]">ModSecurity rule</dt>
                  <dd className="m-0 font-mono text-[var(--text-primary)]">
                    {rule ?? (outcome === 'blocked' ? 'Not recorded for this request' : 'None')}
                  </dd>
                </div>
                <div className="p-3 rounded-lg bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)]">
                  <dt className="text-[12px] text-[var(--text-muted)]">Detection reason</dt>
                  <dd className="m-0 text-[var(--text-primary)]">{selectedLog.attack_type || 'None recorded'}</dd>
                </div>
                {selectedLog.user_agent && (
                  <div className="sm:col-span-2 p-3 rounded-lg bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)]">
                    <dt className="text-[12px] text-[var(--text-muted)]">User agent</dt>
                    <dd className="m-0 font-mono text-[12px] text-[var(--text-secondary)] break-all">{selectedLog.user_agent}</dd>
                  </div>
                )}
              </dl>

              {/* Next steps. Block IP opens the origin's IP access tab with
                  the address filled in; nothing changes from here. */}
              <div className="flex flex-wrap items-center gap-2">
                <BlockIpButton
                  ip={selectedLog.ip}
                  originId={selectedOrigin !== 'ALL' ? selectedOrigin : null}
                  note={`Traffic log ${formatBkkDateTime(selectedLog.datetime)}`}
                  size="md"
                />
                <Button variant="secondary" onClick={() => setSearch(selectedLog.ip)} icon={<Search size={13} />}>
                  Show all requests from this IP
                </Button>
              </div>

              <div className="pt-3 border-t border-[var(--bg-border-subtle)] flex flex-wrap gap-2">
                <Button
                  variant="secondary"
                  onClick={() => selectedLog.log_id && handleExplainLog(selectedLog.log_id)}
                  disabled={isExplaining || !selectedLog.log_id}
                  icon={<Sparkles size={13} />}
                >
                  {isExplaining ? 'Explaining…' : 'Explain with AI'}
                </Button>
                <Button variant="secondary" onClick={() => handleMaskPreview(selectedLog.url)} disabled={isMasking}>
                  {isMasking ? 'Masking…' : 'Preview URL with personal data masked'}
                </Button>
              </div>

              {explanation && (
                <div className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] space-y-2">
                  <p className="m-0 flex items-center gap-1.5 text-[12px] font-medium text-indigo-700 dark:text-indigo-300">
                    <Sparkles size={12} aria-hidden="true" />
                    AI explanation. It can be wrong; the recorded rule and reason above are what the WAF logged.
                  </p>
                  <p className="text-[var(--text-primary)] m-0 leading-relaxed whitespace-pre-wrap">{explanation.summary}</p>
                  <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 m-0 text-[12.5px]">
                    {explanation.category && (<><dt className="text-[var(--text-muted)]">Category</dt><dd className="m-0 text-[var(--text-primary)]">{explanation.category}</dd></>)}
                    {explanation.matchedToken && (<><dt className="text-[var(--text-muted)]">Matched token</dt><dd className="m-0 font-mono break-all text-[var(--text-primary)]">{explanation.matchedToken}</dd></>)}
                    {explanation.rootCause && explanation.rootCause !== explanation.summary && (<><dt className="text-[var(--text-muted)]">Root cause</dt><dd className="m-0 text-[var(--text-primary)]">{explanation.rootCause}</dd></>)}
                    {explanation.remediation && (<><dt className="text-[var(--text-muted)]">Remediation</dt><dd className="m-0 text-[var(--text-primary)]">{explanation.remediation}</dd></>)}
                    {explanation.confidence !== undefined && (<><dt className="text-[var(--text-muted)]">Confidence</dt><dd className="m-0 text-[var(--text-primary)]">{confidenceLabel(explanation.confidence)}</dd></>)}
                  </dl>
                </div>
              )}

              {maskedPayload && (
                <div className="p-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] space-y-1.5">
                  <p className="m-0 text-[12px] font-medium text-[var(--text-secondary)]">URL with personal data masked</p>
                  <pre className="text-[var(--text-primary)] m-0 p-2 bg-[var(--bg-primary)] rounded-md overflow-x-auto text-[12px] font-mono whitespace-pre-wrap">
                    {maskedPayload}
                  </pre>
                  {maskedPayload === selectedLog.url && (
                    <p className="m-0 text-[12px] text-[var(--text-muted)]">Nothing in this URL looked like personal data.</p>
                  )}
                </div>
              )}
            </div>
          )
        })()}
      </Drawer>
    </div>
  )
}

export default Logs
