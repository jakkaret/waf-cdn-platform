import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { systemApi } from '../api/system'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'

// Platform operator page (moved out of Platform settings, 2026-10-28). Each
// row is the backend's own probe from GET /api/system/status: a TCP port check
// per service and a query against the control-plane database.

type Row = { key: string; label: string; status?: 'online' | 'offline'; port?: number; detail?: string }

export const StackDiagnostics: React.FC = () => {
  const { data, isLoading, isError, isFetching, refetch, dataUpdatedAt } = useQuery({
    queryKey: ['system-status-diagnostics'],
    queryFn: () => systemApi.getSystemStatus(),
    refetchInterval: 10000,
  })

  const services = data?.services ?? {}
  const rows: Row[] = [
    { key: 'dashboard_api', label: 'Dashboard API (FastAPI)' },
    { key: 'waf_nginx', label: 'nginx + ModSecurity CRS' },
    { key: 'redis', label: 'Redis (rate limits, cache)' },
    { key: 'clickhouse', label: 'ClickHouse (traffic logs)' },
    { key: 'frps', label: 'FRP tunnel server' },
    { key: 'control_api', label: 'WAF control API' },
  ].map((r) => ({
    ...r,
    status: services[r.key]?.status,
    port: services[r.key]?.port,
    detail: services[r.key]?.desc,
  }))
  // The backend's database probe (main.py) targets PostgreSQL: tenants,
  // rules, alerts. Its detail text is empty for non-admins.
  rows.push({
    key: 'database',
    label: 'PostgreSQL (tenants, rules, alerts)',
    status: data?.db?.status,
    detail: data?.db?.detail || undefined,
  })

  const workers = Object.entries(data?.workers ?? {})

  return (
    <div className="animate-fade-in pb-12 space-y-5">
      <TopBar
        title="Stack diagnostics"
        subtitle="Reachability of the services behind the control plane, checked by the dashboard API every time this page refreshes."
        action={
          <Button
            variant="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
            icon={<RefreshCw size={13} className={isFetching ? 'animate-spin motion-reduce:animate-none' : ''} />}
          >
            Check again
          </Button>
        }
      />

      {isError && (
        <p role="alert" className="m-0 rounded-lg border border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 px-4 py-3 text-[13px] text-red-700 dark:text-red-300">
          The status check failed, so the states below are unknown. The dashboard API itself may be down.
        </p>
      )}

      <section className="dash-card overflow-hidden" aria-labelledby="svc-heading">
        <div className="dash-card-header">
          <h2 id="svc-heading" className="text-[14px] font-semibold m-0">Services</h2>
          {dataUpdatedAt > 0 && (
            <span className="text-[12px] text-[var(--text-muted)]">
              Checked {new Date(dataUpdatedAt).toLocaleTimeString('en-GB', { timeZone: 'Asia/Bangkok' })}
            </span>
          )}
        </div>
        <ul className="m-0 p-0 list-none divide-y divide-[var(--bg-border-subtle)]">
          {rows.map((r) => {
            const known = !isLoading && !isError && r.status !== undefined
            const online = r.status === 'online'
            return (
              <li key={r.key} className="flex items-center justify-between gap-3 px-4 py-3">
                <div className="min-w-0">
                  <p className="m-0 text-[13px] font-medium text-[var(--text-primary)]">{r.label}</p>
                  <p className="m-0 text-[12px] text-[var(--text-muted)]">
                    {r.port !== undefined && <span className="font-mono">port {r.port}</span>}
                    {r.port !== undefined && r.detail ? ', ' : ''}
                    {r.detail}
                    {r.port === undefined && !r.detail && (known ? (online ? 'Reachable' : 'Not reachable') : '')}
                  </p>
                </div>
                <span
                  className={`inline-flex items-center gap-1.5 shrink-0 rounded-md border px-2 py-0.5 text-[12px] font-medium ${
                    !known
                      ? 'border-[var(--bg-border)] text-[var(--text-muted)]'
                      : online
                        ? 'border-emerald-600/30 text-emerald-700 dark:text-emerald-400'
                        : 'border-red-600/30 text-red-700 dark:text-red-400'
                  }`}
                >
                  <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${!known ? 'bg-[var(--text-muted)]' : online ? 'bg-emerald-500' : 'bg-red-500'}`} />
                  {isLoading ? 'Checking' : !known ? 'Unknown' : online ? 'Online' : 'Offline'}
                </span>
              </li>
            )
          })}
          <li className="flex items-center justify-between gap-3 px-4 py-3">
            <div className="min-w-0">
              <p className="m-0 text-[13px] font-medium text-[var(--text-primary)]">Caddy (TLS on the edges)</p>
              <p className="m-0 text-[12px] text-[var(--text-muted)]">Not covered by this check. See CDN edge nodes for edge health.</p>
            </div>
            <span className="inline-flex items-center gap-1.5 shrink-0 rounded-md border border-[var(--bg-border)] px-2 py-0.5 text-[12px] font-medium text-[var(--text-muted)]">
              Not checked
            </span>
          </li>
        </ul>
      </section>

      {workers.length > 0 && (
        <section className="dash-card overflow-hidden" aria-labelledby="workers-heading">
          <div className="dash-card-header">
            <h2 id="workers-heading" className="text-[14px] font-semibold m-0">Background workers</h2>
            <span className="text-[12px] text-[var(--text-muted)]">Inferred from the service each worker needs</span>
          </div>
          <ul className="m-0 p-0 list-none divide-y divide-[var(--bg-border-subtle)]">
            {workers.map(([key, w]) => (
              <li key={key} className="flex items-center justify-between gap-3 px-4 py-3">
                <p className="m-0 text-[13px] text-[var(--text-primary)]">{w.desc}</p>
                <span className={`shrink-0 text-[12px] font-medium ${w.status === 'running' ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                  {w.status === 'running' ? 'Running' : 'Stopped'}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {data?.system && (
        <section className="dash-card p-4" aria-labelledby="host-heading">
          <h2 id="host-heading" className="text-[14px] font-semibold m-0 mb-2">Main node host</h2>
          <dl className="m-0 grid grid-cols-2 sm:grid-cols-4 gap-3 text-[12.5px]">
            <div><dt className="text-[var(--text-muted)]">Disk used</dt><dd className="m-0 font-mono">{data.system.disk_used_percent}%</dd></div>
            <div><dt className="text-[var(--text-muted)]">Disk free</dt><dd className="m-0 font-mono">{data.system.disk_free_gb} GB</dd></div>
            <div><dt className="text-[var(--text-muted)]">Disk total</dt><dd className="m-0 font-mono">{data.system.disk_total_gb} GB</dd></div>
            <div><dt className="text-[var(--text-muted)]">Load (1/5/15 min)</dt><dd className="m-0 font-mono">{data.system.load_average.map((n) => n.toFixed(2)).join(' / ')}</dd></div>
          </dl>
        </section>
      )}
    </div>
  )
}

export default StackDiagnostics
