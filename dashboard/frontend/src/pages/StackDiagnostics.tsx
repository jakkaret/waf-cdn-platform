import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { systemApi } from '../api/system'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { useT } from '../i18n'

// Platform operator page (moved out of Platform settings, 2026-10-28). Each
// row is the backend's own probe from GET /api/system/status: a TCP port check
// per service and a query against the control-plane database.

type Row = { key: string; label: string; status?: 'online' | 'offline'; port?: number; detail?: string }

export const StackDiagnostics: React.FC = () => {
  const { t } = useT()
  const { data, isLoading, isError, isFetching, refetch, dataUpdatedAt } = useQuery({
    queryKey: ['system-status-diagnostics'],
    queryFn: () => systemApi.getSystemStatus(),
    refetchInterval: 10000,
  })

  const services = data?.services ?? {}
  const rows: Row[] = [
    { key: 'dashboard_api', label: 'Dashboard API (FastAPI)' },
    { key: 'waf_nginx', label: 'nginx + ModSecurity CRS' },
    { key: 'redis', label: t('Redis (rate limits, cache)', 'Redis (rate limit, cache)') },
    { key: 'clickhouse', label: t('ClickHouse (traffic logs)', 'ClickHouse (log ทราฟฟิก)') },
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
    label: t('PostgreSQL (tenants, rules, alerts)', 'PostgreSQL (tenant, กฎ, การแจ้งเตือน)'),
    status: data?.db?.status,
    detail: data?.db?.detail || undefined,
  })

  const workers = Object.entries(data?.workers ?? {})

  return (
    <div className="animate-fade-in pb-12 space-y-5">
      <TopBar
        title={t('Stack diagnostics', 'ตรวจสุขภาพระบบ')}
        subtitle={t(
          'Reachability of the services behind the control plane, checked by the dashboard API every time this page refreshes.',
          'การเข้าถึงบริการเบื้องหลัง control plane ตรวจโดย dashboard API ทุกครั้งที่หน้านี้รีเฟรช',
        )}
        action={
          <Button
            variant="secondary"
            onClick={() => refetch()}
            disabled={isFetching}
            icon={<RefreshCw size={13} className={isFetching ? 'animate-spin motion-reduce:animate-none' : ''} />}
          >
            {t('Check again', 'ตรวจอีกครั้ง')}
          </Button>
        }
      />

      {isError && (
        <p role="alert" className="m-0 rounded-lg border border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 px-4 py-3 text-[13px] text-red-700 dark:text-red-300">
          {t('The status check failed, so the states below are unknown. The dashboard API itself may be down.', 'ตรวจสถานะไม่สำเร็จ สถานะด้านล่างจึงไม่ทราบ dashboard API เองอาจล่มอยู่')}
        </p>
      )}

      <section className="dash-card overflow-hidden" aria-labelledby="svc-heading">
        <div className="dash-card-header">
          <h2 id="svc-heading" className="text-[14px] font-semibold m-0">{t('Services', 'บริการ')}</h2>
          {dataUpdatedAt > 0 && (
            <span className="text-[12px] text-[var(--text-muted)]">
              {t('Checked', 'ตรวจเมื่อ')} {new Date(dataUpdatedAt).toLocaleTimeString('en-GB', { timeZone: 'Asia/Bangkok' })}
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
                    {r.port === undefined && !r.detail && (known ? (online ? t('Reachable', 'เข้าถึงได้') : t('Not reachable', 'เข้าถึงไม่ได้')) : '')}
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
                  {isLoading ? t('Checking', 'กำลังตรวจ') : !known ? t('Unknown', 'ไม่ทราบ') : online ? t('Online', 'ออนไลน์') : t('Offline', 'ออฟไลน์')}
                </span>
              </li>
            )
          })}
          <li className="flex items-center justify-between gap-3 px-4 py-3">
            <div className="min-w-0">
              <p className="m-0 text-[13px] font-medium text-[var(--text-primary)]">{t('Caddy (TLS on the edges)', 'Caddy (TLS ที่ edge)')}</p>
              <p className="m-0 text-[12px] text-[var(--text-muted)]">{t('Not covered by this check. See CDN edge nodes for edge health.', 'การตรวจนี้ไม่ครอบคลุม ดูสุขภาพของ edge ที่หน้า CDN edge node')}</p>
            </div>
            <span className="inline-flex items-center gap-1.5 shrink-0 rounded-md border border-[var(--bg-border)] px-2 py-0.5 text-[12px] font-medium text-[var(--text-muted)]">
              {t('Not checked', 'ไม่ได้ตรวจ')}
            </span>
          </li>
        </ul>
      </section>

      {workers.length > 0 && (
        <section className="dash-card overflow-hidden" aria-labelledby="workers-heading">
          <div className="dash-card-header">
            <h2 id="workers-heading" className="text-[14px] font-semibold m-0">{t('Background workers', 'งานเบื้องหลัง')}</h2>
            <span className="text-[12px] text-[var(--text-muted)]">{t('Inferred from the service each worker needs', 'อนุมานจากบริการที่แต่ละงานต้องใช้')}</span>
          </div>
          <ul className="m-0 p-0 list-none divide-y divide-[var(--bg-border-subtle)]">
            {workers.map(([key, w]) => (
              <li key={key} className="flex items-center justify-between gap-3 px-4 py-3">
                <p className="m-0 text-[13px] text-[var(--text-primary)]">{w.desc}</p>
                <span className={`shrink-0 text-[12px] font-medium ${w.status === 'running' ? 'text-emerald-700 dark:text-emerald-400' : 'text-red-700 dark:text-red-400'}`}>
                  {w.status === 'running' ? t('Running', 'ทำงานอยู่') : t('Stopped', 'หยุด')}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {data?.system && (
        <section className="dash-card p-4" aria-labelledby="host-heading">
          <h2 id="host-heading" className="text-[14px] font-semibold m-0 mb-2">{t('Main node host', 'เครื่อง main node')}</h2>
          <dl className="m-0 grid grid-cols-2 sm:grid-cols-4 gap-3 text-[12.5px]">
            <div><dt className="text-[var(--text-muted)]">{t('Disk used', 'ดิสก์ที่ใช้')}</dt><dd className="m-0 font-mono">{data.system.disk_used_percent}%</dd></div>
            <div><dt className="text-[var(--text-muted)]">{t('Disk free', 'ดิสก์ว่าง')}</dt><dd className="m-0 font-mono">{data.system.disk_free_gb} GB</dd></div>
            <div><dt className="text-[var(--text-muted)]">{t('Disk total', 'ดิสก์ทั้งหมด')}</dt><dd className="m-0 font-mono">{data.system.disk_total_gb} GB</dd></div>
            <div><dt className="text-[var(--text-muted)]">{t('Load (1/5/15 min)', 'Load (1/5/15 นาที)')}</dt><dd className="m-0 font-mono">{data.system.load_average.map((n) => n.toFixed(2)).join(' / ')}</dd></div>
          </dl>
        </section>
      )}
    </div>
  )
}

export default StackDiagnostics
