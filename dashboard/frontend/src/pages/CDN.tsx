import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { cdnApi } from '../api/cdn'
import { CdnNode, CdnStats } from '../types'
import { TopBar } from '../components/layout/TopBar'
import { StatCard } from '../components/ui/StatCard'
import { Badge } from '../components/ui/Badge'
import { useThemeStore } from '../store/themeStore'
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  CartesianGrid,
} from 'recharts'
import { Activity, Globe, HardDrive, Trash2, Clock, Server, Layers } from 'lucide-react'
import { EDGE_STATE_LABEL, EDGE_STATE_LABEL_TH, EdgeState, nextEdgeState } from '../lib/edgeStatus'
import { formatBkkTime } from '../lib/time'
import { useT } from '../i18n'

// Platform operator page: the edge nodes and their cache. Every figure is a
// backend measurement (/cdn/nodes health checks, /cdn/stats cache counters);
// nothing here is per visitor.
export const CDN: React.FC = () => {
  const { theme } = useThemeStore()
  const { t, lang } = useT()

  const { data: nodes = [], isLoading: isLoadingNodes, isError: nodesError, dataUpdatedAt: nodesUpdatedAt } = useQuery({
    queryKey: ['cdn-nodes'],
    queryFn: cdnApi.getNodes,
    refetchInterval: 8000,
  })

  const { data: stats = [], isLoading: isLoadingStats, isError: statsError } = useQuery({
    queryKey: ['cdn-stats'],
    queryFn: cdnApi.getStats,
    refetchInterval: 8000,
  })

  // Safe data extraction (handles both Array and Object backend structures)
  const statsList: CdnStats[] = Array.isArray(stats)
    ? stats
    : stats && typeof stats === 'object' && (stats as any).regional_breakdown
    ? Object.entries((stats as any).regional_breakdown).map(([region, data]: [string, any]) => ({
        region,
        request_count: data.requests || 0,
        cache_hit: Math.round(((data.requests || 0) * (data.hit_ratio || 0)) / 100),
        cache_miss: Math.round(((data.requests || 0) * (100 - (data.hit_ratio || 0))) / 100),
        cache_bypass: 0,
        blocked_count: 0,
        avg_latency: data.avg_latency_ms ?? 0,
      }))
    : []

  const safeNodes: CdnNode[] = Array.isArray(nodes) ? nodes : []
  // MAIN is the WAF core, not an edge: visitors reach only the edges (GeoDNS).
  const edgeNodes = safeNodes.filter((n) => n.region !== 'MAIN')

  // Debounced per-edge state (lib/edgeStatus.ts): one failed 1.2 s probe is
  // "no answer to the last check", two in a row is Offline.
  const [edgeStates, setEdgeStates] = useState<Record<string, EdgeState>>({})
  useEffect(() => {
    if (!nodesUpdatedAt) return
    setEdgeStates((prev) => {
      const next: Record<string, EdgeState> = {}
      for (const n of safeNodes) {
        const answered = n.online === true || n.status === 'healthy' || n.status === 'online'
        next[n.region] = nextEdgeState(prev[n.region], answered)
      }
      return next
    })
    // Recomputed once per fetch, not per render.
  }, [nodesUpdatedAt])
  const stateOf = (n: CdnNode): EdgeState => edgeStates[n.region] ?? 'unknown'
  const onlineEdges = edgeNodes.filter((n) => stateOf(n) === 'online').length

  // Calculations
  const statsObj = stats && !Array.isArray(stats) ? (stats as any) : null
  const totalRequests = statsObj?.total_requests ?? statsList.reduce((sum, s) => sum + (s.request_count || 0), 0)
  const totalHits = statsObj?.cached_requests ?? statsList.reduce((sum, s) => sum + (s.cache_hit || 0), 0)
  const totalMisses = statsObj?.uncached_requests ?? statsList.reduce((sum, s) => sum + (s.cache_miss || 0), 0)
  const totalBypass = statsList.reduce((sum, s) => sum + (s.cache_bypass || 0), 0)
  const totalBlocked = statsList.reduce((sum, s) => sum + (s.blocked_count || 0), 0)
  const hitRatio = statsObj?.cache_hit_ratio
    ? Number(statsObj.cache_hit_ratio).toFixed(1)
    : totalRequests > 0
    ? ((totalHits / Math.max(totalRequests - totalBlocked - totalBypass, 1)) * 100).toFixed(1)
    : null
  // /cdn/stats reports a mean time to first byte, not a percentile.
  const avgTtfb = statsObj?.avg_ttfb_ms != null
    ? String(statsObj.avg_ttfb_ms)
    : statsList.length > 0
    ? (statsList.reduce((sum, s) => sum + (s.avg_latency || 0), 0) / statsList.length).toFixed(0)
    : null

  const pieData = [
    { name: t('Cache hit', 'Cache hit'), value: totalHits, color: '#059669' },
    { name: t('Cache miss', 'Cache miss'), value: totalMisses, color: '#d97706' },
    { name: t('Bypass (dynamic)', 'Bypass (เนื้อหา dynamic)'), value: totalBypass, color: '#0284c7' },
  ].filter((d) => d.value > 0)

  // Health-check round trip from the control plane to each edge -- the same
  // probe as the node status. It is not what a visitor experiences, and the
  // control plane's own loopback (~0 ms) is not a "direct origin" baseline, so
  // the two are no longer charted side by side as an "acceleration".
  const rttData = edgeNodes.map((n) => ({
    name: n.name || n.region,
    rtt: stateOf(n) === 'online' && n.latency_ms ? n.latency_ms : null,
  }))

  const isDark = theme === 'dark'
  const gridColor = isDark ? '#1a2436' : '#e2e8f0'
  const axisColor = isDark ? '#94a3b8' : '#64748b'
  const tooltipStyle = { backgroundColor: isDark ? '#101827' : '#ffffff', borderColor: isDark ? '#2a374d' : '#e2e8f0', borderRadius: '8px', fontSize: '12px' }

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title={t('CDN edge nodes', 'CDN edge node')}
        subtitle={t('Edge health as seen from the control plane, and edge cache counters.', 'สุขภาพของ edge ตามที่ control plane ตรวจได้ และตัวนับ cache ของ edge')}
        badge={
          isLoadingNodes ? (
            <Badge color="gray">{t('Checking edges…', 'กำลังตรวจ edge…')}</Badge>
          ) : nodesError ? (
            <Badge color="gray">{t('Edge status unavailable', 'ไม่มีข้อมูลสถานะ edge')}</Badge>
          ) : (
            <Badge color={onlineEdges === edgeNodes.length ? 'success' : 'warning'} dot>
              {t(`${onlineEdges} of ${edgeNodes.length} edges answering`, `edge ตอบ ${onlineEdges} จาก ${edgeNodes.length}`)}
            </Badge>
          )
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          label={t('Cache hit rate', 'อัตรา cache hit')}
          value={isLoadingStats || statsError || hitRatio === null ? '—' : `${hitRatio}%`}
          color="green"
          icon={<HardDrive size={16} />}
          sub={statsError ? t('Cache counters unavailable', 'ไม่มีข้อมูลตัวนับ cache') : t(`${totalHits.toLocaleString()} responses served from cache`, `ตอบจาก cache ${totalHits.toLocaleString()} ครั้ง`)}
        />
        <StatCard
          label={t('Requests at the edges', 'request ที่ edge')}
          value={isLoadingStats || statsError ? '—' : totalRequests.toLocaleString()}
          color="blue"
          icon={<Globe size={16} />}
          sub={t('All edges together', 'รวมทุก edge')}
        />
        <StatCard
          label={t('Average time to first byte', 'เวลาเฉลี่ยถึง byte แรก')}
          value={isLoadingStats || statsError || avgTtfb === null ? '—' : `${avgTtfb} ms`}
          color="cyan"
          icon={<Activity size={16} />}
          sub={t("Mean over the edges' recorded responses", 'ค่าเฉลี่ยจาก response ที่ edge บันทึกไว้')}
        />
      </div>

      {/* POP Grid & Cache Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <section className="dash-card overflow-hidden flex flex-col" aria-labelledby="edge-nodes-heading">
          <div className="dash-card-header">
            <div className="flex items-center gap-2">
              <Server size={16} className="text-[var(--text-muted)]" aria-hidden="true" />
              <h3 id="edge-nodes-heading">{t('Nodes', 'Node')}</h3>
            </div>
            {nodesUpdatedAt > 0 && (
              <span className="text-[12px] text-[var(--text-muted)]">{t('Checked', 'ตรวจเมื่อ')} {formatBkkTime(nodesUpdatedAt, { seconds: true })}</span>
            )}
          </div>

          <ul className="m-0 p-4 list-none space-y-3 flex-1">
            {isLoadingNodes ? (
              <li className="text-center py-8 text-[var(--text-muted)] text-[13px]">{t('Checking nodes…', 'กำลังตรวจ node…')}</li>
            ) : nodesError ? (
              <li className="text-center py-8 text-red-600 dark:text-red-400 text-[13px]">{t('Could not reach the status check.', 'ติดต่อระบบตรวจสถานะไม่ได้')}</li>
            ) : safeNodes.length === 0 ? (
              <li className="text-center py-8 text-[var(--text-muted)] text-[13px]">{t('No edge nodes configured.', 'ยังไม่ได้ตั้งค่า edge node')}</li>
            ) : (
              safeNodes.map((node) => {
                const state = stateOf(node)
                const isCore = node.region === 'MAIN'
                const tls = (node as any).ssl_status as string | undefined
                return (
                  <li
                    key={node.region}
                    className="flex items-center justify-between gap-3 p-3 rounded-lg bg-[var(--bg-primary)] border border-[var(--bg-border)]"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <span className="text-2xl leading-none" aria-hidden="true">{node.flag || '🌐'}</span>
                      <div className="min-w-0">
                        <p className="font-semibold text-[13px] text-[var(--text-primary)] m-0 truncate">
                          {node.name || node.region}{isCore ? t(' (WAF core)', ' (WAF core)') : ''}
                        </p>
                        <p className="text-[12px] text-[var(--text-muted)] m-0">
                          {state === 'online' && node.latency_ms
                            ? t(`Health check ${node.latency_ms} ms`, `health check ${node.latency_ms} ms`)
                            : t('No round-trip sample', 'ยังไม่มีค่าเวลาไป-กลับ')}
                          {!isCore && tls
                            ? tls === 'port_open'
                              ? t(', TLS port open', ', พอร์ต TLS เปิดอยู่')
                              : t(', TLS port not reachable', ', เข้าถึงพอร์ต TLS ไม่ได้')
                            : ''}
                        </p>
                      </div>
                    </div>
                    <Badge
                      color={state === 'online' ? 'success' : state === 'missed' ? 'warning' : state === 'offline' ? 'danger' : 'gray'}
                      dot
                    >
                      {lang === 'th' ? EDGE_STATE_LABEL_TH[state] : EDGE_STATE_LABEL[state]}
                    </Badge>
                  </li>
                )
              })
            )}
          </ul>
        </section>

        {/* Cache Performance Breakdown */}
        <section className="lg:col-span-2 dash-card overflow-hidden flex flex-col" aria-labelledby="cache-heading">
          <div className="dash-card-header">
            <div className="flex items-center gap-2">
              <Layers size={16} className="text-[var(--text-muted)]" aria-hidden="true" />
              <h3 id="cache-heading">{t('Requests and cache hits per edge', 'request และ cache hit แยกตาม edge')}</h3>
            </div>
          </div>

          <div className="p-4 sm:p-5 flex-1 flex flex-col md:flex-row gap-6 items-center">
            <div className="flex-1 h-[220px] w-full">
              {statsList.length === 0 ? (
                <div className="h-full flex items-center justify-center text-[13px] text-[var(--text-muted)]">
                  {isLoadingStats
                    ? t('Loading…', 'กำลังโหลด…')
                    : statsError
                      ? t('Cache counters unavailable.', 'ไม่มีข้อมูลตัวนับ cache')
                      : t('No per-edge counters reported yet.', 'ยังไม่มีตัวนับของแต่ละ edge')}
                </div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={statsList} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                    <CartesianGrid stroke={gridColor} strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="region" stroke={axisColor} fontSize={11} tickLine={false} />
                    <YAxis stroke={axisColor} fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} width={44} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="request_count" name={t('Requests', 'Request')} fill={isDark ? '#38bdf8' : '#0369a1'} radius={[4, 4, 0, 0]} isAnimationActive={false} />
                    <Bar dataKey="cache_hit" name={t('Cache hits', 'Cache hit')} fill="#059669" radius={[4, 4, 0, 0]} isAnimationActive={false} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>

            <div className="w-full md:w-[220px] flex flex-col items-center shrink-0">
              {pieData.length > 0 ? (
                <>
                  <div className="h-[140px] w-[140px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%" innerRadius={42} outerRadius={62} paddingAngle={2} dataKey="value" isAnimationActive={false}>
                          {pieData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={tooltipStyle} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <ul className="m-0 p-0 list-none w-full space-y-1 mt-2 text-[12.5px]">
                    {pieData.map((d) => (
                      <li key={d.name} className="flex justify-between items-center text-[var(--text-secondary)]">
                        <span className="flex items-center gap-1.5 truncate">
                          <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: d.color }} aria-hidden="true" />
                          {d.name}
                        </span>
                        <span className="font-mono font-semibold text-[var(--text-primary)]">{d.value.toLocaleString()}</span>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <p className="m-0 text-[13px] text-[var(--text-muted)] text-center">{t('No cache outcomes recorded yet.', 'ยังไม่มีผลของ cache ที่บันทึกไว้')}</p>
              )}
            </div>
          </div>
        </section>
      </div>

      <section className="dash-card overflow-hidden" aria-labelledby="rtt-heading">
        <div className="dash-card-header">
          <div className="flex items-center gap-2">
            <Clock size={16} className="text-[var(--text-muted)]" aria-hidden="true" />
            <div>
              <h3 id="rtt-heading">{t('Health check round trip (ms)', 'เวลาไป-กลับของ health check (ms)')}</h3>
              <p className="m-0 text-[12px] text-[var(--text-muted)]">
                {t('From the control plane to each edge, latest check. Not the latency your visitors see.', 'จาก control plane ไปยังแต่ละ edge จากการตรวจล่าสุด ไม่ใช่ความหน่วงที่ผู้เข้าชมเห็น')}
              </p>
            </div>
          </div>
        </div>
        <div className="p-4 sm:p-5 h-[220px]">
          {isLoadingNodes ? (
            <div className="h-full flex items-center justify-center text-[13px] text-[var(--text-muted)]">{t('Checking…', 'กำลังตรวจ…')}</div>
          ) : rttData.every((d) => d.rtt === null) ? (
            <div className="h-full flex items-center justify-center text-[13px] text-[var(--text-muted)]">{t('No edge answered the last check.', 'ไม่มี edge ตอบการตรวจครั้งล่าสุด')}</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={rttData} layout="vertical" margin={{ top: 4, right: 24, left: 8, bottom: 0 }}>
                <CartesianGrid stroke={gridColor} strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke={axisColor} fontSize={11} tickLine={false} unit=" ms" allowDecimals={false} />
                <YAxis type="category" dataKey="name" stroke={axisColor} fontSize={12} tickLine={false} axisLine={false} width={140} />
                <Tooltip contentStyle={tooltipStyle} formatter={(v: any) => (v == null ? t('no answer', 'ไม่ตอบ') : `${v} ms`)} />
                <Bar dataKey="rtt" name={t('Round trip', 'เวลาไป-กลับ')} fill={isDark ? '#38bdf8' : '#0369a1'} radius={[0, 4, 4, 0]} maxBarSize={28} isAnimationActive={false} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </section>

      <section className="dash-card p-4 sm:p-5" aria-labelledby="purge-heading">
        <div className="flex items-center gap-2 mb-1.5">
          <Trash2 size={16} className="text-[var(--text-muted)]" aria-hidden="true" />
          <h3 id="purge-heading" className="text-[14px] font-semibold text-[var(--text-primary)] m-0">{t("Purge a site's cache", 'ล้าง cache ของเว็บ')}</h3>
        </div>
        <p className="text-[13px] text-[var(--text-secondary)] m-0">
          {t('Purging works per site. Open the site in', 'การล้าง cache ทำทีละเว็บ เปิดเว็บใน')}{' '}
          <Link to="/origins" className="text-[var(--accent)] hover:underline">Origins</Link>
          {t(
            ', then use Purge cache on its Overview tab. The purge reaches every edge within a few seconds.',
            ' แล้วใช้ปุ่มล้าง cache ที่แท็บภาพรวม คำสั่งจะถึงทุก edge ภายในไม่กี่วินาที',
          )}
        </p>
      </section>
    </div>
  )
}

export default CDN
