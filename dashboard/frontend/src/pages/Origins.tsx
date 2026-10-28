import React, { useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { toast } from 'react-hot-toast'
import { ArrowRight, Cable, Check, ChevronRight, Lock, Plus, RefreshCw, Search, Server } from 'lucide-react'
import { getOrigins, getOriginsOverview } from '../api/origins'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { ConnectSiteFlow } from '../components/ConnectSiteFlow'
import { ProtIcons, ProtLegend, StatusPill } from '../components/origins/OriginBits'
import { originTabPath } from '../components/layout/navigation'
import { useAuthStore } from '../store/authStore'
import { ORIGIN_ROLE_LABEL, canEditOrigin, originRoleOf } from '../lib/roles'
import { originHealth, onCount, protectionStates } from '../lib/originSummary'
import { originUpstreamLabel } from '../lib/originUpstream'
import { useVerifiedGuard } from '../components/auth/EmailVerifyGate'
import type { Origin, OriginOverview } from '../types'
import { useT } from '../i18n'

// The Origins list: one row per website with the same columns (status,
// protections, blocked in 24 h, next step), problems first. Every figure
// comes from GET /api/origins and /api/origins/overview.

type Filter = 'all' | 'act' | 'ok' | 'archived'

const fmt = (n: number) => n.toLocaleString('en-US')

export const Origins: React.FC = () => {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { t, lang } = useT()
  const guard = useVerifiedGuard()
  const currentUser = useAuthStore((st) => st.user)
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<Filter>(() => {
    try {
      const f = localStorage.getItem('origins-filter') as Filter | null
      return f && ['all', 'act', 'ok', 'archived'].includes(f) ? f : 'all'
    } catch {
      return 'all'
    }
  })
  const [isRefreshingStatus, setIsRefreshingStatus] = useState(false)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['origins'],
    queryFn: () => getOrigins(),
    refetchInterval: 15000,
  })
  // Heavier (one log query plus per-origin settings), so polled slower.
  const { data: overviewData, isLoading: overviewLoading } = useQuery({
    queryKey: ['origins-overview'],
    queryFn: () => getOriginsOverview(),
    refetchInterval: 60000,
  })
  const { data: quotaData } = useQuery({
    queryKey: ['origins-quota'],
    queryFn: () => api.get('/origins/quota').then((r) => r.data),
    refetchInterval: 30000,
  })

  // Tunnel connectivity is cached server-side for 60 s; this checks now.
  const handleRefreshStatus = async () => {
    setIsRefreshingStatus(true)
    try {
      const res = await getOrigins({ forceRefreshStatus: true })
      queryClient.setQueryData(['origins'], res)
      queryClient.invalidateQueries({ queryKey: ['origins-overview'] })
    } catch {
      toast.error(t('Could not refresh the tunnel status', 'รีเฟรชสถานะ tunnel ไม่สำเร็จ'))
    } finally {
      setIsRefreshingStatus(false)
    }
  }

  const setF = (f: Filter) => {
    setFilter(f)
    try {
      localStorage.setItem('origins-filter', f)
    } catch {
      /* per-viewer convenience only */
    }
  }

  const origins: Origin[] = data?.data?.origins || []
  const overview = useMemo(() => {
    const m = new Map<string, OriginOverview>()
    for (const r of overviewData?.data?.origins || []) m.set(r.origin_id, r)
    return m
  }, [overviewData])

  const rows = useMemo(
    () =>
      origins.map((o) => {
        const ov = overview.get(o.origin_id)
        const role = originRoleOf(o, currentUser?.user_id)
        return { o, ov, role, health: originHealth(o, ov?.domains, lang), prot: protectionStates(ov?.protection, lang) }
      }),
    [origins, overview, currentUser?.user_id, lang],
  )

  const live = rows.filter((r) => r.o.status !== 'archived')
  const act = live.filter((r) => r.health.needsAction).sort((a, b) => a.health.rank - b.health.rank || a.o.label.localeCompare(b.o.label))
  const ok = live.filter((r) => !r.health.needsAction).sort((a, b) => (b.ov?.blocked_24h ?? -1) - (a.ov?.blocked_24h ?? -1))
  const archived = rows.filter((r) => r.o.status === 'archived')

  const q = query.trim().toLowerCase()
  const match = (r: (typeof rows)[number]) =>
    !q || r.o.label.toLowerCase().includes(q) || r.o.ip.toLowerCase().includes(q) || originUpstreamLabel(r.o).toLowerCase().includes(q)

  const blockedKnown = ok.filter((r) => r.ov?.blocked_24h != null)
  const totalBlocked = blockedKnown.reduce((n, r) => n + (r.ov?.blocked_24h ?? 0), 0)
  const top = blockedKnown[0]
  const badCount = act.filter((r) => r.health.tone === 'bad').length
  const withOverview = ok.filter((r) => r.ov)
  const avgOn = withOverview.length ? withOverview.reduce((n, r) => n + onCount(r.prot), 0) / withOverview.length : null

  const quotaMax: number | null = quotaData?.origins?.max ?? null
  const quotaUsed: number = quotaData?.origins?.used ?? live.length
  const quotaFull: boolean = quotaData?.origins?.at_limit ?? false

  const groups: { key: string; label: string; tone: 'bad' | 'ok' | 'off'; list: typeof rows }[] = []
  if (filter === 'all' || filter === 'act') groups.push({ key: 'act', label: t('Needs action', 'ต้องจัดการ'), tone: 'bad', list: act.filter(match) })
  if (filter === 'all' || filter === 'ok') groups.push({ key: 'ok', label: t('Protected', 'ป้องกันอยู่'), tone: 'ok', list: ok.filter(match) })
  if (filter === 'archived') groups.push({ key: 'archived', label: t('Archived', 'เก็บถาวร'), tone: 'off', list: archived.filter(match) })
  const shown = groups.reduce((n, g) => n + g.list.length, 0)
  const scope = filter === 'archived' ? archived.length : live.length

  const segs: { id: Filter; label: string; count: number }[] = [
    { id: 'all', label: t('All', 'ทั้งหมด'), count: live.length },
    { id: 'act', label: t('Needs action', 'ต้องจัดการ'), count: act.length },
    { id: 'ok', label: t('Protected', 'ป้องกันอยู่'), count: ok.length },
    ...(archived.length ? [{ id: 'archived' as Filter, label: t('Archived', 'เก็บถาวร'), count: archived.length }] : []),
  ]

  const nextCell = (r: (typeof rows)[number]) => {
    const step = r.health.step
    if (!step) {
      return (
        <span className="flex items-center gap-2 text-[13px] text-[var(--text-muted)]">
          <Check size={15} className="text-[var(--success)]" />
          {t('All set', 'เรียบร้อย')}
        </span>
      )
    }
    if (!canEditOrigin(r.role)) {
      return (
        <span className="flex items-center gap-2 text-[13px] text-[var(--text-muted)] min-w-0" title={step.label}>
          <Lock size={15} className="shrink-0" />
          <span className="truncate">{t(`Ask an owner to ${step.label.charAt(0).toLowerCase() + step.label.slice(1)}`, `ให้ Owner ${step.label}`)}</span>
        </span>
      )
    }
    return (
      <span className="flex items-center gap-2 text-[13px] font-medium text-[var(--text-primary)] min-w-0" title={step.label}>
        <ArrowRight size={15} className="shrink-0 text-[var(--accent)]" />
        <span className="truncate">{step.label}</span>
      </span>
    )
  }

  const hrefFor = (r: (typeof rows)[number]) => {
    const step = r.health.step
    if (step?.tab && canEditOrigin(r.role)) return originTabPath(r.o.origin_id, step.tab)
    return `/origins/${encodeURIComponent(r.o.origin_id)}`
  }

  const cols = 'md:grid md:grid-cols-[minmax(0,2fr)_132px_148px_104px_minmax(0,1.6fr)_16px] md:items-center md:gap-x-5'

  return (
    <div className="space-y-5 animate-fade-in">
      <TopBar
        title="Origins"
        subtitle={t('The websites the WAF protects. Problems are listed first; open one to manage it.', 'เว็บไซต์ที่ WAF ป้องกันอยู่ รายการที่มีปัญหาแสดงก่อน เปิดรายการเพื่อจัดการ')}
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="secondary"
              onClick={() => navigate('/tunnels')}
              icon={<Cable size={14} />}
              title={t('For a server without a public IP: it connects out to the WAF through a tunnel agent', 'สำหรับเซิร์ฟเวอร์ที่ไม่มี public IP: เชื่อมออกมาหา WAF ผ่าน tunnel agent')}
            >
              {t('Connect through a tunnel', 'เชื่อมผ่าน tunnel')}
            </Button>
            <Button
              variant="brand"
              onClick={() => guard('create_origin', () => setIsAddModalOpen(true))}
              disabled={quotaFull}
              icon={<Plus size={14} />}
              title={quotaFull ? t('Your origin quota is full', 'โควตา origin ของคุณเต็มแล้ว') : t('Add a site by its domain', 'เพิ่มเว็บจากโดเมน')}
            >
              {t('Add origin', 'เพิ่ม origin')}
            </Button>
          </div>
        }
      />

      <section className="grid grid-cols-2 lg:grid-cols-4 gap-3" aria-label={t('Summary', 'สรุป')}>
        <div className="dash-card px-4 py-3.5 min-w-0">
          <div className="flex items-center gap-1.5 text-[12.5px] text-[var(--text-muted)]">
            <span className="w-[7px] h-[7px] rounded-full bg-[var(--danger)]" aria-hidden="true" />
            {t('Needs action', 'ต้องจัดการ')}
          </div>
          <div className="mt-1 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{isLoading ? '—' : act.length}</div>
          <div className="text-[12px] text-[var(--text-muted)] truncate">{act.length ? t(`${badCount} offline · ${act.length - badCount} waiting for setup`, `ออฟไลน์ ${badCount} · รอตั้งค่า ${act.length - badCount}`) : t('Nothing waiting on you', 'ไม่มีอะไรรอคุณจัดการ')}</div>
        </div>
        <div className="dash-card px-4 py-3.5 min-w-0">
          <div className="flex items-center gap-1.5 text-[12.5px] text-[var(--text-muted)]">
            <span className="w-[7px] h-[7px] rounded-full bg-[var(--success)]" aria-hidden="true" />
            {t('Protected', 'ป้องกันอยู่')}
          </div>
          <div className="mt-1 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{isLoading ? '—' : ok.length}</div>
          <div className="text-[12px] text-[var(--text-muted)] truncate">{overviewLoading ? t('Checking protections…', 'กำลังตรวจการป้องกัน…') : avgOn === null ? '—' : t(`${avgOn.toFixed(1)} of 5 protections on, on average`, `เปิดการป้องกันเฉลี่ย ${avgOn.toFixed(1)} จาก 5`)}</div>
        </div>
        <div className="dash-card px-4 py-3.5 min-w-0">
          <div className="text-[12.5px] text-[var(--text-muted)]">{t('Blocked · last 24 h', 'บล็อก · 24 ชม. ล่าสุด')}</div>
          <div className="mt-1 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">{overviewLoading ? '—' : blockedKnown.length ? fmt(totalBlocked) : '—'}</div>
          <div className="text-[12px] text-[var(--text-muted)] truncate">
            {top && totalBlocked > 0 ? t(`Most on ${top.o.label} (${Math.round(((top.ov?.blocked_24h ?? 0) / totalBlocked) * 100)}%)`, `มากสุดที่ ${top.o.label} (${Math.round(((top.ov?.blocked_24h ?? 0) / totalBlocked) * 100)}%)`) : t('Across protected origins', 'รวมทุก origin ที่ป้องกันอยู่')}
          </div>
        </div>
        <div className="dash-card px-4 py-3.5 min-w-0">
          <div className="text-[12.5px] text-[var(--text-muted)]">{t('Origin quota', 'โควตา origin')}</div>
          <div className="mt-1 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">
            {quotaUsed} <small className="text-[13px] font-normal text-[var(--text-muted)]">/ {quotaMax ?? '—'}</small>
          </div>
          <div className="mt-2 h-1 rounded bg-[var(--bg-border)] overflow-hidden">
            <div
              className={`h-full rounded ${quotaFull ? 'bg-[var(--danger)]' : 'bg-[var(--text-secondary)]'}`}
              style={{ width: quotaMax ? `${Math.min(100, (quotaUsed / quotaMax) * 100)}%` : '0%' }}
            />
          </div>
        </div>
      </section>

      <div className="flex flex-wrap items-center gap-2.5">
        <div className="inline-flex max-w-full overflow-x-auto rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-[3px] gap-0.5" role="group" aria-label={t('Filter origins', 'กรอง origin')}>
          {segs.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => setF(s.id)}
              aria-pressed={filter === s.id}
              className={`h-7 px-3 rounded-md text-[13px] font-medium inline-flex items-center gap-1.5 whitespace-nowrap cursor-pointer ${
                filter === s.id ? 'bg-[var(--bg-surface-active)] text-[var(--text-primary)]' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
              }`}
            >
              {s.label}
              <span className="font-mono text-[11.5px] text-[var(--text-muted)]">{s.count}</span>
            </button>
          ))}
        </div>
        <span className="flex-1" />
        <label className="relative w-full sm:w-64 order-first sm:order-none">
          <span className="sr-only">{t('Search origins', 'ค้นหา origin')}</span>
          <Search size={15} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={t('Search by name or address', 'ค้นหาจากชื่อหรือที่อยู่')}
            className="w-full dash-input h-9 pl-8 text-[13.5px]"
          />
        </label>
        <button
          type="button"
          onClick={handleRefreshStatus}
          disabled={isRefreshingStatus}
          title={t('Check tunnel connectivity now (skips the 60 s cache)', 'ตรวจการเชื่อมต่อ tunnel ทันที (ข้าม cache 60 วินาที)')}
          aria-label={t('Refresh status', 'รีเฟรชสถานะ')}
          className="h-9 w-9 grid place-items-center rounded-lg border border-[var(--bg-border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--bg-border-hover)] disabled:opacity-40 cursor-pointer"
        >
          <RefreshCw size={15} className={isRefreshingStatus ? 'animate-spin' : ''} />
        </button>
      </div>

      <div className="dash-card overflow-hidden" role="table" aria-label="Origins">
        <div className={`hidden ${cols} h-[38px] px-[18px] bg-[var(--bg-primary)] border-b border-[var(--bg-border)] text-[12px] font-medium text-[var(--text-muted)]`} role="row">
          <span role="columnheader">{t('Website', 'เว็บไซต์')}</span>
          <span role="columnheader">{t('Status', 'สถานะ')}</span>
          <span role="columnheader">{t('Protection', 'การป้องกัน')}</span>
          <span role="columnheader" className="text-right">{t('Blocked · 24 h', 'บล็อก · 24 ชม.')}</span>
          <span role="columnheader">{t('Next step', 'ขั้นต่อไป')}</span>
          <span />
        </div>

        {isLoading ? (
          <div className="py-12 text-center text-[13px] text-[var(--text-muted)]">{t('Loading origins…', 'กำลังโหลด origin…')}</div>
        ) : origins.length === 0 ? (
          <div className="py-12 px-6 text-center space-y-3">
            <Server size={32} className="mx-auto text-[var(--text-muted)] opacity-50" />
            <p className="m-0 text-[14px] font-semibold text-[var(--text-primary)]">{t('No origins yet', 'ยังไม่มี origin')}</p>
            <p className="m-0 text-[13px] text-[var(--text-muted)]">{t('Start from your domain. We find the server and tell you what to set up.', 'เริ่มจากโดเมนของคุณ ระบบหาเซิร์ฟเวอร์ให้และบอกสิ่งที่ต้องตั้งค่า')}</p>
            <Button variant="brand" onClick={() => guard('create_origin', () => setIsAddModalOpen(true))} icon={<Plus size={14} />}>
              {t('Connect your first site', 'เชื่อมเว็บแรกของคุณ')}
            </Button>
          </div>
        ) : shown === 0 ? (
          <div className="py-12 text-center text-[13px] text-[var(--text-muted)]">
            {q ? t(`No origins match “${query.trim()}”.`, `ไม่มี origin ที่ตรงกับ “${query.trim()}”`) : t('No origins in this group.', 'ไม่มี origin ในกลุ่มนี้')}
          </div>
        ) : (
          groups
            .filter((g) => g.list.length)
            .map((g) => (
              <React.Fragment key={g.key}>
                <div className="flex items-center gap-2 px-[18px] py-2.5 bg-[var(--bg-primary)] border-b border-[var(--bg-border-subtle)] text-[12px] font-semibold text-[var(--text-secondary)]" role="row">
                  <span className={`w-[7px] h-[7px] rounded-full ${g.tone === 'bad' ? 'bg-[var(--danger)]' : g.tone === 'ok' ? 'bg-[var(--success)]' : 'bg-[var(--text-muted)]'}`} />
                  {g.label}
                  <span className="font-mono font-medium text-[var(--text-muted)]">{g.list.length}</span>
                </div>
                {g.list.map((r) => {
                  const blocked = r.ov?.blocked_24h
                  const serving = r.health.tone === 'ok'
                  return (
                    <Link
                      key={r.o.origin_id}
                      to={hrefFor(r)}
                      role="row"
                      className={`group grid grid-cols-[minmax(0,1fr)_auto] gap-y-2.5 gap-x-3 px-4 py-3.5 ${cols} md:px-[18px] md:py-0 md:min-h-16 border-b border-[var(--bg-border-subtle)] hover:bg-[var(--bg-hover)] text-inherit no-underline`}
                    >
                      <div className="min-w-0" role="cell">
                        <span className="block truncate font-semibold text-[14px] text-[var(--text-primary)]" title={r.o.label}>
                          {r.o.label}
                        </span>
                        <span className="flex items-center gap-1.5 text-[12.5px] text-[var(--text-muted)] truncate">
                          {r.role ? ORIGIN_ROLE_LABEL[r.role] : t('Member', 'สมาชิก')}
                          <span className="opacity-50">·</span>
                          {r.o.is_tunnel ? <Cable size={12} /> : <Server size={12} />}
                          <span className="font-mono text-[11.5px] truncate">{r.o.is_tunnel ? 'Private tunnel' : originUpstreamLabel(r.o, lang)}</span>
                        </span>
                      </div>
                      <div role="cell" className="justify-self-end md:justify-self-start">
                        <StatusPill tone={r.health.tone}>{r.health.label}</StatusPill>
                      </div>
                      <div role="cell" title={t(`${onCount(r.prot)} of 5 protections on`, `เปิดการป้องกัน ${onCount(r.prot)} จาก 5`)}>
                        {r.ov ? <ProtIcons states={r.prot} /> : <span className="text-[12px] text-[var(--text-muted)]">{overviewLoading ? t('Checking…', 'กำลังตรวจ…') : '—'}</span>}
                      </div>
                      <div role="cell" className="justify-self-end text-right">
                        <span className={`font-mono tabular-nums text-[14px] ${serving && blocked ? 'font-medium text-[var(--text-primary)]' : 'text-[var(--text-muted)]'}`}>
                          {!serving || blocked == null ? '—' : fmt(blocked)}
                        </span>
                        <span className="md:hidden text-[12px] text-[var(--text-muted)]">{serving ? t(' blocked · 24 h', ' บล็อก · 24 ชม.') : t(' not serving traffic', ' ไม่มีทราฟฟิกผ่าน')}</span>
                      </div>
                      <div role="cell" className="col-span-2 md:col-span-1 min-w-0 border-t border-dashed border-[var(--bg-border-subtle)] pt-2.5 md:border-0 md:pt-0">
                        {nextCell(r)}
                      </div>
                      <ChevronRight size={16} className="hidden md:block text-[var(--bg-border-hover)] group-hover:text-[var(--text-secondary)]" aria-hidden="true" />
                    </Link>
                  )
                })}
              </React.Fragment>
            ))
        )}

        {origins.length > 0 && (
          <div className="flex flex-wrap justify-between gap-3 px-[18px] py-3 bg-[var(--bg-primary)] border-t border-[var(--bg-border)] text-[12.5px] text-[var(--text-muted)]">
            <span>{t(`Showing ${shown} of ${scope} origins`, `แสดง ${shown} จาก ${scope} origin`)}</span>
            <span>
              {t('Total blocked · 24 h', 'บล็อกรวม · 24 ชม.')} <b className="font-mono font-semibold text-[var(--text-primary)]">{blockedKnown.length ? fmt(totalBlocked) : '—'}</b>
            </span>
          </div>
        )}
      </div>

      <ProtLegend />

      {/* Domain first: the flow finds the server behind it and creates the
          origin + domain in one call, then lands on its live setup status. */}
      <Modal
        open={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        title={t('Connect your site', 'เชื่อมเว็บของคุณ')}
        description={t('We check the domain’s DNS and server before connecting.', 'ระบบจะตรวจ DNS และเซิร์ฟเวอร์ของโดเมนให้ก่อนเชื่อมต่อ')}
      >
        <ConnectSiteFlow
          onCancel={() => setIsAddModalOpen(false)}
          onDone={(originId) => {
            setIsAddModalOpen(false)
            refetch()
            queryClient.invalidateQueries({ queryKey: ['origins-overview'] })
            navigate(`/origins/${originId}?tab=domains`)
          }}
        />
      </Modal>
    </div>
  )
}

export default Origins
