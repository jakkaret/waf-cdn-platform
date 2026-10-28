import React, { useState } from 'react'
import { buildTunnelCommands, tunnelErrorMessage } from '../lib/tunnelCommands'
import { tunnelStatusBadge, combineTunnelHubStatus } from '../lib/tunnelStatus'
import { formatBkkDateTime } from '../lib/time'
import { useVerifiedGuard } from '../components/auth/EmailVerifyGate'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { toast } from 'react-hot-toast'
import {
  Network,
  Terminal,
  Server,
  Copy,
  Check,
  Shield,
  Zap,
  Activity,
  ExternalLink,
  Laptop,
  Box,
  Sparkles,
  RefreshCw,
  Plus,
  Trash2,
} from 'lucide-react'
import { CRS_VERSION } from '../lib/crsVersion'
import { useDebouncedValue } from '../lib/useDebouncedValue'
import { statusWord, useT } from '../i18n'

// A platform-named address (POST /api/tunnels/quick) for a user who has no
// domain of their own; see services/quick_tunnel.py.
interface QuickTunnel {
  origin_id: string
  domain_name: string
  url: string
  port: number | null
  owner_username: string
  created_at: string
  last_seen_at: string | null
  is_online: boolean
  expires_at: string | null
}

export const Tunnels: React.FC = () => {
  const queryClient = useQueryClient()
  const guard = useVerifiedGuard()
  const { t, lang } = useT()
  // The platform names the address (quick tunnel). A domain the user owns is
  // connected from its origin instead, not from this page.
  const [quickHost, setQuickHost] = useState<string | null>(null)
  const [localPort, setLocalPort] = useState<number>(3000)
  const [localIp, setLocalIp] = useState('127.0.0.1')
  const [activeTab, setActiveTab] = useState<'linux' | 'docker'>('linux')
  const [scope, setScope] = useState<'my' | 'all'>('my')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  // Fetch live active tunnels status from FRP server (shared-token clients:
  // juice/dvwa/bwapp).
  const { data, isFetching, refetch, isError: frpErrored } = useQuery({
    queryKey: ['tunnels-status', scope],
    queryFn: () => api.get('/tunnels/status', { params: { scope } }).then((r) => r.data),
    refetchInterval: 6000,
  })

  // 2026-09-20: this page used to only ever poll the FRP status above --
  // this platform's second, custom domain-scoped tunnel protocol (e.g.
  // vampi) had zero visibility here at all. /api/tunnel/status reports
  // that system's real state (server_running, from the tunnel server's own
  // state file, considered stale after a timeout -- see api/tunnel.py).
  const { data: cloudwaf, refetch: refetchCloudwaf } = useQuery({
    queryKey: ['cloudwaf-tunnel-status'],
    queryFn: () => api.get('/tunnel/status').then((r) => r.data),
    refetchInterval: 6000,
  })

  const hubStatus = combineTunnelHubStatus(data !== undefined && !frpErrored, cloudwaf)
  const cloudwafAgents = cloudwaf?.agents || []

  const { data: quickData } = useQuery({
    queryKey: ['quick-tunnels'],
    queryFn: () => api.get('/tunnels/quick').then((r) => r.data),
    refetchInterval: 10000,
  })
  const quickTunnels: QuickTunnel[] = quickData?.tunnels || []
  const quickLimit: number = quickData?.limit ?? 3
  const selectedQuick = quickTunnels.find((q) => q.domain_name === quickHost) || quickTunnels[0] || null

  const selectQuick = (q: QuickTunnel) => {
    setQuickHost(q.domain_name)
    if (q.port) setLocalPort(q.port)
  }

  // combineTunnelHubStatus words its detail in English; the Thai is looked up here.
  const hubDetail = (detail: string) => {
    if (lang !== 'th') return detail
    if (detail === 'Both tunnel systems reachable') return 'ระบบ tunnel ทั้งสองเชื่อมต่อได้'
    if (detail === 'Neither tunnel system is reachable') return 'เชื่อมต่อระบบ tunnel ไม่ได้ทั้งสองระบบ'
    if (detail.endsWith(' unreachable')) return `${detail.slice(0, -' unreachable'.length)} เชื่อมต่อไม่ได้`
    return detail
  }

  const createQuick = useMutation({
    mutationFn: () => api.post('/tunnels/quick', { port: localPort }).then((r) => r.data),
    onSuccess: (created: { domain_name: string }) => {
      setQuickHost(created.domain_name)
      queryClient.invalidateQueries({ queryKey: ['quick-tunnels'] })
      toast.success(t(`Created ${created.domain_name}`, `สร้าง ${created.domain_name} แล้ว`))
    },
    onError: (err) => toast.error(tunnelErrorMessage(err, lang) || t('Could not create the address', 'สร้างที่อยู่ไม่สำเร็จ')),
  })

  const removeQuick = useMutation({
    mutationFn: (originId: string) => api.delete(`/tunnels/quick/${originId}`).then((r) => r.data),
    onSuccess: (r: { domain_name: string }) => {
      if (r.domain_name === quickHost) setQuickHost(null)
      queryClient.invalidateQueries({ queryKey: ['quick-tunnels'] })
      toast.success(t(`Removed ${r.domain_name}`, `ลบ ${r.domain_name} แล้ว`))
    },
    onError: (err) => toast.error(tunnelErrorMessage(err, lang) || t('Could not remove the address', 'ลบที่อยู่ไม่สำเร็จ')),
  })

  // Each config-generator call mints a tunnel token and scans the domains
  // table, so wait for typing to pause instead of calling per keystroke (F-104).
  const debouncedDomain = useDebouncedValue(selectedQuick?.domain_name || '')
  const debouncedPort = useDebouncedValue(localPort)
  const debouncedIp = useDebouncedValue(localIp)

  // Fetch generated commands
  const { data: configData, error: configError } = useQuery({
    queryKey: ['tunnel-config', debouncedDomain, debouncedPort, debouncedIp, activeTab],
    queryFn: () =>
      api
        .get('/tunnels/config-generator', {
          params: { domain: debouncedDomain, port: debouncedPort, local_ip: debouncedIp, platform: activeTab },
        })
        .then((r) => r.data),
    enabled: debouncedDomain.trim().length > 0,
    // A 403/422 is an answer, not a hiccup: show it instead of retrying.
    retry: false,
  })

  const tunnels = data?.tunnels || []
  // Derive the live count from the same rows the table renders so the
  // summary cards and the table heading can never disagree (the backend's
  // active_count previously read 0 while the table listed 5 tunnels).
  const activeCount = data === undefined ? null : tunnels.filter((row: any) => row.is_online).length

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    toast.success(t('Copied the command', 'คัดลอกคำสั่งแล้ว'))
    setTimeout(() => setCopiedKey(null), 2500)
  }

  // The install command carries a domain-scoped JWT that only the backend can
  // mint. Show only what it returned; never fabricate a command client-side
  // (the old fallback here printed a hardcoded placeholder token and an
  // unscoped frpc config). buildTunnelCommands returns null until the backend
  // has minted a config for a domain the user owns.
  const cmds = buildTunnelCommands(configData)
  const configMessage = debouncedDomain.trim() ? tunnelErrorMessage(configError, lang) : null
  const PLACEHOLDER = configMessage
    ? `# ${configMessage}`
    : t('# Create an address above to get a signed install command.', '# สร้างที่อยู่ด้านบนก่อน เพื่อรับคำสั่งติดตั้งที่ลงนามแล้ว')
  const linuxCmd = cmds?.linux || PLACEHOLDER
  const dockerCmd = cmds?.docker || PLACEHOLDER

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title={t('Private tunnels', 'Private tunnel')}
        subtitle={t(
          'Connect a server that has no public IP. A small agent on it opens an outbound FRP tunnel to the WAF, so no port forwarding is needed.',
          'เชื่อมเซิร์ฟเวอร์ที่ไม่มี public IP โดย agent ขนาดเล็กบนเครื่องจะเปิด FRP tunnel ขาออกมาหา WAF จึงไม่ต้องทำ port forwarding',
        )}
        badge={
          <Badge color="success" dot>
            {activeCount ?? '—'} {t('TUNNELS ACTIVE', 'tunnel ทำงานอยู่')}
          </Badge>
        }
      />

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-4 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[12px] font-mono text-[var(--text-muted)]">
              {t('Tunnel hub status', 'สถานะ tunnel hub')}
            </span>
            <div className="flex items-center gap-2 mt-1">
              <span
                className={`w-2.5 h-2.5 rounded-full ${hubStatus.online ? 'bg-emerald-400 animate-ping' : 'bg-red-500'}`}
              />
              <span
                className={`text-[16px] font-bold font-mono ${hubStatus.online ? 'text-[var(--text-primary)]' : 'text-red-400'}`}
              >
                {statusWord(hubStatus.label, lang)}
              </span>
            </div>
            <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">{hubDetail(hubStatus.detail)}</p>
          </div>
          <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Server size={22} />
          </div>
        </div>

        <div className="card p-4 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[12px] font-mono text-[var(--text-muted)]">
              {t('Active tunnels', 'tunnel ที่ทำงานอยู่')}
            </span>
            <div className="text-[20px] font-bold text-[var(--text-primary)] font-mono mt-1">
              {activeCount ?? '—'} {t('connected', 'เชื่อมต่ออยู่')}
            </div>
            <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">{t('Persistent FRP links, live', 'การเชื่อมต่อ FRP แบบต่อเนื่อง แสดงสด')}</p>
          </div>
          <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Network size={22} />
          </div>
        </div>

        <div className="card p-4 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[12px] font-mono text-[var(--text-muted)]">
              {t('WAF protection', 'การป้องกันของ WAF')}
            </span>
            <div className="text-[16px] font-bold text-emerald-400 font-mono mt-1">
              ModSec CRS {CRS_VERSION} {t('active', 'ทำงานอยู่')}
            </div>
            <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">{t('The server IP is never exposed to the internet', 'ไม่เปิดเผย IP ของเซิร์ฟเวอร์สู่อินเทอร์เน็ต')}</p>
          </div>
          <div className="p-3 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Shield size={22} />
          </div>
        </div>
      </div>

      {/* Interactive 1-Click Script Generator */}
      <div className="card p-6 border border-indigo-500/30 bg-gradient-to-br from-[var(--bg-surface)] to-indigo-950/20 rounded-2xl shadow-md space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
              <Terminal size={20} />
            </div>
            <div>
              <h2 className="text-[16px] font-bold text-[var(--text-primary)] font-mono m-0">
                {t('Private tunnel agent installer', 'สร้างคำสั่งติดตั้ง tunnel agent')}
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                {t('Generate an install command for your private app, Docker container, or local machine.', 'สร้างคำสั่งติดตั้งสำหรับแอป, Docker container หรือเครื่องในเครือข่ายส่วนตัวของคุณ')}
              </p>
            </div>
          </div>
          <span className="px-2.5 py-1 rounded-full text-[11px] font-mono bg-indigo-500/20 text-indigo-800 dark:text-indigo-300 border border-indigo-500/30 font-semibold flex items-center gap-1.5">
            <Zap size={13} className="text-amber-400" /> {t('1-step setup', 'ตั้งค่าขั้นตอนเดียว')}
          </span>
        </div>

        {/* The platform-named address the agent serves */}
        <div className="rounded-xl border border-[var(--bg-border)] bg-[var(--bg-surface)] p-4 space-y-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <p className="text-[12px] text-[var(--text-secondary)] m-0 max-w-[60ch]">
              {t('The platform gives your app an address under', 'แพลตฟอร์มจะให้ที่อยู่สำหรับแอปของคุณภายใต้')}{' '}
              <span className="font-mono">{quickData?.zone || '…'}</span>.{' '}
              {t(
                `The name is random and cannot be chosen. An address whose agent stays offline for ${quickData?.idle_days ?? 7} days is removed.`,
                `ชื่อจะสุ่มให้และเลือกเองไม่ได้ ที่อยู่ที่ agent ออฟไลน์ติดกัน ${quickData?.idle_days ?? 7} วันจะถูกลบ`,
              )}
            </p>
            <button
              onClick={() => guard('agent_token', () => createQuick.mutate())}
              disabled={createQuick.isPending || quickTunnels.length >= quickLimit}
              className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-mono text-[12px] font-semibold flex items-center gap-1.5 transition-all"
            >
              <Plus size={13} />
              {createQuick.isPending
                ? t('Creating…', 'กำลังสร้าง…')
                : t(`New address (${quickTunnels.length}/${quickLimit})`, `สร้างที่อยู่ใหม่ (${quickTunnels.length}/${quickLimit})`)}
            </button>
          </div>

          {quickTunnels.length === 0 ? (
            <p className="text-[12px] text-[var(--text-muted)] m-0">
              {t('You have no address yet. Set the local port below, then press New address.', 'ยังไม่มีที่อยู่ ตั้ง local port ด้านล่างแล้วกดสร้างที่อยู่ใหม่')}
            </p>
          ) : (
            <ul className="divide-y divide-[var(--bg-border-subtle)] m-0 p-0 list-none">
              {quickTunnels.map((q) => {
                const b = tunnelStatusBadge(q.is_online)
                const selected = selectedQuick?.domain_name === q.domain_name
                return (
                  <li key={q.origin_id} className="flex flex-wrap items-center gap-3 py-2">
                    <label className="flex items-center gap-2 min-w-0 cursor-pointer">
                      <input
                        type="radio"
                        name="quick-tunnel"
                        checked={selected}
                        onChange={() => selectQuick(q)}
                        className="accent-indigo-500"
                      />
                      <span className="font-mono text-[13px] text-[var(--text-primary)] break-all">{q.domain_name}</span>
                    </label>
                    <Badge color={b.color}>{statusWord(b.label, lang)}</Badge>
                    <span className="text-[11.5px] text-[var(--text-muted)] font-mono">
                      {q.port ? `port ${q.port} · ` : ''}
                      {q.expires_at
                        ? t(
                            `removed after ${formatBkkDateTime(q.expires_at, { seconds: false })} if still offline`,
                            `จะถูกลบหลัง ${formatBkkDateTime(q.expires_at, { seconds: false })} ถ้ายังออฟไลน์`,
                          )
                        : t('connected', 'เชื่อมต่ออยู่')}
                    </span>
                    <span className="ml-auto flex items-center gap-1">
                      <a
                        href={q.url}
                        target="_blank"
                        rel="noreferrer"
                        className="p-1.5 rounded-lg text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]"
                        title={t('Open', 'เปิด')}
                        aria-label={t('Open', 'เปิด')}
                      >
                        <ExternalLink size={13} />
                      </a>
                      <button
                        onClick={() => {
                          if (
                            window.confirm(
                              t(
                                `Remove ${q.domain_name}? Its agent stops working and the name is gone for good.`,
                                `ลบ ${q.domain_name}? agent ของที่อยู่นี้จะหยุดทำงานและชื่อนี้จะหายไปถาวร`,
                              ),
                            )
                          ) {
                            removeQuick.mutate(q.origin_id)
                          }
                        }}
                        disabled={removeQuick.isPending}
                        className="p-1.5 rounded-lg text-[var(--text-secondary)] hover:text-red-400 hover:bg-[var(--bg-hover)] disabled:opacity-50"
                        title={t('Remove', 'ลบ')}
                        aria-label={t('Remove', 'ลบ')}
                      >
                        <Trash2 size={13} />
                      </button>
                    </span>
                  </li>
                )
              })}
            </ul>
          )}
        </div>

        {/* Input Parameters Form */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
          <div>
            <label className="block text-[11px] font-mono text-[var(--text-muted)] mb-1">
              Local port
            </label>
            <input
              type="number"
              value={localPort}
              onChange={(e) => setLocalPort(Number(e.target.value))}
              placeholder="3000"
              className="w-full px-3 py-2 bg-[var(--bg-surface)] border border-[var(--bg-border)] rounded-lg text-[13px] font-mono text-[var(--text-primary)] focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono text-[var(--text-muted)] mb-1">
              {t('Local IP address', 'Local IP')}
            </label>
            <input
              type="text"
              value={localIp}
              onChange={(e) => setLocalIp(e.target.value)}
              placeholder="127.0.0.1"
              className="w-full px-3 py-2 bg-[var(--bg-surface)] border border-[var(--bg-border)] rounded-lg text-[13px] font-mono text-[var(--text-primary)] focus:outline-none focus:border-indigo-500"
            />
          </div>
        </div>

        {/* Platform Tabs */}
        <div className="flex items-center gap-2 mb-3 border-b border-[var(--bg-border)] pb-2">
          <button
            onClick={() => setActiveTab('linux')}
            className={`px-3 py-1.5 rounded-lg text-[12px] font-mono font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'linux'
                ? 'bg-indigo-500 text-white shadow-md'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
            }`}
          >
            <Laptop size={14} /> {t('Linux service (one line)', 'Linux service (คำสั่งเดียว)')}
          </button>
          <button
            onClick={() => setActiveTab('docker')}
            className={`px-3 py-1.5 rounded-lg text-[12px] font-mono font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'docker'
                ? 'bg-indigo-500 text-white shadow-md'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
            }`}
          >
            <Box size={14} /> Docker container
          </button>
        </div>

        {/* Code / Command Block */}
        <div className="relative">
          {activeTab === 'linux' && (
            <div className="p-4 rounded-xl bg-black/80 border border-indigo-500/30 text-emerald-400 font-mono text-[12.5px] leading-relaxed overflow-x-auto select-all">
              <span className="text-gray-500 select-none">$ </span>
              {linuxCmd}
            </div>
          )}

          {activeTab === 'docker' && (
            <div className="p-4 rounded-xl bg-black/80 border border-indigo-500/30 text-cyan-400 font-mono text-[12.5px] leading-relaxed overflow-x-auto select-all">
              <span className="text-gray-500 select-none">$ </span>
              {dockerCmd}
            </div>
          )}

          {/* Copy Button */}
          <button
            onClick={() => cmds && handleCopy(activeTab === 'linux' ? linuxCmd : dockerCmd, activeTab)}
            disabled={!cmds}
            className="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-mono text-[11.5px] font-semibold flex items-center gap-1.5 transition-all shadow-lg cursor-pointer"
          >
            {copiedKey === activeTab ? <Check size={13} /> : <Copy size={13} />}
            {copiedKey === activeTab ? t('COPIED!', 'คัดลอกแล้ว') : t('COPY COMMAND', 'คัดลอกคำสั่ง')}
          </button>
        </div>

        <div className="mt-3 flex items-center gap-2 text-[11.5px] text-[var(--text-muted)]">
          <Sparkles size={13} className="text-amber-400" />
          <span>
            {t(
              'Paste this single command in your private server terminal. It downloads the agent and keeps a connection open in the background, 24/7.',
              'วางคำสั่งนี้ใน terminal ของเซิร์ฟเวอร์ส่วนตัว ระบบจะดาวน์โหลด agent และเปิดการเชื่อมต่อค้างไว้เบื้องหลังตลอด 24 ชั่วโมง',
            )}
          </span>
        </div>
      </div>

      {/* Live Active Tunnels Table */}
      <div className="card p-5 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-2xl shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity size={18} className="text-indigo-400" />
            <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
              {t('Connected tunnel proxies', 'tunnel proxy ที่เชื่อมต่ออยู่')} ({activeCount ?? '—'}
              {activeCount !== null && tunnels.length !== activeCount ? t(` of ${tunnels.length}`, ` จาก ${tunnels.length}`) : ''})
            </h3>
          </div>
          <div className="flex items-center gap-2">
            {data?.is_admin && (
              <div className="flex items-center p-0.5 rounded-lg bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)]">
                <button
                  onClick={() => setScope('my')}
                  className={`px-2.5 py-1 rounded-md text-[11.5px] font-mono transition-all ${
                    scope === 'my'
                      ? 'bg-indigo-600 text-white shadow-sm font-semibold'
                      : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  👤 {t('My tunnels', 'tunnel ของฉัน')}
                </button>
                <button
                  onClick={() => setScope('all')}
                  className={`px-2.5 py-1 rounded-md text-[11.5px] font-mono transition-all ${
                    scope === 'all'
                      ? 'bg-indigo-600 text-white shadow-sm font-semibold'
                      : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  🌐 {t('All tunnels (admin)', 'tunnel ทั้งระบบ (admin)')}
                </button>
              </div>
            )}
            <button
              onClick={() => {
                refetch()
                toast.success(t('Refreshed tunnel connections', 'รีเฟรชการเชื่อมต่อ tunnel แล้ว'))
              }}
              className="p-1.5 rounded-lg bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] border border-[var(--bg-border)] transition-colors cursor-pointer"
              title={t('Refresh tunnels', 'รีเฟรช tunnel')}
              aria-label={t('Refresh tunnels', 'รีเฟรช tunnel')}
            >
              <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-[12.5px]">
            <thead>
              <tr className="border-b border-[var(--bg-border)] text-[var(--text-muted)] text-[11px]">
                <th className="py-2.5 px-3">Tunnel proxy</th>
                <th className="py-2.5 px-3">{t('Protected public domain', 'โดเมนสาธารณะที่ป้องกัน')}</th>
                {data?.is_admin && <th className="py-2.5 px-3">{t('Owner', 'เจ้าของ')}</th>}
                <th className="py-2.5 px-3">{t('Target', 'ปลายทาง')}</th>
                <th className="py-2.5 px-3">{t('Live connections', 'การเชื่อมต่อ')}</th>
                <th className="py-2.5 px-3 text-right">{t('Status', 'สถานะ')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--bg-border-subtle)]">
              {tunnels.length === 0 ? (
                <tr>
                  <td colSpan={data?.is_admin ? 6 : 5} className="py-8 text-center text-[var(--text-muted)]">
                    {t(
                      'No tunnel proxies are connected. Run the install command on your private machine to connect one.',
                      'ยังไม่มี tunnel proxy ที่เชื่อมต่ออยู่ รันคำสั่งติดตั้งบนเครื่องส่วนตัวของคุณเพื่อเชื่อมต่อ',
                    )}
                  </td>
                </tr>
              ) : (
                tunnels.map((row: any, idx: number) => {
                  const domainName = row.custom_domains?.[0] || row.domain || row.name
                  return (
                    <tr key={idx} className="hover:bg-[var(--bg-hover)] transition-colors">
                      <td className="py-3 px-3 font-bold text-[var(--text-primary)] flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        {row.name}
                      </td>
                      <td className="py-3 px-3 text-indigo-400 hover:text-indigo-900 dark:hover:text-indigo-300">
                        <a
                          href={`https://${domainName}`}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-1 underline underline-offset-2"
                        >
                          {domainName}
                          <ExternalLink size={11} />
                        </a>
                      </td>
                      {data?.is_admin && (
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded-md text-[11px] font-mono ${
                              row.is_mine
                                ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20'
                                : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            }`}
                          >
                            {row.is_mine ? `👤 ${t('You', 'คุณ')}` : `👤 @${row.owner_username}`}
                          </span>
                        </td>
                      )}
                      <td className="py-3 px-3 text-amber-300">{row.local_target || t('Local app', 'แอปในเครื่อง')}</td>
                      <td className="py-3 px-3 text-[var(--text-secondary)]">{row.connections || 0} {t('conns', 'การเชื่อมต่อ')}</td>
                      <td className="py-3 px-3 text-right">
                        {(() => {
                          const b = tunnelStatusBadge(row.is_online)
                          return <Badge color={b.color}>{statusWord(b.label, lang)}</Badge>
                        })()}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Custom Tunnel (cloudwaf) -- the platform's second, domain-scoped
          tunnel protocol (e.g. vampi). Previously invisible on this page
          entirely: only the FRP table above was ever rendered. */}
      <div className="card p-5 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-2xl shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-purple-400" />
            <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
              {t('Custom tunnel', 'Custom tunnel')} — cloudwaf ({cloudwafAgents.length})
            </h3>
          </div>
          <button
            onClick={() => refetchCloudwaf()}
            className="p-1.5 rounded-lg bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] border border-[var(--bg-border)] transition-colors cursor-pointer"
            title={t('Refresh custom tunnel', 'รีเฟรช custom tunnel')}
            aria-label={t('Refresh custom tunnel', 'รีเฟรช custom tunnel')}
          >
            <RefreshCw size={14} />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-[12.5px]">
            <thead>
              <tr className="border-b border-[var(--bg-border)] text-[var(--text-muted)] text-[11px]">
                <th className="py-2.5 px-3">Origin</th>
                <th className="py-2.5 px-3">{t('Domains', 'โดเมน')}</th>
                <th className="py-2.5 px-3">{t('Live connections', 'การเชื่อมต่อ')}</th>
                <th className="py-2.5 px-3 text-right">{t('Status', 'สถานะ')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--bg-border-subtle)]">
              {!cloudwaf?.server_running ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-[var(--text-muted)]">
                    {cloudwaf?.reason || t('The custom tunnel server has not published any state.', 'custom tunnel server ยังไม่ได้ส่งสถานะใด ๆ')}
                  </td>
                </tr>
              ) : cloudwafAgents.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-[var(--text-muted)]">
                    {t('No custom-tunnel agents are connected.', 'ยังไม่มี agent ของ custom tunnel ที่เชื่อมต่ออยู่')}
                  </td>
                </tr>
              ) : (
                cloudwafAgents.map((a: any) => (
                  <tr key={a.agent_id} className="hover:bg-[var(--bg-hover)] transition-colors">
                    <td className="py-3 px-3 font-bold text-[var(--text-primary)] flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      {a.origin_label || a.agent_id}
                    </td>
                    <td className="py-3 px-3 text-indigo-400">{(a.domains || []).join(', ') || '—'}</td>
                    <td className="py-3 px-3 text-[var(--text-secondary)]">{a.active_connections || 0} {t('conns', 'การเชื่อมต่อ')}</td>
                    <td className="py-3 px-3 text-right">
                      {/* server_running is fresh here (checked above), so
                          every agent still listed is connected right now --
                          same "presence = online" guarantee the server's
                          own snapshot() gives (see tunnel/server.py). */}
                      {(() => {
                        const b = tunnelStatusBadge(true)
                        return <Badge color={b.color}>{statusWord(b.label, lang)}</Badge>
                      })()}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Tunnels
