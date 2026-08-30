import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
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
  FileCode,
  Sparkles,
  RefreshCw,
} from 'lucide-react'

export const Tunnels: React.FC = () => {
  const [domain, setDomain] = useState('juice.waf-it-kku.online')
  const [localPort, setLocalPort] = useState<number>(3000)
  const [localIp, setLocalIp] = useState('127.0.0.1')
  const [activeTab, setActiveTab] = useState<'linux' | 'docker' | 'toml'>('linux')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  // Fetch live active tunnels status from FRP server
  const { data, isFetching, refetch } = useQuery({
    queryKey: ['tunnels-status'],
    queryFn: () => api.get('/tunnels/status').then((r) => r.data),
    refetchInterval: 6000,
  })

  // Fetch generated commands. These carry the tunnel auth token, so the server
  // builds them (admin only) — nothing here may fall back to a literal token,
  // since this bundle is served to unauthenticated visitors.
  const {
    data: configData,
    isLoading: configLoading,
    isError: configError,
    error: configErrorDetail,
  } = useQuery({
    queryKey: ['tunnel-config', domain, localPort, localIp, activeTab],
    queryFn: () =>
      api
        .get('/tunnels/config-generator', {
          params: { domain, port: localPort, local_ip: localIp, platform: activeTab },
        })
        .then((r) => r.data),
    retry: false,
  })

  const tunnels = data?.tunnels || []
  const activeCount = data?.active_count || (tunnels.length > 0 ? tunnels.length : 0)

  const handleCopy = (text: string, key: string) => {
    if (!configData) {
      toast.error('No command to copy yet')
      return
    }
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    toast.success('Copied command to clipboard!')
    setTimeout(() => setCopiedKey(null), 2500)
  }

  const configStatus = configLoading
    ? '# Generating install command…'
    : configError
      ? (configErrorDetail as any)?.response?.status === 403
        ? '# Administrator access is required to generate an agent command.'
        : '# Could not reach the config generator. Try refreshing.'
      : '# No command available.'

  const linuxCmd = configData?.linux_command || configStatus
  const dockerCmd = configData?.docker_command || configStatus
  const rawToml = configData?.toml_config || configStatus

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="Private Edge Tunnels"
        subtitle="Secure outbound reverse tunneling for private origins without public IPs or port forwarding"
        badge={
          <Badge color="success" dot>
            {activeCount} TUNNELS ACTIVE
          </Badge>
        }
      />

      {/* Overview Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-4 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[12px] font-mono text-[var(--text-muted)] uppercase tracking-wider">
              Tunnel Hub Status
            </span>
            <div className="flex items-center gap-2 mt-1">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping" />
              <span className="text-[16px] font-bold text-[var(--text-primary)] font-mono">ONLINE & READY</span>
            </div>
            <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">WAF Central Core (main.waf-it-kku.online)</p>
          </div>
          <div className="p-3 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Server size={22} />
          </div>
        </div>

        <div className="card p-4 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[12px] font-mono text-[var(--text-muted)] uppercase tracking-wider">
              Active Tunnels
            </span>
            <div className="text-[20px] font-bold text-[var(--text-primary)] font-mono mt-1">
              {activeCount} Connected
            </div>
            <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">Real-time persistent FRP links</p>
          </div>
          <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <Network size={22} />
          </div>
        </div>

        <div className="card p-4 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[12px] font-mono text-[var(--text-muted)] uppercase tracking-wider">
              WAF Protection
            </span>
            <div className="text-[16px] font-bold text-emerald-400 font-mono mt-1">
              ModSec CRS 4.0 Active
            </div>
            <p className="text-[11.5px] text-[var(--text-secondary)] mt-0.5">Zero IP exposure to internet</p>
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
                1-Click Private Tunnel Agent Generator
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                Generate an instant automated installer command for your private app, Docker container, or local machine.
              </p>
            </div>
          </div>
          <span className="px-2.5 py-1 rounded-full text-[11px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-semibold flex items-center gap-1.5">
            <Zap size={13} className="text-amber-400" /> 1-Step Setup
          </span>
        </div>

        {/* Input Parameters Form */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2">
          <div>
            <label className="block text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-1">
              Public Target Domain
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="juice.waf-it-kku.online"
              className="w-full px-3 py-2 bg-[var(--bg-surface)] border border-[var(--bg-border)] rounded-lg text-[13px] font-mono text-[var(--text-primary)] focus:outline-none focus:border-indigo-500"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-1">
              Local Port
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
            <label className="block text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)] mb-1">
              Local IP Address
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
            <Laptop size={14} /> Linux Service (1-Liner)
          </button>
          <button
            onClick={() => setActiveTab('docker')}
            className={`px-3 py-1.5 rounded-lg text-[12px] font-mono font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'docker'
                ? 'bg-indigo-500 text-white shadow-md'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
            }`}
          >
            <Box size={14} /> Docker Container
          </button>
          <button
            onClick={() => setActiveTab('toml')}
            className={`px-3 py-1.5 rounded-lg text-[12px] font-mono font-medium flex items-center gap-1.5 transition-all ${
              activeTab === 'toml'
                ? 'bg-indigo-500 text-white shadow-md'
                : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
            }`}
          >
            <FileCode size={14} /> Raw frpc.toml
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

          {activeTab === 'toml' && (
            <pre className="p-4 rounded-xl bg-black/80 border border-indigo-500/30 text-amber-300 font-mono text-[12px] leading-relaxed overflow-x-auto select-all m-0">
              {rawToml}
            </pre>
          )}

          {/* Copy Button */}
          <button
            onClick={() =>
              handleCopy(
                activeTab === 'linux' ? linuxCmd : activeTab === 'docker' ? dockerCmd : rawToml,
                activeTab
              )
            }
            className="absolute top-3 right-3 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-[11.5px] font-semibold flex items-center gap-1.5 transition-all shadow-lg cursor-pointer"
          >
            {copiedKey === activeTab ? <Check size={13} /> : <Copy size={13} />}
            {copiedKey === activeTab ? 'COPIED!' : 'COPY COMMAND'}
          </button>
        </div>

        <div className="mt-3 flex items-center gap-2 text-[11.5px] text-[var(--text-muted)]">
          <Sparkles size={13} className="text-amber-400" />
          <span>
            Paste this single command in your private server terminal. It automatically downloads the agent and establishes a permanent 24/7 background connection.
          </span>
        </div>
      </div>

      {/* Live Active Tunnels Table */}
      <div className="card p-5 border border-[var(--bg-border)] bg-[var(--bg-surface)] rounded-2xl shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity size={18} className="text-indigo-400" />
            <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono uppercase tracking-wider m-0">
              Live Connected Tunnel Proxies ({tunnels.length})
            </h3>
          </div>
          <button
            onClick={() => {
              refetch()
              toast.success('Refreshed tunnel connections')
            }}
            className="p-1.5 rounded-lg bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] border border-[var(--bg-border)] transition-colors cursor-pointer"
            title="Refresh Tunnels"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-[12.5px]">
            <thead>
              <tr className="border-b border-[var(--bg-border)] text-[var(--text-muted)] text-[11px] uppercase tracking-wider">
                <th className="py-2.5 px-3">Tunnel Proxy</th>
                <th className="py-2.5 px-3">Public Protected Domain</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Local Port</th>
                <th className="py-2.5 px-3">Live Connections</th>
                <th className="py-2.5 px-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--bg-border-subtle)]">
              {tunnels.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[var(--text-muted)]">
                    No active tunnel proxies currently connected. Run the installer script on your private machine to establish a connection.
                  </td>
                </tr>
              ) : (
                tunnels.map((t: any, idx: number) => {
                  const domainName = t.custom_domains?.[0] || t.domain || t.name
                  return (
                    <tr key={idx} className="hover:bg-[var(--bg-hover)] transition-colors">
                      <td className="py-3 px-3 font-bold text-[var(--text-primary)] flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                        {t.name}
                      </td>
                      <td className="py-3 px-3 text-indigo-400 hover:text-indigo-300">
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
                      <td className="py-3 px-3 text-[var(--text-secondary)] uppercase">{t.type}</td>
                      <td className="py-3 px-3 text-amber-300">{t.local_port || 'Local App'}</td>
                      <td className="py-3 px-3 text-[var(--text-secondary)]">{t.connections || 0} conns</td>
                      <td className="py-3 px-3 text-right">
                        <span className="px-2 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          🟢 ONLINE
                        </span>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Tunnels
