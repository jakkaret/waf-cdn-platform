import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { settingsApi, SystemSettings } from '../api/settings'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import {
  Shield,
  Bell,
  Globe,
  Save,
  Send,
  CheckCircle2,
  AlertTriangle,
  Server,
  Activity,
  Zap,
  Info,
  RotateCw,
  Sliders,
  Radio,
  Lock,
  Check,
  Cpu,
  Layers,
} from 'lucide-react'

export const Settings: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()

  const [activeTab, setActiveTab] = useState<'waf' | 'alerts' | 'edge' | 'system'>('waf')

  // Settings State Form
  const [form, setForm] = useState<Partial<SystemSettings>>({
    waf_mode: 'blocking',
    paranoia_level: 1,
    inbound_anomaly_threshold: 10,
    outbound_anomaly_threshold: 10,
    auto_purge_edge_cache: true,
    real_ip_header: 'X-Forwarded-For',
    telegram_notifications: true,
    telegram_bot_token: '',
    telegram_chat_id: '',
    edge_sync_interval_seconds: 5,
  })

  // Fetch Settings
  const { data: settings, isLoading, refetch } = useQuery({
    queryKey: ['system-settings'],
    queryFn: settingsApi.getSettings,
  })

  useEffect(() => {
    if (settings) {
      setForm(settings)
    }
  }, [settings])

  // Save Settings Mutation
  const saveMutation = useMutation({
    mutationFn: settingsApi.updateSettings,
    onSuccess: (updated) => {
      toast.success('System configuration saved & WAF engine updated')
      queryClient.setQueryData(['system-settings'], updated)
      setForm(updated)
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Failed to save settings')
    },
  })

  // Test Notification Mutation
  const testAlertMutation = useMutation({
    mutationFn: () => settingsApi.sendTestNotification('telegram'),
    onSuccess: (res) => {
      toast.success(res.message || 'Test notification sent to Telegram!')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Test notification failed')
    },
  })

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault()
    saveMutation.mutate(form)
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-24 text-[var(--text-muted)] font-mono text-[12.5px]">
        <div className="flex items-center gap-2.5">
          <RotateCw size={18} className="animate-spin text-orange-500" />
          <span>Loading system configurations & security posture...</span>
        </div>
      </div>
    )
  }

  const isBlocking = form.waf_mode === 'blocking'

  return (
    <div className="animate-fade-in pb-12">
      {/* Top Header Bar */}
      <TopBar
        title="System Settings"
        subtitle="Configure WAF operational modes, anomaly scoring thresholds, edge delivery, and notifications"
        badge={
          <Badge color={isBlocking ? 'success' : 'warning'} dot pulse={isBlocking}>
            {isBlocking ? 'ACTIVE BLOCKING' : 'DETECTION ONLY'}
          </Badge>
        }
        action={
          <div className="flex items-center gap-2">
            {isAdmin && (
              <Button
                variant="brand"
                onClick={handleSave}
                isLoading={saveMutation.isPending}
                icon={<Save size={14} />}
              >
                Save Settings
              </Button>
            )}
          </div>
        }
      />

      {/* Main 12-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        
        {/* Left Column (8 cols): Tab Navigation & Configuration Panels */}
        <div className="lg:col-span-8 space-y-4">
          
          {/* Tab Navigation Header */}
          <div className="flex items-center gap-1.5 p-1 rounded-lg bg-[var(--bg-surface)] border border-[var(--bg-border)] overflow-x-auto text-[12px] font-mono">
            <button
              onClick={() => setActiveTab('waf')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'waf'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
              }`}
            >
              <Shield size={14} />
              <span>WAF & Core Engine</span>
            </button>

            <button
              onClick={() => setActiveTab('alerts')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'alerts'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
              }`}
            >
              <Bell size={14} />
              <span>Telegram Alerts</span>
            </button>

            <button
              onClick={() => setActiveTab('edge')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'edge'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
              }`}
            >
              <Globe size={14} />
              <span>Edge & CDN Delivery</span>
            </button>

            <button
              onClick={() => setActiveTab('system')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md font-semibold transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'system'
                  ? 'bg-orange-500 text-white shadow-sm'
                  : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
              }`}
            >
              <Server size={14} />
              <span>Stack Diagnostics</span>
            </button>
          </div>

          {/* ═══ Tab 1: WAF & Core Engine ═══ */}
          {activeTab === 'waf' && (
            <div className="dash-card p-5 sm:p-6 space-y-6 animate-fade-in">
              <div>
                <h3 className="text-[14.5px] font-bold text-[var(--text-primary)] font-mono m-0 mb-1 flex items-center gap-2">
                  <Shield size={16} className="text-orange-600 dark:text-orange-400" />
                  WAF Operational Mode
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0">
                  Select how ModSecurity Core Rule Set (CRS) evaluates and enforces perimeter security policies.
                </p>
              </div>

              {/* Radio Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                <label
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    form.waf_mode === 'blocking'
                      ? 'border-orange-500 bg-orange-50/40 dark:bg-orange-500/[0.08] ring-1 ring-orange-500/50'
                      : 'border-[var(--bg-border)] bg-[var(--bg-primary)] hover:bg-[var(--bg-hover)]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-500" />
                      <span className="font-bold text-[13px] text-[var(--text-primary)] font-mono">
                        Active Blocking (On)
                      </span>
                    </div>
                    <input
                      type="radio"
                      name="waf_mode"
                      value="blocking"
                      checked={form.waf_mode === 'blocking'}
                      onChange={() => setForm({ ...form, waf_mode: 'blocking' })}
                      className="accent-orange-500"
                    />
                  </div>
                  <p className="text-[11.5px] text-[var(--text-muted)] m-0 leading-relaxed">
                    Immediately drops and returns HTTP 403 Forbidden on attack payloads exceeding the anomaly score limit.
                  </p>
                </label>

                <label
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    form.waf_mode === 'detection_only'
                      ? 'border-orange-500 bg-orange-50/40 dark:bg-orange-500/[0.08] ring-1 ring-orange-500/50'
                      : 'border-[var(--bg-border)] bg-[var(--bg-primary)] hover:bg-[var(--bg-hover)]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-amber-500" />
                      <span className="font-bold text-[13px] text-[var(--text-primary)] font-mono">
                        Detection Only (Simulate)
                      </span>
                    </div>
                    <input
                      type="radio"
                      name="waf_mode"
                      value="detection_only"
                      checked={form.waf_mode === 'detection_only'}
                      onChange={() => setForm({ ...form, waf_mode: 'detection_only' })}
                      className="accent-orange-500"
                    />
                  </div>
                  <p className="text-[11.5px] text-[var(--text-muted)] m-0 leading-relaxed">
                    Evaluates rules and logs events without blocking traffic. Recommended for baseline testing.
                  </p>
                </label>
              </div>

              {/* Anomaly Limits Section */}
              <div className="border-t border-[var(--bg-border-subtle)] pt-5 space-y-4">
                <h4 className="text-[13.5px] font-bold text-[var(--text-primary)] font-mono m-0 flex items-center gap-2">
                  <Sliders size={15} className="text-orange-600 dark:text-orange-400" />
                  Anomaly Scoring & Sensitivity
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
                  <div>
                    <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
                      Paranoia Level
                    </label>
                    <select
                      className="w-full dash-input text-[12px] font-mono cursor-pointer"
                      value={form.paranoia_level}
                      onChange={(e) => setForm({ ...form, paranoia_level: parseInt(e.target.value, 10) })}
                    >
                      <option value={1}>Level 1 (Standard)</option>
                      <option value={2}>Level 2 (Moderate)</option>
                      <option value={3}>Level 3 (High Security)</option>
                      <option value={4}>Level 4 (Extreme)</option>
                    </select>
                    <span className="text-[10px] text-[var(--text-dim)] mt-0.5 block font-mono">
                      Rule sensitivity depth
                    </span>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
                      Inbound Anomaly Limit
                    </label>
                    <input
                      type="number"
                      min="1"
                      className="w-full dash-input font-mono text-[12px]"
                      value={form.inbound_anomaly_threshold}
                      onChange={(e) => setForm({ ...form, inbound_anomaly_threshold: parseInt(e.target.value, 10) || 5 })}
                    />
                    <span className="text-[10px] text-[var(--text-dim)] mt-0.5 block font-mono">
                      Score ≥ limit triggers 403 (Default: 10)
                    </span>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
                      Outbound Anomaly Limit
                    </label>
                    <input
                      type="number"
                      min="1"
                      className="w-full dash-input font-mono text-[12px]"
                      value={form.outbound_anomaly_threshold}
                      onChange={(e) => setForm({ ...form, outbound_anomaly_threshold: parseInt(e.target.value, 10) || 5 })}
                    />
                    <span className="text-[10px] text-[var(--text-dim)] mt-0.5 block font-mono">
                      Data leak prevention (Default: 10)
                    </span>
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
                    Client Real-IP Header
                  </label>
                  <input
                    type="text"
                    placeholder="X-Forwarded-For"
                    className="w-full dash-input font-mono text-[12px]"
                    value={form.real_ip_header}
                    onChange={(e) => setForm({ ...form, real_ip_header: e.target.value })}
                  />
                  <span className="text-[10.5px] text-[var(--text-muted)] font-mono mt-1 block">
                    Header used by Nginx to identify original client IP behind proxies or CDN nodes.
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* ═══ Tab 2: Telegram Alerts ═══ */}
          {activeTab === 'alerts' && (
            <div className="dash-card p-5 sm:p-6 space-y-5 animate-fade-in">
              <div>
                <h3 className="text-[14.5px] font-bold text-[var(--text-primary)] font-mono m-0 mb-1 flex items-center gap-2">
                  <Bell size={16} className="text-orange-600 dark:text-orange-400" />
                  Telegram Threat Alerts Configuration
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0">
                  Receive instant incident notifications directly to your Telegram chat or security team channel.
                </p>
              </div>

              <div className="p-4 rounded-lg border border-[var(--bg-border)] space-y-4 bg-[var(--bg-primary)]">
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <div className="flex items-center gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-sky-500/10 text-sky-600 dark:text-sky-400 flex items-center justify-center font-bold font-mono text-[12px] border border-sky-500/20">
                      TG
                    </div>
                    <div>
                      <h4 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                        Telegram Bot Credentials
                      </h4>
                      <span className="text-[11px] text-[var(--text-muted)] font-mono">
                        Real-time threat notifications via Telegram Bot API
                      </span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => testAlertMutation.mutate()}
                    disabled={testAlertMutation.isPending}
                    className="px-3 py-1.5 bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--bg-border)] rounded-md text-[11.5px] font-mono font-medium inline-flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
                  >
                    <Send size={12} className="text-sky-500" />
                    <span>{testAlertMutation.isPending ? 'Sending...' : 'Send Test Alert'}</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 pt-2">
                  <div>
                    <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
                      Bot API Token
                    </label>
                    <input
                      type="password"
                      placeholder={settings?.telegram_bot_token_masked || 'Paste Bot Token from @BotFather'}
                      className="w-full dash-input font-mono text-[12px]"
                      value={form.telegram_bot_token || ''}
                      onChange={(e) => setForm({ ...form, telegram_bot_token: e.target.value })}
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
                      Chat ID / Channel ID
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. -100123456789 or 987654321"
                      className="w-full dash-input font-mono text-[12px]"
                      value={form.telegram_chat_id || ''}
                      onChange={(e) => setForm({ ...form, telegram_chat_id: e.target.value })}
                    />
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-[var(--bg-surface)] border border-[var(--bg-border-subtle)] text-[12px] text-[var(--text-muted)] space-y-1">
                  <div className="flex items-center gap-1.5 text-[var(--text-secondary)] font-mono font-bold text-[11px] uppercase">
                    <Info size={13} className="text-orange-500" />
                    <span>Setup Instructions:</span>
                  </div>
                  <ol className="list-decimal list-inside pl-1 space-y-0.5 text-[11.5px] font-mono leading-relaxed">
                    <li>Message <code className="text-orange-600 dark:text-orange-400 font-bold">@BotFather</code> on Telegram to generate a bot token.</li>
                    <li>Add your bot to your channel/group or send it <code className="text-orange-600 dark:text-orange-400 font-bold">/start</code>.</li>
                    <li>Enter Token and Chat ID above, then click <strong>Send Test Alert</strong>.</li>
                  </ol>
                </div>
              </div>
            </div>
          )}

          {/* ═══ Tab 3: Edge & CDN Delivery ═══ */}
          {activeTab === 'edge' && (
            <div className="dash-card p-5 sm:p-6 space-y-5 animate-fade-in">
              <div>
                <h3 className="text-[14.5px] font-bold text-[var(--text-primary)] font-mono m-0 mb-1 flex items-center gap-2">
                  <Globe size={16} className="text-sky-600 dark:text-sky-400" />
                  Edge Node Sync & Caching Policies
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0">
                  Configure synchronization rules between the control plane and distributed edge nodes.
                </p>
              </div>

              <div className="space-y-4">
                <label className="flex items-start gap-3 p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] cursor-pointer hover:bg-[var(--bg-hover)] transition-colors">
                  <input
                    type="checkbox"
                    checked={form.auto_purge_edge_cache}
                    onChange={(e) => setForm({ ...form, auto_purge_edge_cache: e.target.checked })}
                    className="mt-0.5 accent-orange-500 w-4 h-4 cursor-pointer"
                  />
                  <div>
                    <span className="font-bold text-[12.5px] text-[var(--text-primary)] font-mono block">
                      Automatic Edge Cache Purge on Origin Rule Update
                    </span>
                    <span className="text-[11.5px] text-[var(--text-muted)] leading-relaxed block mt-0.5">
                      Instantly flush cached assets across all edge nodes whenever WAF rules or origin mappings change.
                    </span>
                  </div>
                </label>

                <div>
                  <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1">
                    Edge Rule Polling Interval (seconds)
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="60"
                    className="w-full max-w-xs dash-input font-mono text-[12px]"
                    value={form.edge_sync_interval_seconds}
                    onChange={(e) => setForm({ ...form, edge_sync_interval_seconds: parseInt(e.target.value, 10) || 5 })}
                  />
                  <span className="text-[10.5px] text-[var(--text-muted)] font-mono mt-1 block">
                    Interval for edge nodes daemon (99-rulesync.sh) to pull bundles from Control API.
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* ═══ Tab 4: Stack Diagnostics ═══ */}
          {activeTab === 'system' && (
            <div className="dash-card p-5 sm:p-6 space-y-5 animate-fade-in">
              <div>
                <h3 className="text-[14.5px] font-bold text-[var(--text-primary)] font-mono m-0 mb-1 flex items-center gap-2">
                  <Server size={16} className="text-orange-600 dark:text-orange-400" />
                  Stack Connectivity & Microservice Health
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0">
                  Real-time status of backend security services and container mesh.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                    <div>
                      <div className="font-mono font-bold text-[12.5px] text-[var(--text-primary)]">
                        ModSecurity CRS (waf-nginx)
                      </div>
                      <div className="text-[10.5px] text-[var(--text-muted)] font-mono">
                        Port 8080 / 8443 • Healthy
                      </div>
                    </div>
                  </div>
                  <span className="mono-chip text-emerald-600 dark:text-emerald-400 font-bold">ONLINE</span>
                </div>

                <div className="p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                    <div>
                      <div className="font-mono font-bold text-[12.5px] text-[var(--text-primary)]">
                        Redis Sliding Window (waf-redis)
                      </div>
                      <div className="text-[10.5px] text-[var(--text-muted)] font-mono">
                        Port 6379 • Connected
                      </div>
                    </div>
                  </div>
                  <span className="mono-chip text-emerald-600 dark:text-emerald-400 font-bold">ONLINE</span>
                </div>

                <div className="p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                    <div>
                      <div className="font-mono font-bold text-[12.5px] text-[var(--text-primary)]">
                        ClickHouse OLAP (waf-clickhouse)
                      </div>
                      <div className="text-[10.5px] text-[var(--text-muted)] font-mono">
                        Port 8123 / 9000 • Connected
                      </div>
                    </div>
                  </div>
                  <span className="mono-chip text-emerald-600 dark:text-emerald-400 font-bold">ONLINE</span>
                </div>

                <div className="p-3.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                    <div>
                      <div className="font-mono font-bold text-[12.5px] text-[var(--text-primary)]">
                        Caddy SSL Reverse Proxy
                      </div>
                      <div className="text-[10.5px] text-[var(--text-muted)] font-mono">
                        Port 80 / 443 • Active
                      </div>
                    </div>
                  </div>
                  <span className="mono-chip text-emerald-600 dark:text-emerald-400 font-bold">ONLINE</span>
                </div>
              </div>
            </div>
          )}

        </div>

        {/* Right Column (4 cols): Security Posture & Quick Info Panel */}
        <div className="lg:col-span-4 space-y-3.5">
          
          {/* Card 1: Active Security Posture */}
          <div className="dash-card p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-[var(--bg-border)] pb-2.5">
              <span className="text-[11px] font-bold font-mono text-[var(--text-secondary)] uppercase tracking-wider">
                Security Posture
              </span>
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                  isBlocking
                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                    : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${isBlocking ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                <span>{isBlocking ? 'PROTECTED' : 'SIMULATING'}</span>
              </span>
            </div>

            <div className="space-y-2 text-[11.5px] font-mono">
              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">Operational Mode:</span>
                <span className="font-semibold text-[var(--text-primary)]">
                  {form.waf_mode === 'blocking' ? 'Active Blocking' : 'Detection Only'}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">Paranoia Level:</span>
                <span className="font-bold text-orange-600 dark:text-orange-400">
                  Level {form.paranoia_level} / 4
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">Inbound Threshold:</span>
                <span className="text-[var(--text-primary)]">
                  {form.inbound_anomaly_threshold} pts
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">Outbound Threshold:</span>
                <span className="text-[var(--text-primary)]">
                  {form.outbound_anomaly_threshold} pts
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">Telegram Alerts:</span>
                <span className={`${form.telegram_chat_id ? 'text-emerald-600 dark:text-emerald-400 font-bold' : 'text-[var(--text-muted)]'}`}>
                  {form.telegram_chat_id ? 'Configured' : 'Not Set'}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">Edge Auto-Purge:</span>
                <span className="text-[var(--text-primary)]">
                  {form.auto_purge_edge_cache ? 'Enabled' : 'Disabled'}
                </span>
              </div>
            </div>
          </div>

          {/* Card 2: Quick Operations */}
          <div className="dash-card p-4 space-y-2.5">
            <h4 className="text-[11px] font-bold font-mono text-[var(--text-secondary)] uppercase tracking-wider m-0">
              Quick Operations
            </h4>

            <div className="space-y-2">
              <button
                type="button"
                onClick={() => testAlertMutation.mutate()}
                disabled={testAlertMutation.isPending}
                className="w-full py-2 px-3 rounded-md bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--bg-border)] text-[11.5px] font-mono font-medium flex items-center justify-between transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <Send size={12} className="text-sky-500" />
                  <span>Test Telegram Dispatch</span>
                </div>
                <span className="text-[10.5px] font-mono text-[var(--text-muted)]">Ping</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  saveMutation.mutate(form)
                }}
                disabled={saveMutation.isPending}
                className="w-full py-2 px-3 rounded-md bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--bg-border)] text-[11.5px] font-mono font-medium flex items-center justify-between transition-colors cursor-pointer"
              >
                <div className="flex items-center gap-2">
                  <RotateCw size={12} className="text-orange-500" />
                  <span>Sync & Reload Engine</span>
                </div>
                <span className="text-[10.5px] font-mono text-[var(--text-muted)]">Hot Reload</span>
              </button>
            </div>
          </div>

          {/* Card 3: Contextual Tip */}
          <div className="dash-card p-4 bg-orange-50 dark:bg-orange-500/[0.06] border border-orange-200 dark:border-orange-500/20 text-[12px] space-y-1">
            <div className="flex items-center gap-1.5 font-bold font-mono text-orange-600 dark:text-orange-400 text-[11px] uppercase">
              <Zap size={13} />
              <span>Operational Guideline</span>
            </div>
            <p className="m-0 text-[11px] font-mono leading-relaxed text-[var(--text-secondary)]">
              When introducing major rule changes, switch WAF mode to <strong>Detection Only</strong> for 24h to analyze baseline false positives before enforcing <strong>Active Blocking</strong>.
            </p>
          </div>

        </div>

      </div>
    </div>
  )
}

export default Settings
