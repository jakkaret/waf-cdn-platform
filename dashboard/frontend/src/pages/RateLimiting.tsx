import React, { useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rateLimitsApi, RateRule } from '../api/rateLimits'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'
import { LanguageToggle } from '../components/ui/LanguageToggle'
import {
  Gauge,
  Plus,
  Trash2,
  RefreshCw,
  Zap,
  Activity,
  AlertCircle,
  X,
  RotateCcw,
  CheckCircle2,
  Layers,
} from 'lucide-react'
import { useT } from '../i18n'

export const RateLimiting: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()
  const { t } = useT()

  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<RateRule | null>(null)

  // Form State
  const [formData, setFormData] = useState({
    name: '',
    path_pattern: '',
    method: 'ALL',
    limit_count: 60,
    window_seconds: 60,
    burst: 10,
    action: '429',
  })

  // Fetch Rules
  const { data: rules = [], isLoading: isLoadingRules, refetch: refetchRules } = useQuery({
    queryKey: ['rate-limit-rules'],
    queryFn: rateLimitsApi.getRules,
  })

  // Fetch Live Throttled Clients
  const { data: throttledView, isLoading: isLoadingThrottled, refetch: refetchThrottled, isFetching: isFetchingThrottled } = useQuery({
    queryKey: ['throttled-clients'],
    queryFn: rateLimitsApi.getThrottledClients,
    refetchInterval: 5000, // Poll every 5s for live sliding window updates
  })
  const throttledClients = throttledView?.throttled_clients ?? []
  const hiddenSiteClients = throttledView?.hidden_site_clients ?? 0

  // Create Rule Mutation
  const createMutation = useMutation({
    mutationFn: rateLimitsApi.createRule,
    onSuccess: () => {
      toast.success(t('Rate limit rule applied', 'ใช้กฎ rate limit แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['rate-limit-rules'] })
      setIsAddModalOpen(false)
      resetForm()
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Failed to create the rate limit rule', 'สร้างกฎ rate limit ไม่สำเร็จ'))
    },
  })

  // Update Rule Mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<RateRule> }) =>
      rateLimitsApi.updateRule(id, data),
    onSuccess: () => {
      toast.success(t('Rate limit rule updated', 'อัปเดตกฎ rate limit แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['rate-limit-rules'] })
      setEditingRule(null)
      setIsAddModalOpen(false)
      resetForm()
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Failed to update the rate limit rule', 'อัปเดตกฎ rate limit ไม่สำเร็จ'))
    },
  })

  // Delete Rule Mutation
  const deleteMutation = useMutation({
    mutationFn: rateLimitsApi.deleteRule,
    onSuccess: () => {
      toast.success(t('Rate limit rule removed', 'ลบกฎ rate limit แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['rate-limit-rules'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Failed to remove the rate limit rule', 'ลบกฎ rate limit ไม่สำเร็จ'))
    },
  })

  // Reset Client Mutation
  const resetClientMutation = useMutation({
    mutationFn: rateLimitsApi.resetClient,
    onSuccess: (res) => {
      toast.success(res.message || t('Client counter cleared', 'ล้างตัวนับของ IP นี้แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['throttled-clients'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Failed to reset the client counter', 'รีเซ็ตตัวนับของ IP นี้ไม่สำเร็จ'))
    },
  })

  const resetForm = () => {
    setFormData({
      name: '',
      path_pattern: '',
      method: 'ALL',
      limit_count: 60,
      window_seconds: 60,
      burst: 10,
      action: '429',
    })
  }

  const handleOpenEdit = (rule: RateRule) => {
    setEditingRule(rule)
    setFormData({
      name: rule.name,
      path_pattern: rule.path_pattern,
      method: rule.method,
      limit_count: rule.limit_count,
      window_seconds: rule.window_seconds,
      burst: rule.burst,
      action: rule.action,
    })
    setIsAddModalOpen(true)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (editingRule) {
      updateMutation.mutate({
        id: editingRule.id,
        data: formData,
      })
    } else {
      createMutation.mutate(formData)
    }
  }

  const handleToggleEnable = (rule: RateRule) => {
    updateMutation.mutate({
      id: rule.id,
      data: { enabled: rule.enabled ? 0 : 1 },
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-bold tracking-tight text-[var(--text-primary)] font-mono">
            {t('Platform rate limits', 'Rate limit ของแพลตฟอร์ม')}
          </h1>
          <p className="text-[12.5px] text-[var(--text-muted)] mt-0.5">
            {t('Protect endpoints from L7 floods, brute-force attempts and abusive crawlers.', 'ป้องกัน endpoint จากการยิงปริมาณมากระดับ L7, brute-force และ crawler ที่ไม่เหมาะสม')}
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              refetchRules()
              refetchThrottled()
            }}
            className="px-3 py-1.5 rounded-md bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] border border-[var(--bg-border)] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <RefreshCw size={13} className={isFetchingThrottled ? 'animate-spin' : ''} />
            <span>{t('Refresh', 'รีเฟรช')}</span>
          </button>
          {isAdmin && (
            <button
              onClick={() => {
                setEditingRule(null)
                resetForm()
                setIsAddModalOpen(true)
              }}
              className="px-3 py-1.5 rounded-md bg-orange-500 hover:bg-orange-600 text-white text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
            >
              <Plus size={14} />
              <span>{t('New rate rule', 'กฎ rate ใหม่')}</span>
            </button>
          )}
          <LanguageToggle />
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Rules', 'กฎ')}</span>
            <Gauge size={16} className="text-orange-500" />
          </div>
          <div className="text-[22px] font-bold font-mono text-[var(--text-primary)]">
            {rules.length}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {t(
              `${rules.filter((r) => r.enabled).length} enabled • ${rules.filter((r) => !r.enabled).length} disabled`,
              `เปิด ${rules.filter((r) => r.enabled).length} • ปิด ${rules.filter((r) => !r.enabled).length}`,
            )}
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Throttled clients', 'IP ที่ถูกจำกัด')}</span>
            <Zap size={16} className="text-amber-500" />
          </div>
          <div className="text-[22px] font-bold font-mono text-amber-500">
            {throttledClients.length}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {hiddenSiteClients > 0
              ? t(`+${hiddenSiteClients} on sites without a support grant`, `+${hiddenSiteClients} บนเว็บที่ไม่ได้ให้สิทธิ์ support`)
              : t('Active in the Redis sliding window', 'อยู่ใน sliding window ของ Redis')}
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Mechanism', 'กลไก')}</span>
            <Layers size={16} className="text-blue-400" />
          </div>
          <div className="text-[16px] font-bold font-mono text-[var(--text-primary)] mt-1">
            Redis sliding window
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {t('Millisecond-precision TTL', 'TTL ละเอียดระดับมิลลิวินาที')}
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Edge enforcement', 'การบังคับใช้ที่ edge')}</span>
            <Activity size={16} className="text-emerald-500 animate-pulse" />
          </div>
          <div className="text-[22px] font-bold font-mono text-emerald-500">
            {t('Active', 'ทำงานอยู่')}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            Nginx limit_req_zone & Redis
          </div>
        </div>
      </div>

      {/* Configured Rate Rules Table */}
      <div className="dash-card overflow-hidden">
        <div className="dash-card-header">
          <h3 className="font-mono text-[13.5px]">
            <Gauge size={16} className="text-orange-500" />
            <span>{t('Rate limit rules', 'กฎ rate limit')}</span>
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>{t('Name', 'ชื่อ')}</th>
                <th>{t('Path pattern', 'รูปแบบ path')}</th>
                <th>HTTP method</th>
                <th>Limit</th>
                <th>Burst</th>
                <th>{t('Action', 'การดำเนินการ')}</th>
                <th>{t('Status', 'สถานะ')}</th>
                {isAdmin && <th className="text-right">{t('Actions', 'จัดการ')}</th>}
              </tr>
            </thead>
            <tbody>
              {isLoadingRules ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-[var(--text-muted)]">
                    {t('Loading rate limit rules...', 'กำลังโหลดกฎ rate limit...')}
                  </td>
                </tr>
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-[var(--text-muted)]">
                    {t('No rate limit rules yet.', 'ยังไม่มีกฎ rate limit')}
                  </td>
                </tr>
              ) : (
                rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="font-medium text-[13px] text-[var(--text-primary)]">
                      {rule.name}
                    </td>
                    <td className="font-mono text-[12px] text-orange-400">
                      {rule.path_pattern}
                    </td>
                    <td>
                      <span className="mono-chip font-bold">
                        {rule.method}
                      </span>
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-secondary)]">
                      <span className="font-bold text-[var(--text-primary)]">{rule.limit_count}</span> {t('reqs', 'ครั้ง')} / {rule.window_seconds}s
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-muted)]">
                      +{rule.burst} {t('reqs', 'ครั้ง')}
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        {rule.action === '429' ? '429 Too Many Requests' : t('Temporary ban', 'แบนชั่วคราว')}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        onClick={() => handleToggleEnable(rule)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium cursor-pointer transition-colors ${
                          rule.enabled
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-[var(--bg-hover)] text-[var(--text-muted)] border border-[var(--bg-border)]'
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? 'bg-emerald-500' : 'bg-[var(--text-muted)]'}`} />
                        <span>{rule.enabled ? t('ACTIVE', 'ใช้งานอยู่') : t('PAUSED', 'หยุดชั่วคราว')}</span>
                      </button>
                    </td>
                    {isAdmin && (
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => handleOpenEdit(rule)}
                            className="px-2 py-1 text-[11.5px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] rounded transition-colors cursor-pointer"
                          >
                            {t('Edit', 'แก้ไข')}
                          </button>
                          <button
                            onClick={() => {
                              if (confirm(t(`Delete rate limit rule "${rule.name}"?`, `ลบกฎ rate limit "${rule.name}"?`))) {
                                deleteMutation.mutate(rule.id)
                              }
                            }}
                            className="p-1 text-[var(--text-muted)] hover:text-red-400 hover:bg-red-500/10 rounded transition-colors cursor-pointer"
                            title={t('Delete rule', 'ลบกฎ')}
                            aria-label={t('Delete rule', 'ลบกฎ')}
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Live Throttled Stream Table */}
      <div className="dash-card overflow-hidden">
        <div className="dash-card-header">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
            <h3 className="font-mono text-[13.5px] m-0">{t('Throttled clients right now', 'IP ที่ถูกจำกัดอยู่ตอนนี้')}</h3>
          </div>
          <span className="text-[11.5px] font-mono text-[var(--text-muted)]">
            {t('Refreshes every 5 s', 'รีเฟรชทุก 5 วินาที')}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>{t('Client IP', 'IP ผู้ใช้')}</th>
                <th>Host</th>
                <th>{t('Current count', 'จำนวนปัจจุบัน')}</th>
                <th>{t('Lock time left', 'เวลาล็อกที่เหลือ')}</th>
                <th>{t('Status', 'สถานะ')}</th>
                {isAdmin && <th className="text-right">{t('Action', 'การดำเนินการ')}</th>}
              </tr>
            </thead>
            <tbody>
              {isLoadingThrottled ? (
                <tr>
                  <td colSpan={6} className="text-center py-6 text-[var(--text-muted)]">
                    {t('Reading the Redis counters...', 'กำลังอ่านตัวนับใน Redis...')}
                  </td>
                </tr>
              ) : throttledClients.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-[var(--text-muted)]">
                    <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-500/60" />
                    <span className="text-[12.5px]">{t('No throttled clients right now. Traffic is healthy.', 'ตอนนี้ไม่มี IP ที่ถูกจำกัด ทราฟฟิกปกติ')}</span>
                  </td>
                </tr>
              ) : (
                throttledClients.map((client) => (
                  <tr key={`${client.rule_id}|${client.host}|${client.ip}`}>
                    <td className="font-mono font-bold text-[12.5px] text-[var(--text-primary)]">
                      {client.ip}
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-secondary)]">{client.host}</td>
                    <td className="font-mono text-[12.5px] text-amber-400 font-bold">
                      {client.request_count} {t('requests', 'ครั้ง')}
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-muted)]">
                      {client.ttl_seconds > 0 ? t(`${client.ttl_seconds} seconds`, `${client.ttl_seconds} วินาที`) : t('Expiring', 'กำลังหมดอายุ')}
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        {t('THROTTLED', 'ถูกจำกัด')}
                      </span>
                    </td>
                    {isAdmin && (
                      <td className="text-right">
                        <button
                          onClick={() => resetClientMutation.mutate(client.ip)}
                          disabled={resetClientMutation.isPending}
                          className="px-2.5 py-1 rounded bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--bg-border)] text-[11.5px] font-medium inline-flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <RotateCcw size={11} />
                          <span>{t('Release', 'ปลดล็อก')}</span>
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Policy Modal */}
      {isAddModalOpen && typeof document !== 'undefined' && createPortal(
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setIsAddModalOpen(false)
          }}
        >
          <div
            className="dash-modal w-full max-w-md p-6 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between pb-4 border-b border-[var(--bg-border)] mb-4">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded bg-orange-500/10 text-orange-500 flex items-center justify-center">
                  <Gauge size={16} />
                </div>
                <h3 className="text-[15px] font-bold font-mono text-[var(--text-primary)] m-0">
                  {editingRule ? t('Edit rate rule', 'แก้ไขกฎ rate') : t('Create rate limit rule', 'สร้างกฎ rate limit')}
                </h3>
              </div>
              <button
                onClick={() => setIsAddModalOpen(false)}
                aria-label={t('Close', 'ปิด')}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4 text-[13px]">
              <div>
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                  {t('Name', 'ชื่อ')}
                </label>
                <input
                  type="text"
                  required
                  placeholder={t('e.g. Login brute-force protection', 'เช่น กัน brute-force หน้าล็อกอิน')}
                  className="w-full dash-input text-[12.5px]"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    {t('Path pattern', 'รูปแบบ path')}
                  </label>
                  <input
                    type="text"
                    required
                    placeholder={t('e.g. /api/auth/* or *', 'เช่น /api/auth/* หรือ *')}
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.path_pattern}
                    onChange={(e) => setFormData({ ...formData, path_pattern: e.target.value })}
                  />
                </div>
                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    Method
                  </label>
                  <select
                    className="w-full dash-input text-[12.5px]"
                    value={formData.method}
                    onChange={(e) => setFormData({ ...formData, method: e.target.value })}
                  >
                    <option value="ALL">ALL</option>
                    <option value="POST">POST</option>
                    <option value="GET">GET</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    {t('Max requests', 'จำนวน request สูงสุด')}
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.limit_count}
                    onChange={(e) => setFormData({ ...formData, limit_count: parseInt(e.target.value, 10) || 1 })}
                  />
                </div>

                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    {t('Window (sec)', 'ช่วงเวลา (วินาที)')}
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.window_seconds}
                    onChange={(e) => setFormData({ ...formData, window_seconds: parseInt(e.target.value, 10) || 1 })}
                  />
                </div>

                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    Burst
                  </label>
                  <input
                    type="number"
                    min="0"
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.burst}
                    onChange={(e) => setFormData({ ...formData, burst: parseInt(e.target.value, 10) || 0 })}
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                  {t('Action when the limit is exceeded', 'เมื่อเกิน limit ให้')}
                </label>
                <select
                  className="w-full dash-input text-[12.5px]"
                  value={formData.action}
                  onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                >
                  <option value="429">{t('HTTP 429 Too Many Requests (standard)', 'ตอบ HTTP 429 Too Many Requests (มาตรฐาน)')}</option>
                  <option value="temp_ban">{t('Temporary IP ban / drop', 'แบน IP ชั่วคราว / ตัดการเชื่อมต่อ')}</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[var(--bg-border)]">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-3.5 py-1.5 rounded-md bg-[var(--bg-primary)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] text-[12px] font-medium transition-colors cursor-pointer"
                >
                  {t('Cancel', 'ยกเลิก')}
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                  className="px-4 py-1.5 rounded-md bg-orange-500 hover:bg-orange-600 text-white text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
                >
                  {createMutation.isPending || updateMutation.isPending
                    ? t('Saving...', 'กำลังบันทึก...')
                    : editingRule
                      ? t('Save changes', 'บันทึกการเปลี่ยนแปลง')
                      : t('Apply rule', 'ใช้กฎ')}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}

export default RateLimiting
