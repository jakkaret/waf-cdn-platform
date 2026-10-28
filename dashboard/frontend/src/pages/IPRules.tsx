import React, { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ipRulesApi, IPRule } from '../api/ipRules'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'
import { LanguageToggle } from '../components/ui/LanguageToggle'
import {
  ShieldAlert,
  ShieldCheck,
  Clock,
  Plus,
  Trash2,
  Search,
  RefreshCw,
  Copy,
  Check,
  X,
  AlertTriangle,
  Radio,
} from 'lucide-react'
import { useT } from '../i18n'

export const IPRules: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()
  const { t } = useT()

  const [activeTab, setActiveTab] = useState<'all' | 'block' | 'allow' | 'temp'>('all')
  const [search, setSearch] = useState('')
  const [selectedIps, setSelectedIps] = useState<string[]>([])
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [copiedIp, setCopiedIp] = useState<string | null>(null)

  // Form state
  const [newIp, setNewIp] = useState('')
  const [newType, setNewType] = useState<'block' | 'allow'>('block')
  const [newReason, setNewReason] = useState('')
  const [newDuration, setNewDuration] = useState<string>('0') // 0 = permanent

  // Fetch IP rules
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['ip-rules', activeTab === 'temp' ? 'block' : activeTab, search],
    queryFn: () => ipRulesApi.getRules(activeTab === 'temp' ? 'block' : activeTab, search),
    refetchInterval: 10000,
  })

  // Add rule mutation
  const addMutation = useMutation({
    mutationFn: ipRulesApi.addRule,
    onSuccess: () => {
      toast.success(t('IP rule applied and synced to the edge nodes', 'ใช้กฎ IP แล้วและซิงก์ไปยัง edge node แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] })
      setIsAddModalOpen(false)
      setNewIp('')
      setNewReason('')
      setNewDuration('0')
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Failed to add IP rule', 'เพิ่มกฎ IP ไม่สำเร็จ'))
    },
  })

  // Delete rule mutation
  const deleteMutation = useMutation({
    mutationFn: ipRulesApi.deleteRule,
    onSuccess: () => {
      toast.success(t('IP rule removed', 'ลบกฎ IP แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Failed to remove IP rule', 'ลบกฎ IP ไม่สำเร็จ'))
    },
  })

  // Bulk delete mutation
  const bulkDeleteMutation = useMutation({
    mutationFn: ipRulesApi.bulkDelete,
    onSuccess: (res) => {
      toast.success(t(`Removed ${res.deleted_count} IP rules`, `ลบกฎ IP แล้ว ${res.deleted_count} รายการ`))
      setSelectedIps([])
      queryClient.invalidateQueries({ queryKey: ['ip-rules'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Bulk action failed', 'ดำเนินการหลายรายการไม่สำเร็จ'))
    },
  })

  const rules = (data?.rules || []).filter((r) => {
    if (activeTab === 'temp') {
      return r.expires_at !== null && r.remaining_seconds !== null && r.remaining_seconds > 0
    }
    return true
  })

  const stats = data?.stats || {
    total_blocked: 0,
    total_allowed: 0,
    temp_banned: 0,
    permanent_blocked: 0,
  }

  const handleCopy = (ip: string) => {
    navigator.clipboard.writeText(ip)
    setCopiedIp(ip)
    setTimeout(() => setCopiedIp(null), 2000)
  }

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedIps(rules.map((r) => r.ip))
    } else {
      setSelectedIps([])
    }
  }

  const handleSelectOne = (ip: string) => {
    setSelectedIps((prev) =>
      prev.includes(ip) ? prev.filter((item) => item !== ip) : [...prev, ip]
    )
  }

  const handleAddSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const durationSeconds = parseInt(newDuration, 10)
    addMutation.mutate({
      ip: newIp.trim(),
      rule_type: newType,
      reason: newReason.trim() || 'Manual entry',
      duration_seconds: durationSeconds > 0 ? durationSeconds : null,
      source: 'manual',
    })
  }

  const formatRemaining = (seconds: number | null) => {
    if (seconds === null) return t('Permanent', 'ถาวร')
    if (seconds <= 0) return t('Expired', 'หมดอายุแล้ว')
    if (seconds < 60) return `${seconds}s`
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
    const hours = Math.floor(seconds / 3600)
    const mins = Math.floor((seconds % 3600) / 60)
    return `${hours}h ${mins}m`
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-bold tracking-tight text-[var(--text-primary)] font-mono">
            {t('Platform IP list', 'รายการ IP ของแพลตฟอร์ม')}
          </h1>
          <p className="text-[12.5px] text-[var(--text-muted)] mt-0.5">
            {t('Block lists, temporary bans and trusted allow lists for the whole platform, synced to the edge nodes.', 'รายการบล็อก การแบนชั่วคราว และรายการอนุญาตของทั้งแพลตฟอร์ม ซิงก์ไปยัง edge node')}
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="px-3 py-1.5 rounded-md bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] border border-[var(--bg-border)] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <RefreshCw size={13} className={isFetching ? 'animate-spin' : ''} />
            <span>{t('Refresh', 'รีเฟรช')}</span>
          </button>
          {isAdmin && (
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="px-3 py-1.5 rounded-md bg-orange-500 hover:bg-orange-600 text-white text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
            >
              <Plus size={14} />
              <span>{t('Add IP rule', 'เพิ่มกฎ IP')}</span>
            </button>
          )}
          <LanguageToggle />
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Total blocked', 'บล็อกทั้งหมด')}</span>
            <ShieldAlert size={16} className="text-red-500" />
          </div>
          <div className="text-[22px] font-bold font-mono text-[var(--text-primary)]">
            {stats.total_blocked}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {t(`${stats.permanent_blocked} permanent • ${stats.temp_banned} temporary`, `ถาวร ${stats.permanent_blocked} • ชั่วคราว ${stats.temp_banned}`)}
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Allow list', 'รายการอนุญาต')}</span>
            <ShieldCheck size={16} className="text-emerald-500" />
          </div>
          <div className="text-[22px] font-bold font-mono text-[var(--text-primary)]">
            {stats.total_allowed}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {t('Skip all WAF checks', 'ข้ามการตรวจของ WAF ทั้งหมด')}
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Temporary bans', 'แบนชั่วคราว')}</span>
            <Clock size={16} className="text-amber-500" />
          </div>
          <div className="text-[22px] font-bold font-mono text-[var(--text-primary)]">
            {stats.temp_banned}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {t('Block rules that expire by themselves', 'กฎบล็อกที่หมดอายุเอง')}
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium">{t('Edge sync', 'การซิงก์ไป edge')}</span>
            <Radio size={16} className="text-orange-500 animate-pulse" />
          </div>
          <div className="text-[22px] font-bold font-mono text-emerald-500">
            {t('Active', 'ทำงานอยู่')}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {t('ModSecurity and edge nodes synced', 'ซิงก์ ModSecurity และ edge node แล้ว')}
          </div>
        </div>
      </div>

      {/* Main Table Card */}
      <div className="dash-card overflow-hidden">
        {/* Controls Toolbar */}
        <div className="p-3.5 border-b border-[var(--bg-border)] flex flex-col md:flex-row md:items-center justify-between gap-3 bg-[var(--bg-surface)]">
          {/* Tabs */}
          <div className="flex items-center gap-1 bg-[var(--bg-primary)] p-1 rounded-lg border border-[var(--bg-border-subtle)] text-[12px]">
            <button
              onClick={() => setActiveTab('all')}
              className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                activeTab === 'all'
                  ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-sm'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              {t('All rules', 'กฎทั้งหมด')} ({stats.total_blocked + stats.total_allowed})
            </button>
            <button
              onClick={() => setActiveTab('block')}
              className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                activeTab === 'block'
                  ? 'bg-[var(--bg-surface)] text-red-500 shadow-sm'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              {t('Block list', 'รายการบล็อก')} ({stats.total_blocked})
            </button>
            <button
              onClick={() => setActiveTab('allow')}
              className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                activeTab === 'allow'
                  ? 'bg-[var(--bg-surface)] text-emerald-500 shadow-sm'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              {t('Allow list', 'รายการอนุญาต')} ({stats.total_allowed})
            </button>
            <button
              onClick={() => setActiveTab('temp')}
              className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                activeTab === 'temp'
                  ? 'bg-[var(--bg-surface)] text-amber-500 shadow-sm'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
              }`}
            >
              {t('Temporary bans', 'แบนชั่วคราว')} ({stats.temp_banned})
            </button>
          </div>

          {/* Search Box & Bulk Action */}
          <div className="flex items-center gap-2.5">
            {selectedIps.length > 0 && isAdmin && (
              <button
                onClick={() => bulkDeleteMutation.mutate(selectedIps)}
                disabled={bulkDeleteMutation.isPending}
                className="px-2.5 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-md text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <Trash2 size={13} />
                <span>{t('Remove selected', 'ลบที่เลือก')} ({selectedIps.length})</span>
              </button>
            )}

            <div className="relative">
              <Search className="absolute left-2.5 top-2 text-[var(--text-muted)]" size={14} />
              <input
                type="text"
                placeholder={t('Search IP, CIDR, or reason...', 'ค้นหา IP, CIDR หรือเหตุผล...')}
                className="dash-input pl-8 py-1.5 text-[12px] w-64"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                {isAdmin && (
                  <th className="w-10 text-center">
                    <input
                      type="checkbox"
                      checked={rules.length > 0 && selectedIps.length === rules.length}
                      onChange={handleSelectAll}
                      aria-label={t('Select all', 'เลือกทั้งหมด')}
                      className="rounded border-[var(--bg-border)] text-orange-500 focus:ring-orange-500/20 cursor-pointer"
                    />
                  </th>
                )}
                <th>{t('IP address / network', 'IP / เครือข่าย')}</th>
                <th>{t('Type', 'ประเภท')}</th>
                <th>{t('Reason', 'เหตุผล')}</th>
                <th>{t('Time left', 'เวลาที่เหลือ')}</th>
                <th>{t('Source', 'ที่มา')}</th>
                <th>{t('Added by', 'เพิ่มโดย')}</th>
                {isAdmin && <th className="text-right">{t('Actions', 'จัดการ')}</th>}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="text-center py-10 text-[var(--text-muted)]">
                    <div className="flex items-center justify-center gap-2">
                      <div className="w-4 h-4 border-2 border-orange-500/30 border-t-orange-500 rounded-full animate-spin" />
                      <span>{t('Loading IP rules...', 'กำลังโหลดกฎ IP...')}</span>
                    </div>
                  </td>
                </tr>
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-12 text-[var(--text-muted)]">
                    <AlertTriangle size={24} className="mx-auto mb-2 opacity-40" />
                    <p className="text-[13px] font-medium m-0">{t('No IP rules found', 'ไม่พบกฎ IP')}</p>
                    <p className="text-[11.5px] text-[var(--text-dim)] mt-0.5">
                      {search
                        ? t('Try a different search', 'ลองค้นหาด้วยคำอื่น')
                        : t('Press "Add IP rule" to add the first one', 'กด "เพิ่มกฎ IP" เพื่อเพิ่มรายการแรก')}
                    </p>
                  </td>
                </tr>
              ) : (
                rules.map((rule) => {
                  const isBlocked = rule.rule_type === 'block'
                  const isSelected = selectedIps.includes(rule.ip)
                  const isTemp = rule.expires_at !== null

                  return (
                    <tr key={rule.id} className={isSelected ? 'bg-orange-500/5' : ''}>
                      {isAdmin && (
                        <td className="text-center">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleSelectOne(rule.ip)}
                            aria-label={t(`Select ${rule.ip}`, `เลือก ${rule.ip}`)}
                            className="rounded border-[var(--bg-border)] text-orange-500 focus:ring-orange-500/20 cursor-pointer"
                          />
                        </td>
                      )}
                      <td className="font-mono text-[12.5px] font-semibold text-[var(--text-primary)]">
                        <div className="flex items-center gap-2">
                          <span>{rule.ip}</span>
                          <button
                            type="button"
                            onClick={() => handleCopy(rule.ip)}
                            className="text-[var(--text-muted)] hover:text-[var(--text-primary)] p-0.5 rounded transition-colors cursor-pointer"
                            title={t('Copy IP', 'คัดลอก IP')}
                            aria-label={t('Copy IP', 'คัดลอก IP')}
                          >
                            {copiedIp === rule.ip ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
                          </button>
                        </div>
                      </td>
                      <td>
                        {isBlocked ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-medium bg-red-500/10 text-red-400 border border-red-500/20">
                            <ShieldAlert size={11} />
                            <span>{t('BLOCK (403)', 'บล็อก (403)')}</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            <ShieldCheck size={11} />
                            <span>{t('ALLOW (PASS)', 'อนุญาต (ผ่าน)')}</span>
                          </span>
                        )}
                      </td>
                      <td className="text-[12px] text-[var(--text-secondary)]">
                        {rule.reason}
                      </td>
                      <td>
                        <span
                          className={`font-mono text-[11.5px] ${
                            isTemp ? 'text-amber-400 font-medium' : 'text-[var(--text-muted)]'
                          }`}
                        >
                          {formatRemaining(rule.remaining_seconds)}
                        </span>
                      </td>
                      <td>
                        <span className="mono-chip capitalize">
                          {rule.source}
                        </span>
                      </td>
                      <td className="font-mono text-[11.5px] text-[var(--text-muted)]">
                        {rule.added_by}
                      </td>
                      {isAdmin && (
                        <td className="text-right">
                          <button
                            onClick={() => {
                              if (confirm(t(`Remove IP rule for ${rule.ip}?`, `ลบกฎ IP ของ ${rule.ip}?`))) {
                                deleteMutation.mutate(rule.ip)
                              }
                            }}
                            className="p-1 text-[var(--text-muted)] hover:text-red-400 hover:bg-red-500/10 rounded transition-colors cursor-pointer"
                            title={t('Delete rule', 'ลบกฎ')}
                            aria-label={t('Delete rule', 'ลบกฎ')}
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      )}
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IP Modal */}
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
                  <Plus size={16} />
                </div>
                <h3 className="text-[15px] font-bold font-mono text-[var(--text-primary)] m-0">
                  {t('New IP rule', 'กฎ IP ใหม่')}
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

            <form onSubmit={handleAddSubmit} className="space-y-4 text-[13px]">
              <div>
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                  {t('IP address or CIDR range', 'IP หรือช่วง CIDR')}
                </label>
                <input
                  type="text"
                  required
                  placeholder={t('e.g. 192.168.1.100 or 10.0.0.0/24', 'เช่น 192.168.1.100 หรือ 10.0.0.0/24')}
                  className="w-full dash-input font-mono text-[12.5px]"
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                />
                <span className="text-[10.5px] text-[var(--text-muted)] mt-1 block">
                  {t('A single IPv4/IPv6 address or a CIDR subnet.', 'IPv4/IPv6 เดี่ยว หรือ subnet แบบ CIDR')}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    {t('Action', 'การดำเนินการ')}
                  </label>
                  <select
                    className="w-full dash-input text-[12.5px]"
                    value={newType}
                    onChange={(e) => setNewType(e.target.value as 'block' | 'allow')}
                  >
                    <option value="block">{t('Block (403 deny)', 'บล็อก (403 ปฏิเสธ)')}</option>
                    <option value="allow">{t('Allow (allow list)', 'อนุญาต (รายการอนุญาต)')}</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    {t('Duration', 'ระยะเวลา')}
                  </label>
                  <select
                    className="w-full dash-input text-[12.5px]"
                    value={newDuration}
                    onChange={(e) => setNewDuration(e.target.value)}
                  >
                    <option value="0">{t('Permanent', 'ถาวร')}</option>
                    <option value="3600">{t('1 hour', '1 ชั่วโมง')}</option>
                    <option value="21600">{t('6 hours', '6 ชั่วโมง')}</option>
                    <option value="86400">{t('24 hours', '24 ชั่วโมง')}</option>
                    <option value="604800">{t('7 days', '7 วัน')}</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                  {t('Reason', 'เหตุผล')}
                </label>
                <input
                  type="text"
                  placeholder={t('e.g. SQL injection attack or trusted office VPN', 'เช่น โจมตีด้วย SQL injection หรือ VPN ของออฟฟิศที่เชื่อถือได้')}
                  className="w-full dash-input text-[12.5px]"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                />
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
                  disabled={addMutation.isPending}
                  className="px-4 py-1.5 rounded-md bg-orange-500 hover:bg-orange-600 text-white text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
                >
                  {addMutation.isPending ? t('Applying...', 'กำลังใช้...') : t('Apply rule', 'ใช้กฎ')}
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

export default IPRules
