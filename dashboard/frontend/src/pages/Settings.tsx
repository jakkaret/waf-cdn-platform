import React, { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { settingsApi, SystemSettings } from '../api/settings'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import { isOperator } from '../lib/permissions'
import {
  Shield,
  Globe,
  Save,
  Zap,
  RotateCw,
  Sliders,
  Lock,
} from 'lucide-react'
import { useT } from '../i18n'

export const Settings: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = isOperator(user)
  const queryClient = useQueryClient()
  const { t } = useT()

  // Stack diagnostics moved to its own operator page (/diagnostics), and the
  // account buttons (devices, Google link) to the profile menu (2026-10-28).
  const [activeTab, setActiveTab] = useState<'waf' | 'edge'>('waf')

  // Settings State Form
  const [form, setForm] = useState<Partial<SystemSettings>>({
    waf_mode: 'blocking',
    paranoia_level: 1,
    inbound_anomaly_threshold: 10,
    outbound_anomaly_threshold: 10,
    auto_purge_edge_cache: true,
    real_ip_header: 'X-Forwarded-For',
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
      toast.success(t('Settings saved and the WAF engine updated', 'บันทึกการตั้งค่าและอัปเดต WAF engine แล้ว'))
      queryClient.setQueryData(['system-settings'], updated)
      setForm(updated)
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || t('Failed to save settings', 'บันทึกการตั้งค่าไม่สำเร็จ'))
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
          <span>{t('Loading platform settings...', 'กำลังโหลดการตั้งค่าแพลตฟอร์ม...')}</span>
        </div>
      </div>
    )
  }

  const isBlocking = form.waf_mode === 'blocking'

  return (
    <div className="animate-fade-in pb-12">
      {/* Top Header Bar */}
      <TopBar
        title={t('Platform settings', 'ตั้งค่าแพลตฟอร์ม')}
        subtitle={t(
          'WAF mode and anomaly scoring for every origin on the platform, and how edges sync with the control plane.',
          'โหมด WAF และการให้คะแนน anomaly ของทุก origin บนแพลตฟอร์ม และวิธีที่ edge ซิงก์กับ control plane',
        )}
        badge={
          <Badge color={isBlocking ? 'success' : 'warning'} dot>
            {isBlocking ? t('Blocking', 'บล็อกจริง') : t('Detection only', 'ตรวจจับอย่างเดียว')}
          </Badge>
        }
        action={
          isAdmin ? (
            <Button
              variant="brand"
              onClick={handleSave}
              isLoading={saveMutation.isPending}
              icon={<Save size={14} />}
            >
              {t('Save changes', 'บันทึกการเปลี่ยนแปลง')}
            </Button>
          ) : undefined
        }
      />

      {!isAdmin && (
        <div role="note" className="mb-5 flex items-start gap-2.5 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-4 py-3 text-[13px] text-[var(--text-secondary)]">
          <Lock size={15} className="mt-0.5 shrink-0 text-[var(--text-muted)]" aria-hidden="true" />
          <p className="m-0">
            {t(
              'Read only. These values apply to the whole platform and only the platform operator can change them. Your own sites have per-origin settings on their origin page, for example the anomaly threshold in Rule proposals.',
              'ดูได้อย่างเดียว ค่าเหล่านี้มีผลทั้งแพลตฟอร์มและแก้ได้เฉพาะผู้ดูแลแพลตฟอร์ม เว็บของคุณมีการตั้งค่าของแต่ละ origin ที่หน้า origin เช่น threshold คะแนน anomaly ในหน้ากฎที่รอตรวจ',
            )}
          </p>
        </div>
      )}

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
              <span>{t('WAF & core engine', 'WAF และ core engine')}</span>
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
              <span>{t('Edge & CDN delivery', 'Edge และการส่งผ่าน CDN')}</span>
            </button>
          </div>

          {/* disabled on a fieldset turns every control inside read-only for
              non-operators; POST /api/settings/ still enforces require_admin. */}
          <fieldset disabled={!isAdmin} className="m-0 p-0 border-0 min-w-0 disabled:[&_label]:cursor-default">
          <legend className="sr-only">{isAdmin ? t('Platform settings', 'ตั้งค่าแพลตฟอร์ม') : t('Platform settings (read only)', 'ตั้งค่าแพลตฟอร์ม (ดูได้อย่างเดียว)')}</legend>

          {/* ═══ Tab 1: WAF & Core Engine ═══ */}
          {activeTab === 'waf' && (
            <div className="dash-card p-5 sm:p-6 space-y-6 animate-fade-in">
              <div>
                <h3 className="text-[14.5px] font-bold text-[var(--text-primary)] font-mono m-0 mb-1 flex items-center gap-2">
                  <Shield size={16} className="text-orange-600 dark:text-orange-400" />
                  {t('WAF mode', 'โหมดของ WAF')}
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0">
                  {t('Choose how the ModSecurity Core Rule Set (CRS) evaluates and enforces requests.', 'เลือกวิธีที่ ModSecurity Core Rule Set (CRS) ตรวจและบังคับใช้กับ request')}
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
                        {t('Blocking (on)', 'บล็อกจริง (เปิด)')}
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
                    {t('Requests whose anomaly score reaches the limit are dropped with HTTP 403 Forbidden.', 'request ที่คะแนน anomaly ถึงค่าที่กำหนดจะถูกตัดและได้ HTTP 403 Forbidden')}
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
                        {t('Detection only (simulate)', 'ตรวจจับอย่างเดียว (จำลอง)')}
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
                    {t('Evaluates rules and logs events without blocking traffic. Good for testing a baseline.', 'ตรวจตามกฎและบันทึกเหตุการณ์โดยไม่บล็อกทราฟฟิก เหมาะสำหรับทดสอบค่าพื้นฐาน')}
                  </p>
                </label>
              </div>

              {/* Anomaly Limits Section */}
              <div className="border-t border-[var(--bg-border-subtle)] pt-5 space-y-4">
                <h4 className="text-[13.5px] font-bold text-[var(--text-primary)] font-mono m-0 flex items-center gap-2">
                  <Sliders size={15} className="text-orange-600 dark:text-orange-400" />
                  {t('Anomaly scoring & sensitivity', 'การให้คะแนน anomaly และความไว')}
                </h4>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
                  <div>
                    <label className="block text-[11px] font-bold font-mono text-[var(--text-secondary)] mb-1">
                      Paranoia level
                    </label>
                    <select
                      className="w-full dash-input text-[12px] font-mono cursor-pointer"
                      value={form.paranoia_level}
                      onChange={(e) => setForm({ ...form, paranoia_level: parseInt(e.target.value, 10) })}
                    >
                      <option value={1}>{t('Level 1 (standard)', 'ระดับ 1 (มาตรฐาน)')}</option>
                      <option value={2}>{t('Level 2 (moderate)', 'ระดับ 2 (ปานกลาง)')}</option>
                      <option value={3}>{t('Level 3 (high security)', 'ระดับ 3 (ความปลอดภัยสูง)')}</option>
                      <option value={4}>{t('Level 4 (extreme)', 'ระดับ 4 (สูงสุด)')}</option>
                    </select>
                    <span className="text-[10px] text-[var(--text-dim)] mt-0.5 block font-mono">
                      {t('How deep the rules check', 'ความละเอียดในการตรวจของกฎ')}
                    </span>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold font-mono text-[var(--text-secondary)] mb-1">
                      {t('Inbound anomaly limit', 'ค่าจำกัด anomaly ขาเข้า')}
                    </label>
                    <input
                      type="number"
                      min="1"
                      className="w-full dash-input font-mono text-[12px]"
                      value={form.inbound_anomaly_threshold}
                      onChange={(e) => setForm({ ...form, inbound_anomaly_threshold: parseInt(e.target.value, 10) || 5 })}
                    />
                    <span className="text-[11px] text-[var(--text-muted)] mt-0.5 block">
                      {t('A request scoring at or above this is blocked. Origins without their own threshold use this value.', 'request ที่ได้คะแนนตั้งแต่ค่านี้จะถูกบล็อก origin ที่ไม่ได้ตั้ง threshold เองจะใช้ค่านี้')}
                    </span>
                  </div>

                  <div>
                    <label className="block text-[11px] font-bold font-mono text-[var(--text-secondary)] mb-1">
                      {t('Outbound anomaly limit', 'ค่าจำกัด anomaly ขาออก')}
                    </label>
                    <input
                      type="number"
                      min="1"
                      className="w-full dash-input font-mono text-[12px]"
                      value={form.outbound_anomaly_threshold}
                      onChange={(e) => setForm({ ...form, outbound_anomaly_threshold: parseInt(e.target.value, 10) || 5 })}
                    />
                    <span className="text-[11px] text-[var(--text-muted)] mt-0.5 block">
                      {t('Score limit for responses leaving the origin (data leak checks).', 'ค่าจำกัดคะแนนของ response ที่ออกจาก origin (ตรวจข้อมูลรั่วไหล)')}
                    </span>
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] font-bold font-mono text-[var(--text-secondary)] mb-1">
                    {t('Client real-IP header', 'Header ที่ระบุ IP จริงของผู้ใช้')}
                  </label>
                  <input
                    type="text"
                    placeholder="X-Forwarded-For"
                    className="w-full dash-input font-mono text-[12px]"
                    value={form.real_ip_header}
                    onChange={(e) => setForm({ ...form, real_ip_header: e.target.value })}
                  />
                  <span className="text-[11px] text-amber-700 dark:text-amber-400 mt-1 block">
                    {t('Saved only. The WAF does not use this value yet, so changing it has no effect on traffic.', 'บันทึกไว้เท่านั้น WAF ยังไม่ได้ใช้ค่านี้ การเปลี่ยนจึงไม่มีผลกับทราฟฟิก')}
                  </span>
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
                  {t('Edge node sync & caching', 'การซิงก์ edge node และ cache')}
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0">
                  {t('How the control plane and the edge nodes stay in sync.', 'วิธีที่ control plane และ edge node ซิงก์ข้อมูลกัน')}
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
                      {t('Purge edge caches automatically when origin rules change', 'ล้าง cache ที่ edge อัตโนมัติเมื่อกฎของ origin เปลี่ยน')}
                    </span>
                    <span className="text-[11.5px] text-[var(--text-muted)] leading-relaxed block mt-0.5">
                      {t('Saved only. Changing rules does not purge edge caches yet; purge a site from its origin page instead.', 'บันทึกไว้เท่านั้น การเปลี่ยนกฎยังไม่ล้าง cache ที่ edge ให้ล้าง cache จากหน้า origin แทน')}
                    </span>
                  </div>
                </label>

                <div>
                  <label className="block text-[11px] font-bold font-mono text-[var(--text-secondary)] mb-1">
                    {t('Edge rule polling interval (seconds)', 'ความถี่ที่ edge ดึงกฎ (วินาที)')}
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="60"
                    className="w-full max-w-xs dash-input font-mono text-[12px]"
                    value={form.edge_sync_interval_seconds}
                    onChange={(e) => setForm({ ...form, edge_sync_interval_seconds: parseInt(e.target.value, 10) || 5 })}
                  />
                  <span className="text-[11px] text-amber-700 dark:text-amber-400 mt-1 block">
                    {t('Saved only. Edge nodes use their own configured interval, not this value.', 'บันทึกไว้เท่านั้น edge node ใช้ค่าที่ตั้งไว้ในตัวเอง ไม่ใช่ค่านี้')}
                  </span>
                </div>
              </div>
            </div>
          )}

          </fieldset>


        </div>

        {/* Right Column (4 cols): Security Posture & Quick Info Panel */}
        <div className="lg:col-span-4 space-y-3.5">
          
          {/* Card 1: Active Security Posture */}
          <div className="dash-card p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-[var(--bg-border)] pb-2.5">
              <span className="text-[11px] font-bold font-mono text-[var(--text-secondary)]">
                {t('Security posture', 'สถานะความปลอดภัย')}
              </span>
              <span
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-bold ${
                  isBlocking
                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                    : 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${isBlocking ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                <span>{isBlocking ? t('PROTECTED', 'ป้องกันอยู่') : t('SIMULATING', 'จำลอง')}</span>
              </span>
            </div>

            <div className="space-y-2 text-[11.5px] font-mono">
              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">{t('Mode:', 'โหมด:')}</span>
                <span className="font-semibold text-[var(--text-primary)]">
                  {form.waf_mode === 'blocking' ? t('Blocking', 'บล็อกจริง') : t('Detection only', 'ตรวจจับอย่างเดียว')}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">Paranoia level:</span>
                <span className="font-bold text-orange-600 dark:text-orange-400">
                  {t('Level', 'ระดับ')} {form.paranoia_level} / 4
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">{t('Inbound threshold:', 'threshold ขาเข้า:')}</span>
                <span className="text-[var(--text-primary)]">
                  {form.inbound_anomaly_threshold} {t('pts', 'คะแนน')}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">{t('Outbound threshold:', 'threshold ขาออก:')}</span>
                <span className="text-[var(--text-primary)]">
                  {form.outbound_anomaly_threshold} {t('pts', 'คะแนน')}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-[var(--text-muted)]">{t('Edge auto-purge:', 'ล้าง cache อัตโนมัติ:')}</span>
                <span className="text-[var(--text-primary)]">
                  {form.auto_purge_edge_cache ? t('On (not applied yet)', 'เปิด (ยังไม่มีผล)') : t('Off', 'ปิด')}
                </span>
              </div>
            </div>
          </div>

          {/* Card 2: Quick Operations */}
          <div className="dash-card p-4 space-y-2.5">
            <h4 className="text-[11px] font-bold font-mono text-[var(--text-secondary)] m-0">
              {t('Quick actions', 'การดำเนินการด่วน')}
            </h4>

            <div className="space-y-2">
              {isAdmin && (
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
                    <span>{t('Sync & reload the engine', 'ซิงก์และ reload engine')}</span>
                  </div>
                  <span className="text-[10.5px] font-mono text-[var(--text-muted)]">{t('Hot reload', 'reload ทันที')}</span>
                </button>
              )}
            </div>
          </div>

          {/* Card 3: Contextual Tip */}
          <div className="dash-card p-4 bg-orange-50 dark:bg-orange-500/[0.06] border border-orange-200 dark:border-orange-500/20 text-[12px] space-y-1">
            <div className="flex items-center gap-1.5 font-bold font-mono text-orange-600 dark:text-orange-400 text-[11px]">
              <Zap size={13} />
              <span>{t('Guideline', 'แนวทาง')}</span>
            </div>
            <p className="m-0 text-[11px] font-mono leading-relaxed text-[var(--text-secondary)]">
              {t('When making major rule changes, switch the WAF to', 'เมื่อเปลี่ยนกฎครั้งใหญ่ ให้เปลี่ยน WAF เป็น')}{' '}
              <strong>{t('Detection only', 'ตรวจจับอย่างเดียว')}</strong>{' '}
              {t('for 24 h to look for false positives before turning', 'สัก 24 ชม. เพื่อดู false positive ก่อนเปิด')}{' '}
              <strong>{t('Blocking', 'บล็อกจริง')}</strong> {t('back on.', 'อีกครั้ง')}
            </p>
          </div>

        </div>

      </div>
    </div>
  )
}

export default Settings
