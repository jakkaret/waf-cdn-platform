import React, { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { previewShield, ShieldPreview } from '../api/shieldEvents'
import { ConfirmDialog } from './ui/ConfirmDialog'
import { tr, useT } from '../i18n'

export type ShieldMode = 'enforce' | 'log_only'
export type OtpAccessMode = 'open' | 'allowlist'

const cardTitle = 'text-[13px] font-bold text-[var(--text-primary)] font-mono m-0'
const hint = 'text-[11.5px] font-mono text-[var(--text-muted)] m-0'

export const ModeSelector: React.FC<{ mode: ShieldMode; onChange: (m: ShieldMode) => void }> = ({ mode, onChange }) => {
  const { t } = useT()
  return (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>{t('Mode', 'โหมด')}</h3>
    <div className="flex gap-2" role="radiogroup" aria-label={t('Shield mode', 'โหมดของ Shield')}>
      {([
        [
          'log_only',
          t('Log only', 'บันทึก log อย่างเดียว'),
          t('Record who would be challenged or blocked; let everyone through.', 'บันทึกว่าใครจะถูกทดสอบหรือถูกบล็อก แต่ให้ทุกคนผ่าน'),
        ],
        [
          'enforce',
          t('Enforce', 'บังคับใช้'),
          t('Challenge on GET, block other methods without clearance.', 'ทดสอบเมื่อเป็น GET และบล็อก method อื่นที่ยังไม่ผ่านด่าน'),
        ],
      ] as const).map(([value, label, desc]) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={mode === value}
          onClick={() => onChange(value)}
          className={`flex-1 text-left p-3 rounded-md border cursor-pointer ${
            mode === value ? 'border-orange-500 bg-orange-500/[0.05]' : 'border-[var(--bg-border)]'
          }`}
        >
          <span className="block font-mono text-[12.5px] font-bold text-[var(--text-primary)]">{label}</span>
          <span className="block font-mono text-[11px] text-[var(--text-muted)] mt-0.5">{desc}</span>
        </button>
      ))}
    </div>
    <p className={hint}>
      {t(
        'Start in Log only, check Shield Activity for a day or two, then switch to Enforce.',
        'เริ่มจากโหมดบันทึก log อย่างเดียว ดูกิจกรรมของ Shield สักวันสองวัน แล้วค่อยเปลี่ยนเป็นบังคับใช้',
      )}
    </p>
  </div>
  )
}

export const ExcludePathsField: React.FC<{ value: string; onChange: (v: string) => void }> = ({ value, onChange }) => {
  const { t } = useT()
  return (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>{t('Excluded paths', 'Path ที่ยกเว้น')}</h3>
    <p className={hint}>
      {t(
        'Never gated, even if a protected pattern matches. Use for AJAX endpoints, webhooks and callbacks (e.g. /wp-admin/admin-ajax.php).',
        'ไม่ต้องผ่านด่านเลยแม้จะตรงกับ path ที่ป้องกัน ใช้กับ AJAX endpoint, webhook และ callback (เช่น /wp-admin/admin-ajax.php)',
      )}
    </p>
    <textarea
      className="w-full dash-input font-mono text-[12px] min-h-[70px] resize-y"
      placeholder="/wp-admin/admin-ajax.php"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  </div>
  )
}

export const OtpAccessField: React.FC<{
  accessMode: OtpAccessMode
  allowedText: string
  onModeChange: (m: OtpAccessMode) => void
  onAllowedChange: (v: string) => void
}> = ({ accessMode, allowedText, onModeChange, onAllowedChange }) => {
  const { t } = useT()
  return (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>{t('Who can pass', 'ใครผ่านได้บ้าง')}</h3>
    <div className="space-y-2 font-mono text-[12px]">
      <label className="flex items-start gap-2 cursor-pointer">
        <input type="radio" checked={accessMode === 'open'} onChange={() => onModeChange('open')} className="mt-0.5" />
        <span>
          <strong>{t('Anyone who receives the code', 'ทุกคนที่ได้รับรหัส')}</strong>
          <span className="block text-[11px] text-[var(--text-muted)]">
            {t(
              'Bot friction for public login pages. Anyone can type their own email and pass.',
              'เพิ่มด่านกันบอทให้หน้าล็อกอินสาธารณะ ใครก็กรอกอีเมลของตัวเองแล้วผ่านได้',
            )}
          </span>
        </span>
      </label>
      <label className="flex items-start gap-2 cursor-pointer">
        <input
          type="radio"
          checked={accessMode === 'allowlist'}
          onChange={() => onModeChange('allowlist')}
          className="mt-0.5"
        />
        <span>
          <strong>{t('Only these emails', 'เฉพาะอีเมลเหล่านี้')}</strong>
          <span className="block text-[11px] text-[var(--text-muted)]">
            {t(
              'For admin/staff pages. Personal addresses work (name@gmail.com); @yourcompany.com allows a whole domain. Others see the same "code sent" message but never get a code. Removing someone takes effect immediately.',
              'สำหรับหน้าผู้ดูแล/พนักงาน ใช้อีเมลส่วนตัวได้ (name@gmail.com) และ @yourcompany.com อนุญาตทั้งโดเมน คนอื่นจะเห็นข้อความ "ส่งรหัสแล้ว" เหมือนกันแต่ไม่ได้รับรหัส การนำใครออกมีผลทันที',
            )}
          </span>
        </span>
      </label>
    </div>
    {accessMode === 'allowlist' && (
      <textarea
        aria-label={t('Allowed emails', 'อีเมลที่อนุญาต')}
        className="w-full dash-input font-mono text-[12px] min-h-[90px] resize-y"
        placeholder={'owner@gmail.com\nstaff@hotmail.com\n@kku.ac.th'}
        value={allowedText}
        onChange={(e) => onAllowedChange(e.target.value)}
      />
    )}
  </div>
  )
}

// ---------------------------------------------------------------- presets

export interface ShieldPreset {
  key: string
  label: string
  description: string
  labelTh: string
  descriptionTh: string
  captcha: { enabled: boolean; login_paths: string[]; exclude_paths: string[] }
  otp: {
    enabled: boolean
    login_paths: string[]
    exclude_paths: string[]
    access_mode: OtpAccessMode
    clearance_ttl: number
  }
}

export const SHIELD_PRESETS: ShieldPreset[] = [
  {
    key: 'shop',
    label: 'Shop / member login',
    description: 'CAPTCHA on login, sign-up and password reset. No OTP: customers can\'t be listed in advance.',
    labelTh: 'ร้านค้า / ล็อกอินสมาชิก',
    descriptionTh: 'CAPTCHA ที่หน้าล็อกอิน สมัครสมาชิก และตั้งรหัสผ่านใหม่ ไม่ใช้ OTP เพราะระบุรายชื่อลูกค้าล่วงหน้าไม่ได้',
    captcha: {
      enabled: true,
      login_paths: ['/login*', '/signin*', '/register*', '/signup*', '/forgot-password*', '/password/reset*'],
      exclude_paths: [],
    },
    otp: { enabled: false, login_paths: ['/login*'], exclude_paths: [], access_mode: 'open', clearance_ttl: 3600 },
  },
  {
    key: 'wordpress',
    label: 'WordPress admin',
    description: 'OTP for your team only on wp-login and wp-admin; admin-ajax stays open for the public site.',
    labelTh: 'ผู้ดูแล WordPress',
    descriptionTh: 'OTP เฉพาะทีมของคุณที่ wp-login และ wp-admin ส่วน admin-ajax ยังเปิดให้เว็บสาธารณะใช้ได้',
    captcha: { enabled: false, login_paths: ['/wp-login.php'], exclude_paths: [] },
    otp: {
      enabled: true,
      login_paths: ['/wp-login.php', '/wp-admin*'],
      exclude_paths: ['/wp-admin/admin-ajax.php'],
      access_mode: 'allowlist',
      clearance_ttl: 28800,
    },
  },
  {
    key: 'internal',
    label: 'Internal tool (whole site)',
    description: 'OTP for listed people in front of every page, 12-hour sessions.',
    labelTh: 'ระบบภายใน (ทั้งเว็บ)',
    descriptionTh: 'OTP เฉพาะคนในรายชื่อหน้าทุกหน้า จำการยืนยันไว้ 12 ชั่วโมง',
    captcha: { enabled: false, login_paths: ['/*'], exclude_paths: [] },
    otp: { enabled: true, login_paths: ['/*'], exclude_paths: [], access_mode: 'allowlist', clearance_ttl: 43200 },
  },
  {
    key: 'api',
    label: 'API / mobile backend',
    description: 'Both off. Apps and scripts cannot solve a challenge; use rate limits and WAF rules instead.',
    labelTh: 'API / backend ของแอปมือถือ',
    descriptionTh: 'ปิดทั้งสองอย่าง แอปและสคริปต์ผ่านด่านทดสอบไม่ได้ ให้ใช้ rate limit และกฎ WAF แทน',
    captcha: { enabled: false, login_paths: ['/login*'], exclude_paths: [] },
    otp: { enabled: false, login_paths: ['/login*'], exclude_paths: [], access_mode: 'open', clearance_ttl: 3600 },
  },
]

export const ShieldPresets: React.FC<{ onApply: (p: ShieldPreset) => void; appliedKey: string | null }> = ({
  onApply,
  appliedKey,
}) => {
  const { t } = useT()
  return (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>{t('Start from a preset', 'เริ่มจากค่าสำเร็จรูป')}</h3>
    <p className={hint}>
      {t(
        'Fills in the forms below (in Log only mode). Nothing changes until you review and press Save.',
        'กรอกฟอร์มด้านล่างให้ (ในโหมดบันทึก log อย่างเดียว) ยังไม่มีอะไรเปลี่ยนจนกว่าคุณจะตรวจแล้วกดบันทึก',
      )}
    </p>
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
      {SHIELD_PRESETS.map((p) => (
        <button
          key={p.key}
          type="button"
          onClick={() => onApply(p)}
          className={`text-left p-3 rounded-md border cursor-pointer ${
            appliedKey === p.key ? 'border-orange-500 bg-orange-500/[0.05]' : 'border-[var(--bg-border)]'
          }`}
        >
          <span className="block font-mono text-[12.5px] font-bold text-[var(--text-primary)]">{t(p.label, p.labelTh)}</span>
          <span className="block font-mono text-[11px] text-[var(--text-muted)] mt-1">{t(p.description, p.descriptionTh)}</span>
        </button>
      ))}
    </div>
    {appliedKey && (
      <p className="text-[11.5px] font-mono text-amber-500 m-0 flex items-center gap-1.5">
        <AlertTriangle size={13} /> {t('Preset applied to the forms -- not saved yet.', 'ใส่ค่าสำเร็จรูปในฟอร์มแล้ว — ยังไม่ได้บันทึก')}
      </p>
    )}
  </div>
  )
}

// ----------------------------------------------------- pre-save impact check

function describe(p: ShieldPreview, kind: string): string | null {
  if (p.total === 0 || (p.other_methods === 0 && p.non_browser === 0)) return null
  const days = Math.round(p.hours / 24)
  const lines = [tr(`In the last ${days} days these ${kind} paths got ${p.total} requests.`, `ใน ${days} วันที่ผ่านมา path ${kind} เหล่านี้มี ${p.total} request`)]
  if (p.other_methods > 0)
    lines.push(
      tr(
        `${p.other_methods} used POST/PUT/DELETE etc. and would be blocked (403) without clearance.`,
        `${p.other_methods} request ใช้ POST/PUT/DELETE ฯลฯ และจะถูกบล็อก (403) ถ้ายังไม่ผ่านด่าน`,
      ),
    )
  if (p.non_browser > 0) {
    const uas = p.top_non_browser.map((u) => `${u.user_agent} (${u.count})`).join(', ')
    lines.push(
      tr(
        `${p.non_browser} came from scripts or apps that can't solve a challenge: ${uas}.`,
        `${p.non_browser} request มาจากสคริปต์หรือแอปที่ผ่านด่านทดสอบไม่ได้: ${uas}`,
      ),
    )
  }
  lines.push(tr('Save and enforce anyway? (Log only mode would just record these.)', 'ยังต้องการบันทึกและบังคับใช้ไหม? (โหมดบันทึก log อย่างเดียวจะแค่บันทึกไว้)'))
  return lines.join(' ')
}

/** Before saving an enforcing config, look at the last 7 days of this origin's
 * traffic on those paths and ask for confirmation if API/app traffic would be
 * cut off. Returns the dialog element to render and a guard to call on save. */
export function useShieldImpactCheck(originId: string) {
  const [pending, setPending] = useState<{ message: string; save: () => void } | null>(null)
  const { t } = useT()

  const guard = async (
    opts: { kind: string; enabled: boolean; mode: ShieldMode; login_paths: string[]; exclude_paths: string[] },
    save: () => void,
  ) => {
    if (!opts.enabled || opts.mode !== 'enforce') return save()
    try {
      const { data } = await previewShield(originId, { login_paths: opts.login_paths, exclude_paths: opts.exclude_paths })
      const message = describe(data, opts.kind)
      if (!message) return save()
      setPending({ message, save })
    } catch {
      save() // the check is advisory; never block saving on it
    }
  }

  const dialog = (
    <ConfirmDialog
      open={!!pending}
      title={t('This will affect real traffic', 'การเปลี่ยนนี้จะมีผลกับทราฟฟิกจริง')}
      message={pending?.message || ''}
      confirmText={t('Save and enforce', 'บันทึกและบังคับใช้')}
      isDanger
      onConfirm={() => {
        const save = pending?.save
        setPending(null)
        save?.()
      }}
      onCancel={() => setPending(null)}
    />
  )
  return { guard, dialog }
}

// ------------------------------------------------------------- OTP timing

export interface TimeOption {
  value: number // seconds
  label: string
  labelTh?: string
}

// Ranges match the backend (api/origins.py OtpShieldConfig) and control-api.
export const OTP_CODE_TTL_OPTIONS: TimeOption[] = [
  { value: 60, label: '1 minute', labelTh: '1 นาที' },
  { value: 120, label: '2 minutes', labelTh: '2 นาที' },
  { value: 300, label: '5 minutes', labelTh: '5 นาที' },
  { value: 600, label: '10 minutes', labelTh: '10 นาที' },
  { value: 900, label: '15 minutes', labelTh: '15 นาที' },
  { value: 1800, label: '30 minutes', labelTh: '30 นาที' },
]

export const OTP_CLEARANCE_OPTIONS: TimeOption[] = [
  { value: 900, label: '15 minutes', labelTh: '15 นาที' },
  { value: 3600, label: '1 hour', labelTh: '1 ชั่วโมง' },
  { value: 4 * 3600, label: '4 hours', labelTh: '4 ชั่วโมง' },
  { value: 8 * 3600, label: '8 hours (a work day)', labelTh: '8 ชั่วโมง (หนึ่งวันทำงาน)' },
  { value: 12 * 3600, label: '12 hours', labelTh: '12 ชั่วโมง' },
  { value: 86400, label: '1 day', labelTh: '1 วัน' },
  { value: 3 * 86400, label: '3 days', labelTh: '3 วัน' },
  { value: 7 * 86400, label: '7 days', labelTh: '7 วัน' },
  { value: 30 * 86400, label: '30 days', labelTh: '30 วัน' },
]

/** Keep a saved value that isn't one of the presets selectable (shown as-is).
 * Labels come back in the given language. */
export function withCurrent(options: TimeOption[], current: number, lang: 'en' | 'th' = 'en'): TimeOption[] {
  const th = lang === 'th'
  const shown = options.map((o) => ({ value: o.value, label: th && o.labelTh ? o.labelTh : o.label }))
  if (options.some((o) => o.value === current)) return shown
  const label =
    current % 3600 === 0
      ? th ? `${current / 3600} ชั่วโมง` : `${current / 3600} hours`
      : th ? `${Math.round(current / 60)} นาที` : `${Math.round(current / 60)} minutes`
  return [...shown, { value: current, label: th ? `${label} (ค่าปัจจุบัน)` : `${label} (current)` }].sort((a, b) => a.value - b.value)
}
