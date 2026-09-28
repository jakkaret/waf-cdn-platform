import React, { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { previewShield, ShieldPreview } from '../api/shieldEvents'
import { ConfirmDialog } from './ui/ConfirmDialog'

export type ShieldMode = 'enforce' | 'log_only'
export type OtpAccessMode = 'open' | 'allowlist'

const cardTitle = 'text-[13px] font-bold text-[var(--text-primary)] font-mono m-0'
const hint = 'text-[11.5px] font-mono text-[var(--text-muted)] m-0'

export const ModeSelector: React.FC<{ mode: ShieldMode; onChange: (m: ShieldMode) => void }> = ({ mode, onChange }) => (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>Mode</h3>
    <div className="flex gap-2" role="radiogroup" aria-label="Shield mode">
      {([
        ['log_only', 'Log only', 'Record who would be challenged or blocked; let everyone through.'],
        ['enforce', 'Enforce', 'Challenge on GET, block other methods without clearance.'],
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
    <p className={hint}>Start in Log only, check Shield Activity for a day or two, then switch to Enforce.</p>
  </div>
)

export const ExcludePathsField: React.FC<{ value: string; onChange: (v: string) => void }> = ({ value, onChange }) => (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>Excluded paths</h3>
    <p className={hint}>
      Never gated, even if a protected pattern matches. Use for AJAX endpoints, webhooks and callbacks
      (e.g. /wp-admin/admin-ajax.php).
    </p>
    <textarea
      className="w-full dash-input font-mono text-[12px] min-h-[70px] resize-y"
      placeholder="/wp-admin/admin-ajax.php"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  </div>
)

export const OtpAccessField: React.FC<{
  accessMode: OtpAccessMode
  allowedText: string
  onModeChange: (m: OtpAccessMode) => void
  onAllowedChange: (v: string) => void
}> = ({ accessMode, allowedText, onModeChange, onAllowedChange }) => (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>Who can pass</h3>
    <div className="space-y-2 font-mono text-[12px]">
      <label className="flex items-start gap-2 cursor-pointer">
        <input type="radio" checked={accessMode === 'open'} onChange={() => onModeChange('open')} className="mt-0.5" />
        <span>
          <strong>Anyone who receives the code</strong>
          <span className="block text-[11px] text-[var(--text-muted)]">
            Bot friction for public login pages. Anyone can type their own email and pass.
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
          <strong>Only these emails</strong>
          <span className="block text-[11px] text-[var(--text-muted)]">
            For admin/staff pages. Personal addresses work (name@gmail.com); @yourcompany.com allows a whole
            domain. Others see the same &quot;code sent&quot; message but never get a code. Removing someone
            takes effect immediately.
          </span>
        </span>
      </label>
    </div>
    {accessMode === 'allowlist' && (
      <textarea
        aria-label="Allowed emails"
        className="w-full dash-input font-mono text-[12px] min-h-[90px] resize-y"
        placeholder={'owner@gmail.com\nstaff@hotmail.com\n@kku.ac.th'}
        value={allowedText}
        onChange={(e) => onAllowedChange(e.target.value)}
      />
    )}
  </div>
)

// ---------------------------------------------------------------- presets

export interface ShieldPreset {
  key: string
  label: string
  description: string
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
    captcha: { enabled: false, login_paths: ['/*'], exclude_paths: [] },
    otp: { enabled: true, login_paths: ['/*'], exclude_paths: [], access_mode: 'allowlist', clearance_ttl: 43200 },
  },
  {
    key: 'api',
    label: 'API / mobile backend',
    description: 'Both off. Apps and scripts cannot solve a challenge; use rate limits and WAF rules instead.',
    captcha: { enabled: false, login_paths: ['/login*'], exclude_paths: [] },
    otp: { enabled: false, login_paths: ['/login*'], exclude_paths: [], access_mode: 'open', clearance_ttl: 3600 },
  },
]

export const ShieldPresets: React.FC<{ onApply: (p: ShieldPreset) => void; appliedKey: string | null }> = ({
  onApply,
  appliedKey,
}) => (
  <div className="dash-card p-5 space-y-3">
    <h3 className={cardTitle}>Start from a preset</h3>
    <p className={hint}>
      Fills in the forms below (in Log only mode). Nothing changes until you review and press Save.
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
          <span className="block font-mono text-[12.5px] font-bold text-[var(--text-primary)]">{p.label}</span>
          <span className="block font-mono text-[11px] text-[var(--text-muted)] mt-1">{p.description}</span>
        </button>
      ))}
    </div>
    {appliedKey && (
      <p className="text-[11.5px] font-mono text-amber-500 m-0 flex items-center gap-1.5">
        <AlertTriangle size={13} /> Preset applied to the forms -- not saved yet.
      </p>
    )}
  </div>
)

// ----------------------------------------------------- pre-save impact check

function describe(p: ShieldPreview, kind: string): string | null {
  if (p.total === 0 || (p.other_methods === 0 && p.non_browser === 0)) return null
  const days = Math.round(p.hours / 24)
  const lines = [`In the last ${days} days these ${kind} paths got ${p.total} requests.`]
  if (p.other_methods > 0) lines.push(`${p.other_methods} used POST/PUT/DELETE etc. and would be blocked (403) without clearance.`)
  if (p.non_browser > 0) {
    const uas = p.top_non_browser.map((u) => `${u.user_agent} (${u.count})`).join(', ')
    lines.push(`${p.non_browser} came from scripts or apps that can't solve a challenge: ${uas}.`)
  }
  lines.push('Save and enforce anyway? (Log only mode would just record these.)')
  return lines.join(' ')
}

/** Before saving an enforcing config, look at the last 7 days of this origin's
 * traffic on those paths and ask for confirmation if API/app traffic would be
 * cut off. Returns the dialog element to render and a guard to call on save. */
export function useShieldImpactCheck(originId: string) {
  const [pending, setPending] = useState<{ message: string; save: () => void } | null>(null)

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
      title="This will affect real traffic"
      message={pending?.message || ''}
      confirmText="Save and enforce"
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
