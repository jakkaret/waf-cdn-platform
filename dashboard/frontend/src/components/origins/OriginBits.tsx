import React from 'react'
import { Gauge, Globe, LockKeyhole, ShieldCheck, Sparkles, type LucideIcon } from 'lucide-react'
import { PROT_KEYS, PROT_STATE_LABEL, PROT_STATE_LABEL_TH, protMeta, type ProtKey, type ProtState, type Tone } from '../../lib/originSummary'
import { useT } from '../../i18n'

// Small pieces the Origins list, the origin header and the Protection tab
// share, so one status and one protection look the same everywhere.

const TONE: Record<Tone, string> = {
  ok: 'bg-[var(--success-subtle)] text-emerald-700 dark:text-emerald-300',
  warn: 'bg-[var(--warning-subtle)] text-amber-700 dark:text-amber-300',
  bad: 'bg-[var(--danger-subtle)] text-red-700 dark:text-red-300',
  off: 'bg-[var(--bg-surface-active)] text-[var(--text-muted)]',
}

export const StatusPill: React.FC<{ tone: Tone; children: React.ReactNode; className?: string }> = ({ tone, children, className = '' }) => (
  <span className={`inline-flex items-center gap-1.5 h-6 px-2.5 rounded-full text-[12px] font-medium whitespace-nowrap ${TONE[tone]} ${className}`}>
    <span className="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
    {children}
  </span>
)

export const PROT_ICON: Record<ProtKey, LucideIcon> = {
  waf: ShieldCheck,
  ml: Sparkles,
  ip: Globe,
  rate: Gauge,
  shield: LockKeyhole,
}

const STATE_CLS: Record<ProtState, string> = {
  on: 'bg-[var(--success-subtle)] text-emerald-700 dark:text-emerald-300',
  watch: 'bg-sky-500/10 text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-600/30',
  off: 'text-[var(--text-muted)] opacity-60 ring-1 ring-inset ring-[var(--bg-border)]',
  unknown: 'text-[var(--text-muted)] border border-dashed border-[var(--bg-border-hover)]',
}

export const ProtIcon: React.FC<{ k: ProtKey; state: ProtState; size?: 'sm' | 'lg' }> = ({ k, state, size = 'sm' }) => {
  const { lang } = useT()
  const Icon = PROT_ICON[k]
  const box = size === 'lg' ? 'w-9 h-9 rounded-[9px]' : 'w-[26px] h-[26px] rounded-[7px]'
  const label = `${protMeta(k, lang).name}: ${(lang === 'th' ? PROT_STATE_LABEL_TH : PROT_STATE_LABEL)[state]}`
  return (
    <span role="img" aria-label={label} title={label} className={`relative inline-grid place-items-center shrink-0 ${box} ${STATE_CLS[state]}`}>
      <Icon size={size === 'lg' ? 18 : 15} />
      {state === 'off' && (
        <span aria-hidden="true" className="absolute h-[1.5px] bg-current rotate-[-45deg] rounded" style={{ width: size === 'lg' ? 26 : 20 }} />
      )}
    </span>
  )
}

export const ProtIcons: React.FC<{ states: Record<ProtKey, { state: ProtState }> }> = ({ states }) => (
  <span className="inline-flex items-center gap-1">
    {PROT_KEYS.map((k) => (
      <ProtIcon key={k} k={k} state={states[k].state} />
    ))}
  </span>
)

export const ProtLegend: React.FC = () => {
  const { t, lang } = useT()
  return (
  <div className="flex flex-wrap items-center gap-x-3.5 gap-y-2 text-[12px] text-[var(--text-muted)]">
    <span className="font-semibold text-[var(--text-secondary)]">{t('Protection', 'การป้องกัน')}</span>
    {PROT_KEYS.map((k) => (
      <span key={k} className="inline-flex items-center gap-1.5">
        <ProtIcon k={k} state="on" />
        {protMeta(k, lang).name}
      </span>
    ))}
    <span className="w-px h-4 bg-[var(--bg-border)]" aria-hidden="true" />
    <span className="inline-flex items-center gap-1.5"><ProtIcon k="rate" state="on" />{t('On', 'เปิด')}</span>
    <span className="inline-flex items-center gap-1.5"><ProtIcon k="ml" state="watch" />{t('Watching only', 'เฝ้าดูอย่างเดียว')}</span>
    <span className="inline-flex items-center gap-1.5"><ProtIcon k="rate" state="off" />{t('Off', 'ปิด')}</span>
  </div>
  )
}
