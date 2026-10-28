import React from 'react'
import { ChevronDown } from 'lucide-react'
import { ORIGIN_VIEWS, labelIn, type OriginViewId } from '../layout/navigation'
import { PROT_KEYS, PROT_STATE_LABEL, PROT_STATE_LABEL_TH, protMeta, type ProtKey, type ProtState } from '../../lib/originSummary'
import { ProtIcon } from './OriginBits'
import { useT } from '../../i18n'

// The origin page's tabs, and the Protection tab's accordion: each of
// the five protections is one row (icon, name, what it does, a short
// summary, its state) that opens the existing editor for it.

export const OriginViewTabs: React.FC<{
  active: OriginViewId
  onSelect: (id: OriginViewId) => void
  extra?: Partial<Record<OriginViewId, React.ReactNode>>
}> = ({ active, onSelect, extra = {} }) => {
  const { t, lang } = useT()
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return
    e.preventDefault()
    const i = ORIGIN_VIEWS.findIndex((v) => v.id === active)
    const next = ORIGIN_VIEWS[(i + (e.key === 'ArrowRight' ? 1 : -1) + ORIGIN_VIEWS.length) % ORIGIN_VIEWS.length]
    onSelect(next.id)
    window.setTimeout(() => document.getElementById(`origin-view-${next.id}`)?.focus(), 0)
  }
  return (
    <div role="tablist" aria-label={t('Origin sections', 'ส่วนของ origin')} onKeyDown={onKeyDown} className="flex gap-0.5 border-b border-[var(--bg-border)] overflow-x-auto [scrollbar-width:none]">
      {ORIGIN_VIEWS.map((v) => {
        const on = v.id === active
        return (
          <button
            key={v.id}
            id={`origin-view-${v.id}`}
            type="button"
            role="tab"
            aria-selected={on}
            aria-controls="origin-tab-panel"
            tabIndex={on ? 0 : -1}
            onClick={() => onSelect(v.id)}
            className={`h-10 px-3 -mb-px inline-flex items-center gap-1.5 whitespace-nowrap border-b-2 text-[13.5px] cursor-pointer ${
              on ? 'border-[var(--accent)] font-semibold text-[var(--text-primary)]' : 'border-transparent font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            {labelIn(v, lang)}
            {extra[v.id]}
          </button>
        )
      })}
    </div>
  )
}

const PILL: Record<ProtState, string> = {
  on: 'bg-[var(--success-subtle)] text-emerald-700 dark:text-emerald-300',
  watch: 'bg-sky-500/10 text-sky-700 dark:text-sky-300',
  off: 'bg-[var(--bg-surface-active)] text-[var(--text-muted)]',
  unknown: 'bg-[var(--bg-surface-active)] text-[var(--text-muted)]',
}

export const ProtectionAccordion: React.FC<{
  open: ProtKey | null
  states: Record<ProtKey, { state: ProtState; summary: string }>
  onToggle: (k: ProtKey) => void
  children: React.ReactNode
}> = ({ open, states, onToggle, children }) => {
  const { lang } = useT()
  const meta = (k: ProtKey) => protMeta(k, lang)
  return (
  <section className="dash-card overflow-hidden">
    {PROT_KEYS.map((k, i) => {
      const isOpen = open === k
      const s = states[k]
      return (
        <div key={k} className={`${i ? 'border-t border-[var(--bg-border)]' : ''} ${isOpen ? 'bg-[var(--bg-primary)]' : ''}`}>
          <button
            type="button"
            onClick={() => onToggle(k)}
            aria-expanded={isOpen}
            aria-controls={`prot-body-${k}`}
            className="w-full grid grid-cols-[36px_minmax(0,1fr)_18px] sm:grid-cols-[36px_minmax(0,1fr)_auto_auto_18px] gap-x-3.5 gap-y-2 items-center px-4 sm:px-[18px] py-3.5 text-left hover:bg-[var(--bg-hover)] cursor-pointer"
          >
            <ProtIcon k={k} state={s.state} size="lg" />
            <span className="min-w-0">
              <span className="flex flex-wrap items-baseline gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
                {meta(k).name}
                <span className="font-mono text-[11px] font-medium text-[var(--text-muted)]">{meta(k).tech}</span>
              </span>
              <span className="hidden sm:block text-[12.5px] text-[var(--text-muted)]">{meta(k).desc}</span>
            </span>
            <span className="hidden lg:block text-[12.5px] text-[var(--text-secondary)] text-right whitespace-nowrap">{s.summary}</span>
            <span className={`col-start-2 row-start-2 sm:col-start-auto sm:row-start-auto justify-self-start sm:justify-self-auto inline-flex items-center justify-center gap-1.5 h-6 px-2.5 min-w-[86px] rounded-full text-[12px] font-medium ${PILL[s.state]}`}>
              <span className="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
              {(lang === 'th' ? PROT_STATE_LABEL_TH : PROT_STATE_LABEL)[s.state]}
            </span>
            <ChevronDown size={16} className={`col-start-3 row-start-1 sm:col-start-auto sm:row-start-auto text-[var(--text-muted)] transition-transform ${isOpen ? 'rotate-180' : ''}`} />
          </button>
          {isOpen && (
            <div id={`prot-body-${k}`} className="px-4 sm:px-[18px] pb-[18px] sm:pl-[68px]">
              {children}
            </div>
          )}
        </div>
      )
    })}
  </section>
  )
}
