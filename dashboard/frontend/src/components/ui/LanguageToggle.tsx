import React from 'react'
import { Languages } from 'lucide-react'
import { useLangStore } from '../../i18n'

// TH | EN switch. Both options are visible so the user sees which language
// is on and which one a click gives, in either language.
export const LanguageToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const lang = useLangStore((s) => s.lang)
  const setLang = useLangStore((s) => s.setLang)

  const option = (value: 'th' | 'en', label: string, name: string) => {
    const active = lang === value
    return (
      <button
        type="button"
        onClick={() => setLang(value)}
        aria-pressed={active}
        lang={value}
        title={name}
        className={`h-full px-2 text-[12px] font-semibold rounded-[5px] transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
          active
            ? 'bg-[var(--accent-fill)] text-white'
            : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
        }`}
      >
        {label}
      </button>
    )
  }

  return (
    <div
      role="group"
      aria-label={lang === 'th' ? 'ภาษา' : 'Language'}
      className={`inline-flex items-center gap-0.5 h-9 p-[3px] rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] ${className}`}
    >
      <Languages size={14} aria-hidden="true" className="mx-1 text-[var(--text-muted)]" />
      {option('th', 'TH', 'ภาษาไทย')}
      {option('en', 'EN', 'English')}
    </div>
  )
}

export default LanguageToggle
