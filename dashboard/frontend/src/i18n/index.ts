import { create } from 'zustand'
import { persist } from 'zustand/middleware'

// Two languages only, so each string sits next to its translation in the
// component: t('Save', 'บันทึก'). No key files to keep in sync, and the
// reviewer sees both wordings side by side. Product terms (WAF, CDN, origin,
// rate limit, tunnel, CRS...) stay in English in the Thai text on purpose:
// they are the words the user sees in the rest of the tooling and docs.

export type Lang = 'en' | 'th'

interface LangState {
  lang: Lang
  setLang: (lang: Lang) => void
  toggleLang: () => void
}

const applyHtmlLang = (lang: Lang) => {
  if (typeof document !== 'undefined') document.documentElement.lang = lang
}

export const useLangStore = create<LangState>()(
  persist(
    (set, get) => ({
      lang: 'th',
      setLang: (lang) => {
        applyHtmlLang(lang)
        set({ lang })
      },
      toggleLang: () => get().setLang(get().lang === 'th' ? 'en' : 'th'),
    }),
    {
      name: 'waf_lang',
      onRehydrateStorage: () => (state) => {
        if (state) applyHtmlLang(state.lang)
      },
    },
  ),
)

export type Translate = <T>(en: T, th: T) => T

const pick = (lang: Lang): Translate => (en, th) => (lang === 'th' ? th : en)

// Outside React (toasts fired from callbacks, helpers in lib/): reads the
// language at call time. Components should use useT() so they re-render
// when the language changes.
export const tr: Translate = (en, th) => pick(useLangStore.getState().lang)(en, th)

export const currentLang = (): Lang => useLangStore.getState().lang

// BCP 47 tag for toLocaleString/Intl. Thai keeps the Gregorian calendar:
// log timestamps are compared with server logs, a Buddhist year would not match.
export const localeOf = (lang: Lang) => (lang === 'th' ? 'th-TH-u-ca-gregory' : 'en-GB')

// Severity words shown next to alerts and rules.
const SEVERITY_TH: Record<string, string> = {
  CRITICAL: 'วิกฤต',
  HIGH: 'สูง',
  MEDIUM: 'ปานกลาง',
  LOW: 'ต่ำ',
  INFO: 'ข้อมูล',
  UNKNOWN: 'ไม่ทราบ',
}

// "CRITICAL" -> "Critical" / "วิกฤต". Unknown words come back as given.
export const severityLabel = (sev: string, lang: Lang): string => {
  const up = (sev || '').toUpperCase()
  if (lang === 'th') return SEVERITY_TH[up] ?? sev
  return up ? up.charAt(0) + up.slice(1).toLowerCase() : sev
}

export function useT() {
  const lang = useLangStore((s) => s.lang)
  return { t: pick(lang), lang, locale: localeOf(lang) }
}
