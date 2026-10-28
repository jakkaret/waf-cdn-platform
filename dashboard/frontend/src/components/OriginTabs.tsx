import React, { useCallback, useEffect, useRef, useState } from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { ORIGIN_TABS, type OriginTabId } from './layout/navigation'

// The origin page's tab strip. Nine tabs do not fit narrow screens, so:
// on phones it is a select listing all of them; from sm up it is a tab row
// that scrolls sideways with a fade and arrow buttons on the side that still
// has tabs out of view, and keeps the active tab scrolled into view.

interface Props {
  active: OriginTabId
  onSelect: (id: OriginTabId) => void
  icons: Partial<Record<OriginTabId, React.ReactNode>>
}

export const OriginTabs: React.FC<Props> = ({ active, onSelect, icons }) => {
  const scroller = useRef<HTMLDivElement>(null)
  const [edges, setEdges] = useState({ left: false, right: false })

  const measure = useCallback(() => {
    const el = scroller.current
    if (!el) return
    setEdges({
      left: el.scrollLeft > 4,
      right: el.scrollLeft + el.clientWidth < el.scrollWidth - 4,
    })
  }, [])

  useEffect(() => {
    measure()
    const el = scroller.current
    if (!el) return
    const ro = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(measure) : null
    ro?.observe(el)
    el.addEventListener('scroll', measure, { passive: true })
    return () => {
      ro?.disconnect()
      el.removeEventListener('scroll', measure)
    }
  }, [measure])

  useEffect(() => {
    const tab = scroller.current?.querySelector<HTMLElement>(`[data-tab="${active}"]`)
    tab?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
  }, [active])

  const scrollBy = (dir: 1 | -1) => {
    const el = scroller.current
    if (el) el.scrollBy({ left: dir * el.clientWidth * 0.7, behavior: 'smooth' })
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft' && e.key !== 'Home' && e.key !== 'End') return
    e.preventDefault()
    const i = ORIGIN_TABS.findIndex((t) => t.id === active)
    const next =
      e.key === 'Home' ? 0 : e.key === 'End' ? ORIGIN_TABS.length - 1
      : (i + (e.key === 'ArrowRight' ? 1 : -1) + ORIGIN_TABS.length) % ORIGIN_TABS.length
    onSelect(ORIGIN_TABS[next].id)
    scroller.current?.querySelector<HTMLElement>(`[data-tab="${ORIGIN_TABS[next].id}"]`)?.focus()
  }

  return (
    <>
      <div className="sm:hidden">
        <label htmlFor="origin-tab-select" className="block text-[12px] font-medium text-[var(--text-muted)] mb-1">
          Section ({ORIGIN_TABS.findIndex((t) => t.id === active) + 1} of {ORIGIN_TABS.length})
        </label>
        <select
          id="origin-tab-select"
          value={active}
          onChange={(e) => onSelect(e.target.value as OriginTabId)}
          className="w-full dash-input h-10 text-[14px] cursor-pointer"
        >
          {ORIGIN_TABS.map((t) => (
            <option key={t.id} value={t.id}>{t.label}</option>
          ))}
        </select>
      </div>

      <div className="relative hidden sm:block border-b border-[var(--bg-border)]">
        {edges.left && (
          <button
            type="button"
            tabIndex={-1}
            aria-hidden="true"
            onClick={() => scrollBy(-1)}
            className="absolute left-0 top-0 bottom-px z-10 w-10 flex items-center justify-start bg-gradient-to-r from-[var(--bg-app)] via-[var(--bg-app)] to-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
          >
            <ChevronLeft size={16} />
          </button>
        )}
        <div
          ref={scroller}
          role="tablist"
          aria-label="Origin sections"
          onKeyDown={onKeyDown}
          className="flex gap-1 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
        >
          {ORIGIN_TABS.map((tab) => {
            const selected = tab.id === active
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                data-tab={tab.id}
                id={`origin-tab-${tab.id}`}
                aria-selected={selected}
                aria-controls="origin-tab-panel"
                tabIndex={selected ? 0 : -1}
                onClick={() => onSelect(tab.id)}
                className={`flex items-center gap-2 px-3.5 py-2.5 text-[13px] border-b-2 -mb-px whitespace-nowrap transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent)] ${
                  selected
                    ? 'border-[var(--accent)] text-[var(--text-primary)] font-semibold'
                    : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--bg-border-hover)]'
                }`}
              >
                <span aria-hidden="true" className={selected ? 'text-[var(--accent)]' : 'text-[var(--text-muted)]'}>
                  {icons[tab.id]}
                </span>
                {tab.label}
              </button>
            )
          })}
        </div>
        {edges.right && (
          <button
            type="button"
            tabIndex={-1}
            aria-hidden="true"
            onClick={() => scrollBy(1)}
            className="absolute right-0 top-0 bottom-px z-10 w-12 flex items-center justify-end bg-gradient-to-l from-[var(--bg-app)] via-[var(--bg-app)] to-transparent text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
          >
            <ChevronRight size={16} />
          </button>
        )}
      </div>
    </>
  )
}

export default OriginTabs
