import React, { useState } from 'react'
import { NotificationCenter } from '../NotificationCenter'
import { AISummaryModal } from '../AISummaryModal'
import { OriginSelector } from './OriginSelector'
import { Sparkles } from 'lucide-react'

interface TopBarProps {
  title: string
  subtitle?: string
  badge?: React.ReactNode
  action?: React.ReactNode
  // The page filters its data by origin: show the origin scope picker and
  // the AI traffic summary. Off by default, so pages that do not read the
  // origin filter (devices, support, rules...) do not show a control that
  // changes nothing.
  scope?: boolean
}

export const TopBar: React.FC<TopBarProps> = ({ title, subtitle, badge, action, scope = false }) => {
  const [isAiModalOpen, setIsAiModalOpen] = useState(false)

  return (
    // Side by side only from xl: below that the action row (origin scope,
    // AI summary, page actions) is wide enough to squeeze the title into a
    // column a word or two wide.
    <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 mb-6 pb-4 border-b border-[var(--bg-border-subtle)]">
      <div className="min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <h1 className="text-[21px] font-semibold text-[var(--text-primary)] tracking-tight m-0">
            {title}
          </h1>
          {badge}
        </div>
        {subtitle && (
          <p className="text-[13px] text-[var(--text-muted)] m-0 mt-1 max-w-[72ch]">
            {subtitle}
          </p>
        )}
      </div>
      <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
        {scope && (
          <>
            <OriginSelector />
            <button
              type="button"
              onClick={() => setIsAiModalOpen(true)}
              className="h-9 px-3 rounded-lg bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--bg-border)] text-[12.5px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
              title="Summarise traffic and threats for a time range"
            >
              <Sparkles size={14} className="text-indigo-600 dark:text-indigo-400" aria-hidden="true" />
              <span className="hidden sm:inline">AI summary</span>
              <span className="sm:hidden sr-only">AI summary</span>
            </button>
          </>
        )}

        {action}

        {/* The one entry point to alerts on every page. */}
        <NotificationCenter />
      </div>

      {scope && <AISummaryModal isOpen={isAiModalOpen} onClose={() => setIsAiModalOpen(false)} />}
    </div>
  )
}
