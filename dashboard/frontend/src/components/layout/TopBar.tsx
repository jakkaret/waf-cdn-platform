import React, { useState } from 'react'
import { ThemeToggle } from '../ui/ThemeToggle'
import { NotificationCenter } from '../NotificationCenter'
import { AISummaryModal } from '../AISummaryModal'
import { OriginSelector } from './OriginSelector'
import { Sparkles } from 'lucide-react'

interface TopBarProps {
  title: string
  subtitle?: string
  badge?: React.ReactNode
  action?: React.ReactNode
}

export const TopBar: React.FC<TopBarProps> = ({ title, subtitle, badge, action }) => {
  const [isAiModalOpen, setIsAiModalOpen] = useState(false)

  return (
    // Side by side only from xl: below that the action row (origin scope,
    // AI summary, page actions) is wide enough to squeeze the title into a
    // column a word or two wide.
    <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 mb-6 pb-4 border-b border-[var(--bg-border-subtle)]">
      <div className="min-w-0">
        <div className="flex items-center gap-2.5 flex-wrap">
          <img src="/itkku-logo.png" alt="IT KKU" className="w-7 h-7 object-contain" />
          <h1 className="text-[20px] font-bold text-[var(--text-primary)] tracking-tight m-0 font-mono">
            {title}
          </h1>
          {badge}
        </div>
        {subtitle && (
          <p className="text-[12.5px] text-[var(--text-muted)] m-0 mt-1">
            {subtitle}
          </p>
        )}
      </div>
      <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
        {/* Global Origin Scope Filter */}
        <OriginSelector />

        {/* AI Threat Summary Button */}
        <button
          type="button"
          onClick={() => setIsAiModalOpen(true)}
          className="px-3 py-1.8 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 hover:text-indigo-200 border border-indigo-500/20 text-[12px] font-mono font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm hover:shadow-indigo-500/10"
          title="AI Threat Range Summary"
        >
          <Sparkles size={14} className="text-indigo-400" />
          <span className="hidden sm:inline">AI Summary</span>
        </button>

        {/* Real-time Notification Center */}
        <NotificationCenter />

        {action}
        <ThemeToggle />
      </div>

      {/* AI Summary Modal */}
      <AISummaryModal isOpen={isAiModalOpen} onClose={() => setIsAiModalOpen(false)} />
    </div>
  )
}
