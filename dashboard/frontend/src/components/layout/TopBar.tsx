import React, { useState } from 'react'
import { ThemeToggle } from '../ui/ThemeToggle'
import { NotificationCenter } from '../NotificationCenter'
import { AISummaryModal } from '../AISummaryModal'
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
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-[var(--bg-border-subtle)]">
      <div>
        <div className="flex items-center gap-2.5 flex-wrap">
          <img src="/firewall.png" alt="Firewall" className="w-7 h-7 object-contain drop-shadow-md rounded-md" />
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
        {/* AI Threat Summary Button */}
        <button
          type="button"
          onClick={() => setIsAiModalOpen(true)}
          className="px-3 py-1.8 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 hover:text-indigo-200 border border-indigo-500/20 text-[12px] font-mono font-semibold flex items-center gap-1.5 transition-all cursor-pointer shadow-sm hover:shadow-indigo-500/10"
          title="AI Threat Range Summary"
        >
          <Sparkles size={14} className="text-indigo-400" />
          <span>AI Summary</span>
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
