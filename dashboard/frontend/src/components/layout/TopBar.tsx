import React from 'react'
import { ThemeToggle } from '../ui/ThemeToggle'

interface TopBarProps {
  title: string
  subtitle?: string
  badge?: React.ReactNode
  action?: React.ReactNode
}

export const TopBar: React.FC<TopBarProps> = ({ title, subtitle, badge, action }) => (
  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 pb-4 border-b border-[var(--bg-border-subtle)]">
    <div>
      <div className="flex items-center gap-3 flex-wrap">
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
      {action}
      <ThemeToggle />
    </div>
  </div>
)
