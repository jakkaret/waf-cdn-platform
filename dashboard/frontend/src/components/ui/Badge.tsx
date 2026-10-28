import React from 'react'

export type BadgeColor = 'success' | 'danger' | 'warning' | 'info' | 'blue' | 'gray' | 'brand' | 'purple' | 'cyan'

interface BadgeProps {
  children: React.ReactNode
  color?: BadgeColor
  className?: string
  dot?: boolean
  pulse?: boolean
  size?: 'sm' | 'md'
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  color = 'gray',
  className = '',
  dot = false,
  pulse = false,
  size = 'md',
}) => {
  // Light mode uses the -700/-800 shade for text: the -500/-600 ones on their
  // own 10% tint measured below 4.5:1. Every badge carries a word, so the
  // state never rests on color alone.
  const styles: Record<BadgeColor, string> = {
    success: 'bg-emerald-500/10 text-emerald-800 border-emerald-600/25 dark:text-emerald-300 dark:border-emerald-500/30',
    danger: 'bg-red-500/10 text-red-800 border-red-600/25 dark:text-red-300 dark:border-red-500/30',
    warning: 'bg-amber-500/10 text-amber-800 border-amber-600/25 dark:text-amber-300 dark:border-amber-500/30',
    info: 'bg-sky-500/10 text-sky-800 border-sky-600/25 dark:text-sky-300 dark:border-sky-500/30',
    blue: 'bg-sky-500/10 text-sky-800 border-sky-600/25 dark:text-sky-300 dark:border-sky-500/30',
    brand: 'bg-orange-500/10 text-orange-800 border-orange-600/25 dark:text-orange-300 dark:border-orange-500/35',
    purple: 'bg-violet-500/10 text-violet-800 border-violet-600/25 dark:text-violet-300 dark:border-violet-500/30',
    cyan: 'bg-cyan-500/10 text-cyan-800 border-cyan-600/25 dark:text-cyan-300 dark:border-cyan-500/30',
    gray: 'bg-[var(--bg-surface-elevated)] text-[var(--text-secondary)] border-[var(--bg-border)]',
  }

  const dotColors: Record<BadgeColor, string> = {
    success: 'bg-emerald-500',
    danger: 'bg-red-500',
    warning: 'bg-amber-500',
    info: 'bg-sky-500',
    blue: 'bg-sky-500',
    brand: 'bg-orange-500',
    purple: 'bg-violet-500',
    cyan: 'bg-cyan-500',
    gray: 'bg-[var(--text-muted)]',
  }

  const sizeClasses = size === 'sm' ? 'px-1.5 py-px text-[11px]' : 'px-2 py-0.5 text-[12px]'

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md font-medium border whitespace-nowrap ${styles[color]} ${sizeClasses} ${className}`}
    >
      {dot && (
        <span className="relative flex h-1.5 w-1.5 items-center justify-center shrink-0">
          {pulse && (
            <span
              className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${dotColors[color]}`}
            />
          )}
          <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${dotColors[color]}`} />
        </span>
      )}
      <span>{children}</span>
    </span>
  )
}
