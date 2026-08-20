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
  const styles: Record<BadgeColor, string> = {
    success: 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20 dark:text-emerald-400 dark:border-emerald-500/30',
    danger: 'bg-red-500/10 text-red-500 border-red-500/20 dark:text-red-400 dark:border-red-500/30',
    warning: 'bg-amber-500/10 text-amber-600 border-amber-500/20 dark:text-amber-400 dark:border-amber-500/30',
    info: 'bg-sky-500/10 text-sky-600 border-sky-500/20 dark:text-sky-400 dark:border-sky-500/30',
    blue: 'bg-sky-500/10 text-sky-600 border-sky-500/20 dark:text-sky-400 dark:border-sky-500/30',
    brand: 'bg-orange-500/10 text-orange-600 border-orange-500/25 dark:text-orange-400 dark:border-orange-500/35',
    purple: 'bg-violet-500/10 text-violet-600 border-violet-500/20 dark:text-violet-400 dark:border-violet-500/30',
    cyan: 'bg-cyan-500/10 text-cyan-600 border-cyan-500/20 dark:text-cyan-400 dark:border-cyan-500/30',
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

  const sizeClasses = size === 'sm' ? 'px-1.5 py-0.2 text-[10.5px]' : 'px-2 py-0.5 text-[11px]'

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md font-semibold tracking-tight border font-mono ${styles[color]} ${sizeClasses} ${className}`}
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
