import React from 'react'

export interface StatCardProps {
  label: string
  value: string | number
  color?: 'blue' | 'red' | 'green' | 'amber' | 'slate' | 'brand' | 'success' | 'warning' | 'danger' | 'info' | 'purple' | 'cyan'
  icon?: React.ReactNode
  sub?: string
  badgeText?: string
  trend?: { value: number; label: string; isPositive: boolean }
}

const colorConfig: Record<
  string,
  {
    borderAccent: string
    iconBg: string
    iconColor: string
    valueColor: string
  }
> = {
  brand: {
    borderAccent: 'before:bg-orange-500',
    iconBg: 'bg-orange-500/10 text-orange-500',
    iconColor: 'text-orange-500',
    valueColor: 'text-[var(--text-primary)]',
  },
  blue: {
    borderAccent: 'before:bg-sky-500',
    iconBg: 'bg-sky-500/10 text-sky-500',
    iconColor: 'text-sky-500',
    valueColor: 'text-[var(--text-primary)]',
  },
  info: {
    borderAccent: 'before:bg-sky-500',
    iconBg: 'bg-sky-500/10 text-sky-500',
    iconColor: 'text-sky-500',
    valueColor: 'text-[var(--text-primary)]',
  },
  red: {
    borderAccent: 'before:bg-red-500',
    iconBg: 'bg-red-500/10 text-red-500',
    iconColor: 'text-red-500',
    valueColor: 'text-red-500',
  },
  danger: {
    borderAccent: 'before:bg-red-500',
    iconBg: 'bg-red-500/10 text-red-500',
    iconColor: 'text-red-500',
    valueColor: 'text-red-500',
  },
  green: {
    borderAccent: 'before:bg-emerald-500',
    iconBg: 'bg-emerald-500/10 text-emerald-500',
    iconColor: 'text-emerald-500',
    valueColor: 'text-emerald-500',
  },
  success: {
    borderAccent: 'before:bg-emerald-500',
    iconBg: 'bg-emerald-500/10 text-emerald-500',
    iconColor: 'text-emerald-500',
    valueColor: 'text-emerald-500',
  },
  amber: {
    borderAccent: 'before:bg-amber-500',
    iconBg: 'bg-amber-500/10 text-amber-500',
    iconColor: 'text-amber-500',
    valueColor: 'text-amber-500',
  },
  warning: {
    borderAccent: 'before:bg-amber-500',
    iconBg: 'bg-amber-500/10 text-amber-500',
    iconColor: 'text-amber-500',
    valueColor: 'text-amber-500',
  },
  purple: {
    borderAccent: 'before:bg-violet-500',
    iconBg: 'bg-violet-500/10 text-violet-500',
    iconColor: 'text-violet-500',
    valueColor: 'text-violet-400',
  },
  cyan: {
    borderAccent: 'before:bg-cyan-500',
    iconBg: 'bg-cyan-500/10 text-cyan-500',
    iconColor: 'text-cyan-500',
    valueColor: 'text-cyan-400',
  },
  slate: {
    borderAccent: 'before:bg-slate-500',
    iconBg: 'bg-slate-500/10 text-slate-400',
    iconColor: 'text-slate-400',
    valueColor: 'text-[var(--text-primary)]',
  },
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  color = 'blue',
  icon,
  sub,
  badgeText,
  trend,
}) => {
  const conf = colorConfig[color] || colorConfig.blue

  return (
    <div
      className={`dash-card relative overflow-hidden p-4 sm:p-5 flex flex-col justify-between before:absolute before:left-0 before:top-0 before:bottom-0 before:w-[3px] ${conf.borderAccent}`}
    >
      <div>
        <div className="flex items-center justify-between gap-2 mb-2">
          <span className="text-[12px] font-semibold tracking-tight text-[var(--text-secondary)] uppercase">
            {label}
          </span>
          {icon && (
            <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${conf.iconBg}`}>
              {icon}
            </div>
          )}
        </div>

        <div className="flex items-baseline gap-2">
          <span className={`text-[24px] sm:text-[26px] font-bold font-mono tracking-tight leading-none ${conf.valueColor}`}>
            {value}
          </span>
          {badgeText && (
            <span className="text-[11px] font-semibold px-1.5 py-0.5 rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[var(--text-secondary)] font-mono">
              {badgeText}
            </span>
          )}
        </div>
      </div>

      {(sub || trend) && (
        <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] flex items-center justify-between text-[11.5px]">
          {sub && <span className="text-[var(--text-muted)] font-mono truncate">{sub}</span>}
          {trend && (
            <div className="flex items-center gap-1 font-mono shrink-0 ml-auto">
              <span className={`font-semibold ${trend.isPositive ? 'text-emerald-500' : 'text-red-500'}`}>
                {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
              </span>
              <span className="text-[var(--text-dim)]">{trend.label}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
