import React from 'react'

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
  noPadding?: boolean
}

export const Card: React.FC<CardProps> = ({ children, className = '', noPadding = false, ...props }) => (
  <div className={`dash-card ${noPadding ? '' : 'p-4 sm:p-5'} ${className}`} {...props}>
    {children}
  </div>
)

export const CardHeader: React.FC<{
  title: string
  subtitle?: string
  action?: React.ReactNode
  className?: string
}> = ({ title, subtitle, action, className = '' }) => (
  <div className={`flex items-center justify-between pb-3.5 mb-4 border-b border-[var(--bg-border-subtle)] ${className}`}>
    <div>
      <h3 className="text-[13.5px] font-semibold text-[var(--text-primary)] tracking-tight m-0">{title}</h3>
      {subtitle && <p className="text-[12px] text-[var(--text-muted)] mt-0.5 mb-0">{subtitle}</p>}
    </div>
    {action && <div className="shrink-0 flex items-center gap-2">{action}</div>}
  </div>
)
