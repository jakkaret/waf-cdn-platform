import React from 'react'

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
  noPadding?: boolean
  variant?: 'default' | 'elevated' | 'outlined'
}

export const Card: React.FC<CardProps> = ({ children, className = '', noPadding = false, variant = 'default', ...props }) => {
  const variants = {
    default: 'glass-card',
    elevated: 'glass-card glass-card-hover gradient-border',
    outlined: 'bg-transparent border border-white/[0.06] rounded-2xl',
  }

  return (
    <div
      className={`${variants[variant]} ${noPadding ? '' : 'p-6'} ${className}`}
      {...props}
    >
      {children}
    </div>
  )
}

export const CardHeader: React.FC<{ title: string; subtitle?: string; action?: React.ReactNode; className?: string }> = ({
  title,
  subtitle,
  action,
  className = ''
}) => (
  <div className={`flex justify-between items-start mb-6 ${className}`}>
    <div>
      <h3 className="text-[14px] font-bold text-white/90 m-0 leading-tight font-heading tracking-tight">{title}</h3>
      {subtitle && <p className="text-[12px] text-white/25 mt-1.5 mb-0 font-medium">{subtitle}</p>}
    </div>
    {action && <div>{action}</div>}
  </div>
)
