import React from 'react'

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode
  noPadding?: boolean
}

export const Card: React.FC<CardProps> = ({ children, className = '', noPadding = false, ...props }) => {
  return (
    <div
      className={`glass-card ${noPadding ? '' : 'p-6'} ${className}`}
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
      <h3 className="text-[15px] font-bold text-text-primary m-0 leading-tight">{title}</h3>
      {subtitle && <p className="text-[13px] text-text-muted mt-1 mb-0">{subtitle}</p>}
    </div>
    {action && <div>{action}</div>}
  </div>
)
