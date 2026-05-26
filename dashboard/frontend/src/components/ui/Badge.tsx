import React from 'react'

type BadgeColor = 'success' | 'danger' | 'warning' | 'info' | 'gray' | 'brand'

interface BadgeProps {
  children: React.ReactNode
  color?: BadgeColor
  className?: string
  dot?: boolean
}

export const Badge: React.FC<BadgeProps> = ({ children, color = 'gray', className = '', dot = false }) => {
  const styles = {
    success: 'bg-success/10 text-success border border-success/20',
    danger: 'bg-danger/10 text-danger border border-danger/20',
    warning: 'bg-warning/10 text-warning border border-warning/20',
    info: 'bg-info/10 text-info border border-info/20',
    brand: 'bg-accent/10 text-accent-light border border-accent/20',
    gray: 'bg-white/5 text-text-muted border border-white/10',
  }

  const dotColors = {
    success: 'bg-success',
    danger: 'bg-danger',
    warning: 'bg-warning',
    info: 'bg-info',
    brand: 'bg-accent',
    gray: 'bg-gray-400',
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[20px] text-[11.5px] font-semibold whitespace-nowrap ${styles[color]} ${className}`}>
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${dotColors[color]}`} />}
      {children}
    </span>
  )
}
