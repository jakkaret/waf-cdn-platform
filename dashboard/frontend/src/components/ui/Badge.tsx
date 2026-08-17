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
    success: 'bg-success/[0.08] text-success border border-success/[0.12]',
    danger: 'bg-danger/[0.08] text-danger border border-danger/[0.12]',
    warning: 'bg-warning/[0.08] text-warning border border-warning/[0.12]',
    info: 'bg-info/[0.08] text-info border border-info/[0.12]',
    brand: 'bg-accent/[0.08] text-accent-light border border-accent/[0.12]',
    gray: 'bg-white/[0.04] text-white/40 border border-white/[0.06]',
  }

  const dotColors = {
    success: 'bg-success shadow-[0_0_4px_rgba(104,211,145,0.4)]',
    danger: 'bg-danger shadow-[0_0_4px_rgba(252,129,129,0.4)]',
    warning: 'bg-warning shadow-[0_0_4px_rgba(246,173,85,0.4)]',
    info: 'bg-info shadow-[0_0_4px_rgba(118,228,247,0.4)]',
    brand: 'bg-accent shadow-[0_0_4px_rgba(102,126,234,0.4)]',
    gray: 'bg-white/30',
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-[3px] rounded-md text-[10.5px] font-bold whitespace-nowrap tracking-wide uppercase ${styles[color]} ${className}`}>
      {dot && <span className={`w-1.5 h-1.5 rounded-full ${dotColors[color]}`} />}
      {children}
    </span>
  )
}
