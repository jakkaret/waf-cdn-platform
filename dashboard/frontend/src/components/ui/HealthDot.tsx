import React from 'react'

interface HealthDotProps {
  status: 'online' | 'offline' | 'degraded' | 'syncing'
  size?: 'sm' | 'md'
}

export const HealthDot: React.FC<HealthDotProps> = ({ status, size = 'md' }) => {
  const styles = {
    online: 'bg-success shadow-[0_0_8px_rgba(104,211,145,0.6)] animate-pulse-dot',
    offline: 'bg-danger',
    degraded: 'bg-warning animate-pulse-dot',
    syncing: 'bg-info animate-pulse-dot',
  }

  const sizes = {
    sm: 'w-2 h-2',
    md: 'w-2.5 h-2.5',
  }

  return (
    <span className={`inline-block rounded-full ${sizes[size]} ${styles[status]}`} />
  )
}
