import React from 'react'

interface TopBarProps {
  title: string
  subtitle?: string
  action?: React.ReactNode
}

export const TopBar: React.FC<TopBarProps> = ({ title, subtitle, action }) => {
  return (
    <div className="flex justify-between items-end mb-7">
      <div>
        <h1 className="text-[24px] font-bold text-text-primary m-0 mb-1">{title}</h1>
        {subtitle && <p className="text-[13.5px] text-text-muted m-0">{subtitle}</p>}
      </div>
      {action && <div>{action}</div>}
    </div>
  )
}
