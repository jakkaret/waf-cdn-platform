import React from 'react'

interface TopBarProps {
  title: string
  subtitle?: string
  action?: React.ReactNode
}

export const TopBar: React.FC<TopBarProps> = ({ title, subtitle, action }) => {
  return (
    <div className="flex justify-between items-end mb-8">
      <div>
        <h1 className="text-[22px] font-extrabold text-white tracking-tight font-heading m-0 mb-1 leading-tight">
          {title}
        </h1>
        {subtitle && (
          <p className="text-[13px] text-white/30 m-0 font-medium">{subtitle}</p>
        )}
        {/* Subtle accent underline */}
        <div className="mt-3 h-[2px] w-10 rounded-full bg-gradient-to-r from-accent to-accent-dark opacity-40" />
      </div>
      {action && <div>{action}</div>}
    </div>
  )
}
