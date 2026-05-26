import React from 'react'
import { Card } from './Card'

export interface StatCardProps {
  label: string
  value: string | number
  color?: 'brand' | 'success' | 'warning' | 'danger' | 'info'
  icon?: React.ReactNode
  trend?: {
    value: number
    label: string
    isPositive: boolean
  }
}

export const StatCard: React.FC<StatCardProps> = ({ label, value, color = 'brand', icon, trend }) => {
  const colorMap = {
    brand: 'text-accent',
    success: 'text-success',
    warning: 'text-warning',
    danger: 'text-danger',
    info: 'text-info',
  }

  return (
    <Card className="glass-card-hover" noPadding>
      <div className="p-5 flex flex-col h-full">
        <div className="flex justify-between items-start mb-2">
          <span className="text-[12px] font-bold text-text-muted uppercase tracking-wider">{label}</span>
          {icon && <div className={`opacity-60 ${colorMap[color]}`}>{icon}</div>}
        </div>
        <div className={`text-[28px] font-bold leading-none mt-auto ${colorMap[color]}`}>
          {value}
        </div>
        {trend && (
          <div className="mt-3 flex items-center text-[12px]">
            <span className={`font-semibold mr-1.5 ${trend.isPositive ? 'text-success' : 'text-danger'}`}>
              {trend.isPositive ? '+' : ''}{trend.value}%
            </span>
            <span className="text-text-muted">{trend.label}</span>
          </div>
        )}
      </div>
    </Card>
  )
}
