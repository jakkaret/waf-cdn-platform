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

  const glowMap = {
    brand: 'rgba(102,126,234,0.06)',
    success: 'rgba(104,211,145,0.06)',
    warning: 'rgba(246,173,85,0.06)',
    danger: 'rgba(252,129,129,0.06)',
    info: 'rgba(118,228,247,0.06)',
  }

  const iconBgMap = {
    brand: 'bg-accent/[0.08] text-accent',
    success: 'bg-success/[0.08] text-success',
    warning: 'bg-warning/[0.08] text-warning',
    danger: 'bg-danger/[0.08] text-danger',
    info: 'bg-info/[0.08] text-info',
  }

  return (
    <Card className="glass-card-hover relative overflow-hidden" noPadding>
      {/* Background glow */}
      <div
        className="absolute top-0 right-0 w-24 h-24 rounded-full blur-[40px] pointer-events-none"
        style={{ backgroundColor: glowMap[color] }}
      />
      <div className="p-5 flex flex-col h-full relative z-10">
        <div className="flex justify-between items-start mb-3">
          <span className="text-[11px] font-bold text-white/25 uppercase tracking-[0.08em]">{label}</span>
          {icon && (
            <div className={`w-8 h-8 rounded-[10px] flex items-center justify-center ${iconBgMap[color]}`}>
              {icon}
            </div>
          )}
        </div>
        <div className={`text-[26px] font-extrabold leading-none mt-auto tracking-tight font-heading ${colorMap[color]}`}>
          {value}
        </div>
        {trend && (
          <div className="mt-3 pt-3 border-t border-white/[0.04] flex items-center text-[11px]">
            <span className={`font-bold mr-1.5 ${trend.isPositive ? 'text-success' : 'text-danger'}`}>
              {trend.isPositive ? '↑' : '↓'} {Math.abs(trend.value)}%
            </span>
            <span className="text-white/20 font-medium">{trend.label}</span>
          </div>
        )}
      </div>
    </Card>
  )
}
