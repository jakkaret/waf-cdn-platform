import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../store/authStore'
import {
  LayoutDashboard,
  ShieldAlert,
  ListFilter,
  Bell,
  Globe,
  Users,
  LogOut,
  Server,
  Brain,
  Sparkles,
  Ban,
  Gauge,
  Settings as SettingsIcon,
} from 'lucide-react'

export const Sidebar: React.FC = () => {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const sections = [
    {
      label: 'Monitoring & Core',
      items: [
        { label: 'Security Dashboard', path: '/', icon: <LayoutDashboard size={15} />, roles: ['admin', 'viewer'] },
        { label: 'Traffic Logs', path: '/logs', icon: <ListFilter size={15} />, roles: ['admin', 'viewer'] },
        { label: 'Origin Servers', path: '/origins', icon: <Server size={15} />, roles: ['admin', 'viewer'] },
      ],
    },
    {
      label: 'Security & Access Control',
      items: [
        { label: 'WAF Rules', path: '/rules', icon: <ShieldAlert size={15} />, roles: ['admin', 'viewer'] },
        { label: 'IP Access List', path: '/ip-rules', icon: <Ban size={15} />, roles: ['admin', 'viewer'] },
        { label: 'Rate Limiting', path: '/rate-limits', icon: <Gauge size={15} />, roles: ['admin', 'viewer'] },
        { label: 'ML Anomaly Rules', path: '/ml-rules', icon: <Sparkles size={15} />, roles: ['admin', 'viewer'] },
        { label: 'AI Security Analyst', path: '/ml-analyst', icon: <Brain size={15} />, roles: ['admin', 'viewer'] },
        { label: 'Alert Center', path: '/alerts', icon: <Bell size={15} />, roles: ['admin', 'viewer'] },
      ],
    },
    {
      label: 'Edge & Delivery',
      items: [
        { label: 'CDN Edge Nodes', path: '/cdn', icon: <Globe size={15} />, roles: ['admin', 'viewer'] },
      ],
    },
    {
      label: 'Administration & System',
      items: [
        { label: 'Access Control', path: '/users', icon: <Users size={15} />, roles: ['admin'] },
        { label: 'System Settings', path: '/settings', icon: <SettingsIcon size={15} />, roles: ['admin', 'viewer'] },
      ],
    },
  ]

  return (
    <aside className="w-[240px] bg-[var(--bg-surface)] flex flex-col h-screen fixed left-0 top-0 border-r border-[var(--bg-border)] z-50 select-none">
      {/* Brand Header */}
      <div className="h-16 px-4 flex items-center justify-between border-b border-[var(--bg-border)] bg-[var(--bg-surface)]">
        <div className="flex items-center gap-2.5">
          <img src="/firewall.png" alt="Firewall" className="w-8 h-8 object-contain rounded-lg drop-shadow-md" />
          <div>
            <div className="flex items-center gap-1.5">
              <span className="text-[14px] font-bold text-[var(--text-primary)] tracking-tight font-mono">
                Firewall WAF
              </span>
              <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-orange-500/10 text-orange-500 border border-orange-500/20 uppercase font-mono">
                EDGE
              </span>
            </div>
            <div className="text-[10.5px] text-[var(--text-muted)] tracking-tight flex items-center gap-1 mt-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
              <span>ModSec CRS 4.0</span>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Groups */}
      <nav className="flex-1 overflow-y-auto py-4 px-2.5 space-y-5">
        {sections.map((section) => {
          const items = section.items.filter((item) => user && item.roles.includes(user.role))
          if (!items.length) return null
          return (
            <div key={section.label}>
              <p className="text-[10px] font-bold text-[var(--text-dim)] uppercase tracking-wider px-3 mb-1 font-mono">
                {section.label}
              </p>
              <div className="space-y-0.5">
                {items.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === '/'}
                    className={({ isActive }) =>
                      `group flex items-center gap-2.5 px-3 py-2 text-[12.5px] rounded-md transition-all duration-150 relative ${
                        isActive
                          ? 'bg-orange-500/10 text-orange-500 font-semibold dark:text-orange-400 border border-orange-500/20'
                          : 'text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)]'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <span
                          className={`transition-colors ${
                            isActive
                              ? 'text-orange-500 dark:text-orange-400'
                              : 'text-[var(--text-muted)] group-hover:text-[var(--text-primary)]'
                          }`}
                        >
                          {item.icon}
                        </span>
                        <span className="font-mono">{item.label}</span>
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          )
        })}
      </nav>

      {/* Footer Profile & Logout */}
      <div className="p-3 border-t border-[var(--bg-border)] bg-[var(--bg-surface)]">
        <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-app)] border border-[var(--bg-border-subtle)]">
          <div className="flex items-center gap-2.5 overflow-hidden">
            <div className="w-7 h-7 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-mono text-[11px] font-bold shrink-0">
              {(user?.username || 'U')[0].toUpperCase()}
            </div>
            <div className="truncate">
              <p className="text-[12px] font-medium text-[var(--text-primary)] truncate m-0 font-mono">
                {user?.username || 'User'}
              </p>
              <span className="text-[10px] text-[var(--text-muted)] uppercase font-mono tracking-wider">
                {user?.role || 'Viewer'}
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="p-1.5 rounded text-[var(--text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer"
            title="Sign Out"
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </aside>
  )
}
