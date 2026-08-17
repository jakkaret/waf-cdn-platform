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
  Sparkles
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
      label: 'Main',
      items: [
        { label: 'Overview', path: '/', icon: <LayoutDashboard size={18} />, roles: ['admin', 'viewer'] },
        { label: 'Origin Servers', path: '/origins', icon: <Server size={18} />, roles: ['admin', 'viewer'] },
        { label: 'ML Analyst', path: '/ml-analyst', icon: <Brain size={18} />, roles: ['admin', 'viewer'] },
      ],
    },
    {
      label: 'Monitoring',
      items: [
        { label: 'Attack Logs', path: '/logs', icon: <ListFilter size={18} />, roles: ['admin', 'viewer'] },
        { label: 'Custom Rules', path: '/rules', icon: <ShieldAlert size={18} />, roles: ['admin', 'viewer'] },
        { label: 'ML Rules', path: '/ml-rules', icon: <Sparkles size={18} />, roles: ['admin', 'viewer'] },
        { label: 'Alerts', path: '/alerts', icon: <Bell size={18} />, roles: ['admin', 'viewer'] },
        { label: 'CDN Monitor', path: '/cdn', icon: <Globe size={18} />, roles: ['admin', 'viewer'] },
      ],
    },
    {
      label: 'Admin',
      items: [
        { label: 'Users & Roles', path: '/users', icon: <Users size={18} />, roles: ['admin'] },
      ],
    },
  ]

  return (
    <div className="w-[260px] gradient-sidebar flex flex-col h-screen fixed left-0 top-0 border-r border-white/[0.04]">
      {/* Logo */}
      <div className="px-6 pt-7 pb-1">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-[10px] gradient-brand flex items-center justify-center font-bold text-white text-lg shadow-glow relative">
            W
            {/* Subtle pulse ring */}
            <div className="absolute inset-0 rounded-[10px] gradient-brand opacity-0 animate-ping" style={{ animationDuration: '3s' }} />
          </div>
          <div>
            <h2 className="text-[16px] font-extrabold tracking-wide text-white m-0 leading-none font-heading">WAF</h2>
            <span className="text-[10px] text-accent-light/70 font-semibold tracking-[0.15em] uppercase">Security</span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="mt-7 px-3 flex-1 overflow-y-auto">
        {sections.map((section) => {
          const visibleItems = section.items.filter(item => user && item.roles.includes(user.role))
          if (visibleItems.length === 0) return null

          return (
            <div key={section.label} className="mb-5">
              <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.12em] mb-2 px-3">
                {section.label}
              </p>
              <div className="flex flex-col gap-0.5">
                {visibleItems.map((item) => (
                  <NavLink
                    key={item.path}
                    to={item.path}
                    end={item.path === '/'}
                    className={({ isActive }) =>
                      `group relative flex items-center gap-2.5 px-3 py-[9px] rounded-[10px] text-[13px] font-medium transition-all duration-200 ${
                        isActive
                          ? 'bg-accent/[0.08] text-accent-light'
                          : 'text-white/35 hover:text-white/60 hover:bg-white/[0.03]'
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {/* Active left accent bar */}
                        {isActive && (
                          <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-[16px] rounded-r-full bg-accent shadow-[0_0_8px_rgba(102,126,234,0.4)]" />
                        )}
                        <span className={`transition-transform duration-200 ${isActive ? '' : 'group-hover:scale-110'}`}>
                          {item.icon}
                        </span>
                        {item.label}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          )
        })}
      </div>

      {/* User section */}
      <div className="p-3 border-t border-white/[0.04]">
        <div className="flex items-center gap-2.5 px-3 py-2.5 rounded-[10px] bg-white/[0.02] border border-white/[0.04] mb-2">
          <div className="w-8 h-8 rounded-full bg-gradient-to-br from-accent/20 to-accent-dark/20 border border-accent/10 flex items-center justify-center text-[12px] font-bold text-accent-light uppercase overflow-hidden shrink-0">
            {user?.avatar_url ? (
              <img src={user.avatar_url} alt="avatar" className="w-full h-full object-cover rounded-full" />
            ) : (
              user?.username?.charAt(0) || 'U'
            )}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[12px] font-semibold text-white/70 m-0 truncate">{user?.username}</p>
            <p className="text-[10px] text-accent-light/50 uppercase tracking-[0.1em] m-0 font-semibold">{user?.role}</p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-2.5 px-3 py-2 w-full rounded-[10px] text-[12px] font-medium text-white/25 hover:bg-danger/[0.06] hover:text-danger/80 transition-all duration-200"
        >
          <LogOut size={15} />
          Sign Out
        </button>
      </div>
    </div>
  )
}
