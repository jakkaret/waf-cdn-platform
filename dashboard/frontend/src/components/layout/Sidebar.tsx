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
  Server
} from 'lucide-react'

export const Sidebar: React.FC = () => {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const menu = [
    { label: 'Overview', path: '/', icon: <LayoutDashboard size={20} />, roles: ['admin', 'viewer'] },
    { label: 'Origin Servers', path: '/origins', icon: <Server size={20} />, roles: ['admin', 'viewer'] },
    { label: 'Attack Logs', path: '/logs', icon: <ListFilter size={20} />, roles: ['admin', 'viewer'] },
    { label: 'Custom Rules', path: '/rules', icon: <ShieldAlert size={20} />, roles: ['admin', 'viewer'] },
    { label: 'Alerts', path: '/alerts', icon: <Bell size={20} />, roles: ['admin', 'viewer'] },
    { label: 'CDN Monitor', path: '/cdn', icon: <Globe size={20} />, roles: ['admin', 'viewer'] },
    { label: 'Users & Roles', path: '/users', icon: <Users size={20} />, roles: ['admin'] },
  ]

  const visibleMenu = menu.filter(item => user && item.roles.includes(user.role))

  return (
    <div className="w-[260px] gradient-sidebar flex flex-col h-screen fixed left-0 top-0 border-r border-white/5">
      <div className="p-6 pb-2">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl gradient-brand flex items-center justify-center font-bold text-white text-xl shadow-[0_4px_12px_rgba(102,126,234,0.4)]">
            W
          </div>
          <div>
            <h2 className="text-[18px] font-bold tracking-wide text-white m-0 leading-tight">WAF</h2>
            <span className="text-[11px] text-accent-light font-medium tracking-widest uppercase">Security</span>
          </div>
        </div>
      </div>

      <div className="mt-8 px-4 flex-1">
        <p className="text-[11px] font-bold text-text-muted uppercase tracking-[1px] mb-3 px-3">Menu</p>
        <div className="flex flex-col gap-1">
          {visibleMenu.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-[14px] font-medium transition-all ${
                  isActive
                    ? 'bg-accent/10 text-accent-light'
                    : 'text-text-muted hover:bg-white/5 hover:text-text-primary'
                }`
              }
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </div>
      </div>

      <div className="p-4 border-t border-white/5">
        <div className="flex items-center gap-3 px-3 py-2 mb-2">
          <div className="w-9 h-9 rounded-full bg-white/10 flex items-center justify-center text-sm font-bold text-white uppercase overflow-hidden">
            {user?.avatar_url ? (
              <img src={user.avatar_url} alt="avatar" className="w-full h-full object-cover" />
            ) : (
              user?.username?.charAt(0) || 'U'
            )}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[13px] font-bold text-white m-0 truncate">{user?.username}</p>
            <p className="text-[11.5px] text-accent-light uppercase tracking-wider m-0">{user?.role}</p>
          </div>
        </div>
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 px-3 py-2.5 w-full rounded-lg text-[13.5px] font-medium text-text-muted hover:bg-danger/10 hover:text-danger transition-colors"
        >
          <LogOut size={18} />
          Sign Out
        </button>
      </div>
    </div>
  )
}
