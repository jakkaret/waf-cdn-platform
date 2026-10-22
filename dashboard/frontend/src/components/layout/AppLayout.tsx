import React, { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Menu, MailCheck, ArrowRight } from 'lucide-react'
import { useAuthStore } from '../../store/authStore'
import { isUnverified } from '../auth/EmailVerifyGate'
import { Sidebar } from './Sidebar'
import { NAV_SECTIONS, breadcrumbFor } from './navigation'
import { AICopilotWidget } from '../copilot/AICopilotWidget'

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const location = useLocation()
  const crumbs = breadcrumbFor(NAV_SECTIONS, location.pathname)
  const user = useAuthStore((s) => s.user)

  useEffect(() => {
    setMobileNavOpen(false)
  }, [location.pathname])

  return (
    <div className="flex min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)]">
      <Sidebar mobileOpen={mobileNavOpen} onMobileClose={() => setMobileNavOpen(false)} />
      <div className="flex-1 min-w-0 md:ml-[240px] flex flex-col">
        <div className="md:hidden sticky top-0 z-30 h-14 px-4 flex items-center gap-3 border-b border-[var(--bg-border)] bg-[var(--bg-surface)]">
          <button
            type="button"
            onClick={() => setMobileNavOpen(true)}
            aria-label="Open navigation menu"
            className="p-1.5 -ml-1.5 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
          >
            <Menu size={20} />
          </button>
          <span className="text-[13px] font-bold font-mono text-[var(--text-primary)]">Firewall WAF</span>
        </div>
        <main className="flex-1 p-5 sm:p-7 min-w-0">
          {isUnverified(user) && (
            <div className="max-w-[1560px] mx-auto mb-4 flex flex-col sm:flex-row sm:items-center gap-3 rounded-[10px] border border-[var(--bg-border)] bg-[var(--bg-surface)] px-4 py-3 text-[12.5px]">
              <MailCheck size={16} className="text-orange-500 shrink-0 hidden sm:block" />
              <p className="m-0 flex-1 text-[var(--text-secondary)] leading-5">
                <span className="font-semibold text-[var(--text-primary)]">ยืนยันอีเมล</span>{' '}
                <span className="font-mono">{user?.email}</span> เพื่อเพิ่มเว็บ เชิญทีม และใช้ฟีเจอร์ได้ครบ
              </p>
              <Link
                to={`/verify-email?next=${encodeURIComponent(location.pathname + location.search)}`}
                className="inline-flex items-center justify-center gap-1.5 shrink-0 rounded-md bg-[var(--accent)] hover:bg-[var(--accent-hover)] px-3 py-1.5 text-[12px] font-semibold text-white transition-colors"
              >
                ยืนยันอีเมล <ArrowRight size={13} />
              </Link>
            </div>
          )}
          {crumbs.length > 0 && (
            <nav aria-label="Breadcrumb" className="max-w-[1560px] mx-auto mb-3">
              <ol className="flex flex-wrap items-center gap-1.5 text-[12.5px] text-[var(--text-muted)]">
                {crumbs.map((crumb, i) => (
                  <li key={crumb} className="flex items-center gap-1.5">
                    <span aria-hidden="true">/</span>
                    <span
                      aria-current={i === crumbs.length - 1 ? 'page' : undefined}
                      className={i === crumbs.length - 1 ? 'text-[var(--text-primary)] font-medium' : ''}
                    >
                      {crumb}
                    </span>
                  </li>
                ))}
              </ol>
            </nav>
          )}
          <div className="max-w-[1560px] mx-auto animate-fade-in">
            {children}
          </div>
        </main>
      </div>
      <AICopilotWidget />
    </div>
  )
}

export default AppLayout
