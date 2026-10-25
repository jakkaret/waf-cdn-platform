import React from 'react'
import { Link } from 'react-router-dom'
import { ThemeToggle } from '../ui/ThemeToggle'

// Page frame of the sign-in family (same header as Login and Register) for
// the pages around them: email verification and password reset.
export const AuthShell: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div className="min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)] flex flex-col">
    <header className="border-b border-[var(--bg-border-subtle)] bg-[var(--bg-app)]/85 backdrop-blur">
      <div className="max-w-7xl mx-auto flex justify-between items-center px-4 sm:px-8 py-4">
        <Link to="/" className="flex items-center gap-2.5 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500/50">
          <img src="/itkku-logo.png" alt="IT KKU" className="w-9 h-9 object-contain" />
          <div className="leading-tight">
            <span className="block font-bold text-[15px] tracking-tight"><span className="text-[#a34830] dark:text-[#d0674a]">IT</span> <span className="text-[#89898a] dark:text-[#a3a3a4]">KKU</span></span>
            <span className="block text-[10px] font-mono uppercase tracking-[0.12em] text-[var(--text-muted)]">WAF &amp; CDN</span>
          </div>
        </Link>
        <ThemeToggle />
      </div>
    </header>
    <main className="flex-1 mx-auto max-w-5xl px-4 sm:px-6 lg:px-8 py-10 lg:py-14 w-full">{children}</main>
  </div>
)

export default AuthShell
