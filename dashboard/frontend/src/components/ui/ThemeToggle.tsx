import React, { useEffect } from 'react'
import { useThemeStore } from '../../store/themeStore'
import { Sun, Moon } from 'lucide-react'

export const ThemeToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { theme, toggleTheme } = useThemeStore()

  useEffect(() => {
    const root = document.documentElement
    root.classList.remove('dark', 'light')
    root.classList.add(theme)
  }, [theme])

  return (
    <button
      onClick={toggleTheme}
      type="button"
      className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[12px] font-medium rounded-md border transition-all duration-150 cursor-pointer
        ${
          theme === 'dark'
            ? 'bg-[var(--bg-surface-elevated)] text-[var(--text-secondary)] border-[var(--bg-border)] hover:text-[var(--text-primary)] hover:border-[var(--bg-border-hover)]'
            : 'bg-white text-[var(--text-secondary)] border-[var(--bg-border)] hover:text-[var(--text-primary)] shadow-sm'
        } ${className}`}
      title={theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
    >
      {theme === 'dark' ? (
        <Sun size={13.5} className="text-amber-400" />
      ) : (
        <Moon size={13.5} className="text-slate-600" />
      )}
      <span className="hidden sm:inline font-mono">{theme === 'dark' ? 'Dark' : 'Light'}</span>
    </button>
  )
}
