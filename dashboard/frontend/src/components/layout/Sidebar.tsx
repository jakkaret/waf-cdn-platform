import React, { useEffect, useMemo, useRef, useState } from 'react'
import { NavLink as RouterNavLink, useLocation, useNavigate } from 'react-router-dom'
import { useAuthStore } from '../../store/authStore'
import { api } from '../../api/axios'
import { ChevronRight, LogOut, Search, X } from 'lucide-react'
import { CRS_VERSION } from '../../lib/crsVersion'
import { isOperator, platformRoleLabel } from '../../lib/permissions'
import {
  NAV_SECTIONS,
  activeGroupId,
  filterSections,
  flattenLinks,
  isPathActive,
  visibleSections,
  type NavGroup,
  type NavLink,
} from './navigation'

interface SidebarProps {
  mobileOpen?: boolean
  onMobileClose?: () => void
}

// Which groups the user left open. A per-browser convenience only, so every
// storage access is guarded: private windows and blocked storage throw.
const EXPANDED_KEY = 'waf_nav_expanded'

function loadExpanded(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(EXPANDED_KEY)
    const parsed = raw ? JSON.parse(raw) : null
    return parsed && typeof parsed === 'object' ? parsed : {}
  } catch {
    return {}
  }
}

function saveExpanded(value: Record<string, boolean>) {
  try {
    localStorage.setItem(EXPANDED_KEY, JSON.stringify(value))
  } catch {
    // Storage unavailable; the sidebar still works for this page view.
  }
}

const isMac = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)

// Row styling follows BunkerWeb: roomy rows, a tinted fill on the current
// page and a bar on the sidebar's right edge (-right-3 = the nav padding).
const rowBase =
  'relative flex w-full items-center gap-3 rounded-md px-3 h-9 text-[13.5px] transition-colors ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]'
const rowIdle = 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--nav-hover)]'
const rowActive =
  'bg-[var(--nav-active)] text-[var(--text-primary)] font-medium ' +
  'after:absolute after:-right-3 after:top-1 after:bottom-1 after:w-[3px] after:rounded-l after:bg-[var(--accent)]'

export const Sidebar: React.FC<SidebarProps> = ({ mobileOpen = false, onMobileClose }) => {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const searchRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState('')
  const [expanded, setExpanded] = useState<Record<string, boolean>>(loadExpanded)

  const sections = useMemo(() => visibleSections(NAV_SECTIONS, isOperator(user)), [user])
  const shown = useMemo(() => filterSections(sections, query), [sections, query])
  const searching = query.trim().length > 0

  // Open the group that holds the current page, e.g. after a deep link.
  useEffect(() => {
    const id = activeGroupId(sections, pathname)
    if (id) setExpanded((prev) => (prev[id] ? prev : { ...prev, [id]: true }))
  }, [sections, pathname])

  useEffect(() => saveExpanded(expanded), [expanded])

  const handleLogout = async () => {
    // The HttpOnly access_token cookie (local + Google sessions) can only be
    // cleared by the backend, so call it before dropping client state.
    try {
      await api.post('/auth/logout')
    } catch {
      // Network/401 failure must not trap the user in a signed-in UI.
    }
    logout()
    navigate('/login')
  }

  useEffect(() => {
    if (!mobileOpen) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onMobileClose?.()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [mobileOpen, onMobileClose])

  // Cmd+K / Ctrl+K jumps to the menu search from anywhere.
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        searchRef.current?.focus()
        searchRef.current?.select()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  const handleSearchKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      const first = flattenLinks(shown)[0]
      if (first) {
        navigate(first.path)
        setQuery('')
        searchRef.current?.blur()
        onMobileClose?.()
      }
    } else if (e.key === 'Escape') {
      // Keep Escape from also closing the mobile drawer while clearing.
      if (query) e.stopPropagation()
      setQuery('')
      if (!query) searchRef.current?.blur()
    }
  }

  const toggleGroup = (id: string) => setExpanded((prev) => ({ ...prev, [id]: !prev[id] }))

  const renderLink = (link: NavLink, nested: boolean) => {
    const Icon = link.icon
    const active = isPathActive(link.path, pathname)
    return (
      <RouterNavLink
        key={link.id}
        to={link.path}
        end={link.path === '/'}
        onClick={() => {
          setQuery('')
          onMobileClose?.()
        }}
        className={() => `${rowBase} ${active ? rowActive : rowIdle} ${nested ? 'pl-[41px]' : ''}`}
      >
        {Icon && (
          <Icon
            size={17}
            aria-hidden="true"
            className={`shrink-0 ${active ? 'text-[var(--accent)]' : 'text-[var(--text-muted)]'}`}
          />
        )}
        <span className="truncate">{link.label}</span>
        {link.badge && (
          <span className="ml-auto rounded px-1.5 py-px text-[10.5px] font-medium text-[var(--text-muted)] border border-[var(--bg-border)]">
            {link.badge}
          </span>
        )}
      </RouterNavLink>
    )
  }

  const renderGroup = (group: NavGroup) => {
    const open = searching || !!expanded[group.id]
    const holdsActive = group.children.some((c) => isPathActive(c.path, pathname))
    const panelId = `nav-group-${group.id}`
    const Icon = group.icon
    return (
      <div key={group.id}>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => toggleGroup(group.id)}
          disabled={searching}
          className={`${rowBase} ${holdsActive && !open ? 'text-[var(--text-primary)] font-medium hover:bg-[var(--nav-hover)]' : rowIdle}`}
        >
          <Icon
            size={17}
            aria-hidden="true"
            className={`shrink-0 ${holdsActive ? 'text-[var(--accent)]' : 'text-[var(--text-muted)]'}`}
          />
          <span className="truncate">{group.label}</span>
          <ChevronRight
            size={14}
            aria-hidden="true"
            className={`ml-auto shrink-0 text-[var(--text-muted)] transition-transform duration-150 motion-reduce:transition-none ${open ? 'rotate-90' : ''}`}
          />
        </button>
        {/* grid-rows 0fr -> 1fr animates to the content's natural height;
            visibility keeps collapsed links out of the tab order. The clip
            box reaches the sidebar edge (-mr-3 pr-3) so the active-page bar
            is not cut off. */}
        <div
          id={panelId}
          className={`grid [transition:grid-template-rows_160ms_ease,visibility_160ms] motion-reduce:[transition:none] ${
            open ? 'grid-rows-[1fr] visible' : 'grid-rows-[0fr] invisible'
          }`}
        >
          <div className="overflow-hidden -mr-3 pr-3">
            <div className="relative mt-0.5 space-y-0.5 before:absolute before:left-[20px] before:top-1 before:bottom-1 before:w-px before:bg-[var(--bg-border)]">
              {group.children.map((child) => renderLink(child, true))}
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm md:hidden animate-fade-in"
          onClick={onMobileClose}
          aria-hidden="true"
        />
      )}
      <aside
        role="navigation"
        aria-label="Main"
        className={`w-[240px] bg-[var(--bg-surface)] flex flex-col h-screen fixed left-0 top-0 border-r border-[var(--bg-border)] z-50 select-none transition-transform duration-200 ease-out md:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 px-4 flex items-center justify-between border-b border-[var(--bg-border)] bg-[var(--bg-surface)]">
          <div className="flex items-center gap-2.5">
            <img src="/itkku-logo.png" alt="IT KKU" className="w-9 h-9 object-contain" />
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-[15px] font-bold tracking-tight">
                  <span className="text-[#a34830] dark:text-[#d0674a]">IT</span> <span className="text-[#89898a] dark:text-[#a3a3a4]">KKU</span>
                </span>
                <span className="text-[9px] font-bold px-1.5 py-0.2 rounded bg-orange-500/10 text-orange-500 border border-orange-500/20 uppercase font-mono">
                  WAF
                </span>
              </div>
              <div className="text-[10.5px] text-[var(--text-muted)] tracking-tight flex items-center gap-1 mt-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span>ModSec CRS {CRS_VERSION}</span>
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={onMobileClose}
            aria-label="Close navigation menu"
            className="md:hidden p-1.5 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Quick search */}
        <div className="px-3 pt-3">
          <label className="flex items-center gap-2 h-9 px-3 rounded-md border border-[var(--bg-border)] bg-[var(--bg-primary)] text-[var(--text-muted)] focus-within:border-[var(--accent)] focus-within:ring-2 focus-within:ring-[var(--accent-subtle)]">
            <Search size={14} aria-hidden="true" className="shrink-0" />
            <input
              ref={searchRef}
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleSearchKey}
              placeholder="Quick search..."
              aria-label="Search the menu"
              className="min-w-0 flex-1 bg-transparent text-[13px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none [&::-webkit-search-cancel-button]:hidden"
            />
            <kbd className="shrink-0 text-[10.5px] font-sans text-[var(--text-muted)]">{isMac ? '⌘K' : 'Ctrl K'}</kbd>
          </label>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto px-3 pt-3 pb-4">
          {shown.length === 0 && (
            <p className="px-2.5 py-2 text-[12.5px] text-[var(--text-muted)]">No page matches “{query.trim()}”.</p>
          )}
          {shown.map((section) => (
            <div key={section.id} className={section.label ? 'mt-5 first:mt-0' : ''}>
              {section.label && (
                <p className="px-3 pb-1.5 text-[12px] font-medium text-[var(--text-muted)]">{section.label}</p>
              )}
              <div className="space-y-0.5">
                {section.entries.map((entry) => (entry.kind === 'link' ? renderLink(entry, false) : renderGroup(entry)))}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer Profile & Logout */}
        <div className="p-3 border-t border-[var(--bg-border)] bg-[var(--bg-surface)]">
          <div className="flex items-center justify-between p-2 rounded-lg bg-[var(--bg-app)] border border-[var(--bg-border-subtle)]">
            <div className="flex items-center gap-2.5 overflow-hidden">
              <div className="w-7 h-7 rounded-full bg-indigo-500/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400 font-mono text-[11px] font-bold shrink-0">
                {(user?.username || 'U')[0].toUpperCase()}
              </div>
              <div className="truncate">
                <p className="text-[12.5px] font-medium text-[var(--text-primary)] truncate m-0">
                  {user?.username || 'User'}
                </p>
                <span className="text-[11px] text-[var(--text-muted)]">{platformRoleLabel(user)}</span>
              </div>
            </div>
            <button
              type="button"
              onClick={handleLogout}
              className="p-1.5 rounded text-[var(--text-muted)] hover:text-red-400 hover:bg-red-500/10 transition-colors cursor-pointer"
              title="Sign out"
              aria-label="Sign out"
            >
              <LogOut size={14} />
            </button>
          </div>
        </div>
      </aside>
    </>
  )
}
