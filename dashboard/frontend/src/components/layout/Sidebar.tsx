import React, { useEffect, useMemo, useRef, useState } from 'react'
import { NavLink as RouterNavLink, useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '../../store/authStore'
import { useThemeStore } from '../../store/themeStore'
import { api } from '../../api/axios'
import { getOrigins } from '../../api/origins'
import { ChevronRight, ChevronUp, LogOut, Monitor, Moon, Search, Sun, UserRound, X, Link2 } from 'lucide-react'
import { CRS_VERSION } from '../../lib/crsVersion'
import { isOperator, platformRoleLabel } from '../../lib/permissions'
import { useVerifiedGuard } from '../auth/EmailVerifyGate'
import type { Origin } from '../../types'
import {
  NAV_SECTIONS,
  activeGroupId,
  filterOriginTabs,
  filterSections,
  flattenLinks,
  isPathActive,
  originTabPath,
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

// How many origins a matched origin tab is offered for before the search
// points at the origin list instead.
const MAX_ORIGIN_RESULTS = 5

// Row styling follows BunkerWeb: roomy rows, a tinted fill on the current
// page and a bar on the sidebar's right edge (-right-3 = the nav padding).
const rowBase =
  'relative flex w-full items-center gap-3 rounded-md px-3 h-9 text-[13.5px] transition-colors ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]'
const rowIdle = 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--nav-hover)]'
const rowActive =
  'bg-[var(--nav-active)] text-[var(--text-primary)] font-medium ' +
  'after:absolute after:-right-3 after:top-1 after:bottom-1 after:w-[3px] after:rounded-l after:bg-[var(--accent)]'
// The quick-search result the arrow keys point at.
const rowHighlight = 'ring-2 ring-inset ring-[var(--accent)] text-[var(--text-primary)]'

interface SearchResult {
  key: string
  path: string
}

export const Sidebar: React.FC<SidebarProps> = ({ mobileOpen = false, onMobileClose }) => {
  const { user } = useAuthStore()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const searchRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState('')
  const [highlight, setHighlight] = useState(0)
  const [expanded, setExpanded] = useState<Record<string, boolean>>(loadExpanded)

  const sections = useMemo(() => visibleSections(NAV_SECTIONS, isOperator(user)), [user])
  const shown = useMemo(() => filterSections(sections, query), [sections, query])
  const searching = query.trim().length > 0

  // Origin tabs (Rate limits, IP access, ...) live inside each origin, so the
  // search offers them per origin. Same query key and shape as the origin
  // selector, so the list is usually already cached.
  const { data: originList = [], isLoading: originsLoading } = useQuery({
    queryKey: ['origins-selector-list', user?.user_id],
    queryFn: () => getOrigins().then((r) => r.data?.origins || []).catch(() => [] as Origin[]),
    enabled: !!user && searching,
    staleTime: 30_000,
  })
  const liveOrigins = useMemo(
    () =>
      (Array.isArray(originList) ? originList : []).filter(
        (o) => o?.origin_id && !['archived', 'deleted'].includes((o.status || '').toLowerCase()),
      ),
    [originList],
  )
  const tabMatches = useMemo(() => filterOriginTabs(query), [query])

  const pageResults = useMemo(() => flattenLinks(shown), [shown])
  const tabResults = useMemo(
    () =>
      tabMatches.flatMap((tab) =>
        liveOrigins.length === 0 || liveOrigins.length > MAX_ORIGIN_RESULTS
          ? [{ key: `tab-${tab.id}`, tab, origin: null as Origin | null, path: '/origins' }]
          : liveOrigins.map((o) => ({ key: `tab-${tab.id}-${o.origin_id}`, tab, origin: o, path: originTabPath(o.origin_id, tab.id) })),
      ),
    [tabMatches, liveOrigins],
  )
  const results: SearchResult[] = useMemo(
    () => [...pageResults.map((l) => ({ key: `page-${l.id}`, path: l.path })), ...tabResults],
    [pageResults, tabResults],
  )
  const highlightKey = searching ? results[Math.min(highlight, results.length - 1)]?.key : undefined

  useEffect(() => setHighlight(0), [query])

  // Open the group that holds the current page, e.g. after a deep link.
  useEffect(() => {
    const id = activeGroupId(sections, pathname)
    if (id) setExpanded((prev) => (prev[id] ? prev : { ...prev, [id]: true }))
  }, [sections, pathname])

  useEffect(() => saveExpanded(expanded), [expanded])

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

  const finishSearch = () => {
    setQuery('')
    searchRef.current?.blur()
    onMobileClose?.()
  }

  const handleSearchKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (!results.length) return
      e.preventDefault()
      const step = e.key === 'ArrowDown' ? 1 : -1
      setHighlight((h) => (Math.min(h, results.length - 1) + step + results.length) % results.length)
    } else if (e.key === 'Enter') {
      const target = results[Math.min(highlight, results.length - 1)]
      if (target) {
        navigate(target.path)
        finishSearch()
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
    const highlighted = highlightKey === `page-${link.id}`
    return (
      <RouterNavLink
        key={link.id}
        to={link.path}
        end={link.path === '/'}
        onClick={() => {
          setQuery('')
          onMobileClose?.()
        }}
        className={() => `${rowBase} ${active ? rowActive : rowIdle} ${highlighted ? rowHighlight : ''} ${nested ? 'pl-[41px]' : ''}`}
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

  const nothingFound = searching && results.length === 0 && !(tabMatches.length && originsLoading)

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
            <img src="/itkku-logo.png" alt="" className="w-9 h-9 object-contain" />
            <div>
              <span className="block text-[15px] font-semibold tracking-tight leading-tight">
                <span className="text-[#a34830] dark:text-[#d0674a]">IT</span> <span className="text-[#6b6b6c] dark:text-[#a3a3a4]">KKU</span>{' '}
                <span className="text-[var(--text-primary)]">WAF</span>
              </span>
              <span className="block text-[11px] text-[var(--text-muted)] mt-0.5">ModSecurity CRS {CRS_VERSION}</span>
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
              placeholder="Search pages and settings"
              aria-label="Search pages and origin settings"
              aria-describedby="nav-search-hint"
              className="min-w-0 flex-1 bg-transparent text-[13px] text-[var(--text-primary)] placeholder:text-[var(--text-muted)] outline-none [&::-webkit-search-cancel-button]:hidden"
            />
            <kbd className="shrink-0 text-[10.5px] font-sans text-[var(--text-muted)]">{isMac ? '⌘K' : 'Ctrl K'}</kbd>
          </label>
          <span id="nav-search-hint" className="sr-only">
            Use the up and down arrow keys to pick a result and Enter to open it. Escape clears the search.
          </span>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto px-3 pt-3 pb-4">
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

          {searching && (tabResults.length > 0 || (tabMatches.length > 0 && originsLoading)) && (
            <div className={shown.length ? 'mt-5' : ''}>
              <p className="px-3 pb-1.5 text-[12px] font-medium text-[var(--text-muted)]">Inside an origin</p>
              {originsLoading && tabResults.length === 0 ? (
                <p className="px-3 py-1 text-[12.5px] text-[var(--text-muted)]">Looking up your origins…</p>
              ) : (
                <div className="space-y-0.5">
                  {tabResults.map((r) => (
                    <button
                      key={r.key}
                      type="button"
                      onClick={() => {
                        navigate(r.path)
                        finishSearch()
                      }}
                      className={`${rowBase} ${rowIdle} h-auto py-1.5 text-left ${highlightKey === r.key ? rowHighlight : ''}`}
                    >
                      <span className="min-w-0">
                        <span className="block truncate">{r.tab.label}</span>
                        <span className="block truncate text-[11.5px] text-[var(--text-muted)]">
                          {r.origin ? r.origin.label || r.origin.ip : liveOrigins.length ? 'Pick an origin first' : 'Add an origin first'}
                        </span>
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          {nothingFound && (
            <div className="px-3 py-2 text-[12.5px] text-[var(--text-muted)] space-y-1.5">
              <p className="m-0">Nothing matches “{query.trim()}”.</p>
              <p className="m-0">
                Try a task such as{' '}
                {['block ip', 'rate limit', 'alerts', 'origins'].map((s, i, all) => (
                  <React.Fragment key={s}>
                    <button
                      type="button"
                      onClick={() => {
                        setQuery(s)
                        searchRef.current?.focus()
                      }}
                      className="text-[var(--accent)] hover:underline cursor-pointer"
                    >
                      {s}
                    </button>
                    {i < all.length - 1 ? ', ' : '.'}
                  </React.Fragment>
                ))}
              </p>
            </div>
          )}
        </nav>

        <ProfileMenu onNavigate={onMobileClose} />
      </aside>
    </>
  )
}

// Account items (devices, Google link, theme, sign out) live in the profile
// menu, not in the platform settings page.
const ProfileMenu: React.FC<{ onNavigate?: () => void }> = ({ onNavigate }) => {
  const { user, logout } = useAuthStore()
  const { theme, toggleTheme } = useThemeStore()
  const navigate = useNavigate()
  const guard = useVerifiedGuard()
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        setOpen(false)
        buttonRef.current?.focus()
      }
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey, true)
    menuRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus()
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [open])

  const handleMenuKey = (e: React.KeyboardEvent) => {
    if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
    e.preventDefault()
    const items = Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])
    const i = items.indexOf(document.activeElement as HTMLElement)
    const next = e.key === 'ArrowDown' ? (i + 1) % items.length : (i - 1 + items.length) % items.length
    items[next]?.focus()
  }

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

  const itemClass =
    'flex w-full items-center gap-2.5 rounded-md px-2.5 h-9 text-[13px] text-[var(--text-secondary)] hover:bg-[var(--nav-hover)] hover:text-[var(--text-primary)] focus-visible:outline-none focus-visible:bg-[var(--nav-hover)] focus-visible:text-[var(--text-primary)] cursor-pointer'

  return (
    <div ref={rootRef} className="relative p-3 border-t border-[var(--bg-border)] bg-[var(--bg-surface)]">
      {open && (
        <div
          ref={menuRef}
          role="menu"
          aria-label="Account"
          onKeyDown={handleMenuKey}
          className="absolute bottom-full left-3 right-3 mb-1 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface-elevated)] p-1 shadow-lg"
        >
          <button
            type="button"
            role="menuitem"
            className={itemClass}
            onClick={() => {
              setOpen(false)
              onNavigate?.()
              navigate('/settings/devices')
            }}
          >
            <Monitor size={15} aria-hidden="true" />
            Signed-in devices
          </button>
          <button
            type="button"
            role="menuitem"
            className={itemClass}
            onClick={() => {
              setOpen(false)
              guard('link_google', () => {
                window.location.href = '/api/auth/google?link=true'
              })
            }}
          >
            <Link2 size={15} aria-hidden="true" />
            Link Google account
          </button>
          <button
            type="button"
            role="menuitem"
            className={itemClass}
            onClick={() => toggleTheme()}
          >
            {theme === 'dark' ? <Sun size={15} aria-hidden="true" /> : <Moon size={15} aria-hidden="true" />}
            {theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          </button>
          <div className="my-1 h-px bg-[var(--bg-border-subtle)]" role="separator" />
          <button
            type="button"
            role="menuitem"
            className={`${itemClass} hover:text-red-600 dark:hover:text-red-400`}
            onClick={handleLogout}
          >
            <LogOut size={15} aria-hidden="true" />
            Sign out
          </button>
        </div>
      )}
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center gap-2.5 rounded-lg p-2 text-left hover:bg-[var(--nav-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] cursor-pointer"
      >
        <span className="w-7 h-7 rounded-full bg-[var(--nav-active)] flex items-center justify-center text-[var(--text-secondary)] shrink-0">
          <UserRound size={15} aria-hidden="true" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-[12.5px] font-medium text-[var(--text-primary)] truncate">{user?.username || 'User'}</span>
          <span className="block text-[11px] text-[var(--text-muted)]">{platformRoleLabel(user)}</span>
        </span>
        <ChevronUp size={14} aria-hidden="true" className={`shrink-0 text-[var(--text-muted)] transition-transform ${open ? '' : 'rotate-180'}`} />
      </button>
    </div>
  )
}
