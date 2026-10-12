import type { LucideIcon } from 'lucide-react'
import {
  Bell,
  Brain,
  FlaskConical,
  Globe,
  LayoutDashboard,
  ListFilter,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  Users,
} from 'lucide-react'

// Sidebar structure, Cloudflare style: the most-used pages sit at the top
// without a heading, related pages are grouped under a collapsible parent,
// and sections carry a short heading.
//
// `access` decides who sees an entry. "operator" entries are hidden from
// regular users. It mirrors today's visibility; role-3 plan Phase 6 moves the
// platform-wide pages (rules, BOLA, IP list, rate limits, tuning proposals,
// settings) to "operator" together with the backend guards.

export type NavAccess = 'member' | 'operator'

export interface NavLink {
  kind: 'link'
  id: string
  label: string
  path: string
  icon?: LucideIcon
  access: NavAccess
  badge?: string
  // Extra words the quick search matches, e.g. old page names.
  keywords?: string[]
}

export interface NavGroup {
  kind: 'group'
  id: string
  label: string
  icon: LucideIcon
  children: NavLink[]
}

export type NavEntry = NavLink | NavGroup

export interface NavSection {
  id: string
  label?: string
  entries: NavEntry[]
}

export const NAV_SECTIONS: NavSection[] = [
  {
    id: 'main',
    entries: [
      { kind: 'link', id: 'dashboard', label: 'Security dashboard', path: '/', icon: LayoutDashboard, access: 'member', keywords: ['overview', 'home'] },
      { kind: 'link', id: 'origins', label: 'Origin servers', path: '/origins', icon: Server, access: 'member', keywords: ['sites', 'domains'] },
      { kind: 'link', id: 'logs', label: 'Traffic logs', path: '/logs', icon: ListFilter, access: 'member', keywords: ['requests'] },
      { kind: 'link', id: 'alerts', label: 'Alert center', path: '/alerts', icon: Bell, access: 'member', keywords: ['notifications', 'telegram'] },
    ],
  },
  {
    id: 'protect',
    label: 'Protect & connect',
    entries: [
      {
        kind: 'group',
        id: 'security-rules',
        label: 'Security rules',
        icon: ShieldAlert,
        children: [
          { kind: 'link', id: 'rules', label: 'WAF rules', path: '/rules', access: 'member', keywords: ['modsecurity', 'crs'] },
          { kind: 'link', id: 'bola', label: 'API security (BOLA)', path: '/bola', access: 'member' },
          { kind: 'link', id: 'ip-rules', label: 'IP access list', path: '/ip-rules', access: 'member', keywords: ['block', 'allow'] },
          { kind: 'link', id: 'rate-limits', label: 'Rate limiting', path: '/rate-limits', access: 'member' },
          { kind: 'link', id: 'ml-rules', label: 'ML anomaly rules', path: '/ml-rules', access: 'operator' },
        ],
      },
      {
        kind: 'group',
        id: 'detection',
        label: 'Detection & response',
        icon: Brain,
        children: [
          { kind: 'link', id: 'ml-analyst', label: 'AI security analyst', path: '/ml-analyst', access: 'member' },
          { kind: 'link', id: 'threshold-proposals', label: 'Tuning proposals', path: '/threshold-proposals', access: 'member', keywords: ['threshold'] },
        ],
      },
      { kind: 'link', id: 'tunnels', label: 'Zero Trust tunnels', path: '/tunnels', icon: Shield, access: 'member' },
      { kind: 'link', id: 'cdn', label: 'CDN edge nodes', path: '/cdn', icon: Globe, access: 'member', keywords: ['cache', 'purge'] },
    ],
  },
  {
    id: 'admin',
    label: 'Administration',
    entries: [
      { kind: 'link', id: 'users', label: 'Access control', path: '/users', icon: Users, access: 'operator', keywords: ['users', 'roles'] },
      { kind: 'link', id: 'settings', label: 'System settings', path: '/settings', icon: Settings, access: 'member' },
      { kind: 'link', id: 'concepts', label: 'Concepts', path: '/concepts', icon: FlaskConical, access: 'operator', badge: 'Preview' },
    ],
  },
]

// Drop entries the user may not see, then groups and sections left empty.
export function visibleSections(sections: NavSection[], operator: boolean): NavSection[] {
  const allowed = (link: NavLink) => link.access === 'member' || operator
  return sections
    .map((section) => ({
      ...section,
      entries: section.entries.flatMap((entry): NavEntry[] => {
        if (entry.kind === 'link') return allowed(entry) ? [entry] : []
        const children = entry.children.filter(allowed)
        return children.length ? [{ ...entry, children }] : []
      }),
    }))
    .filter((section) => section.entries.length > 0)
}

// "/" matches only the dashboard itself; other paths also match their
// sub-pages (/origins/123 keeps "Origin servers" active).
export function isPathActive(path: string, pathname: string): boolean {
  if (path === '/') return pathname === '/'
  return pathname === path || pathname.startsWith(`${path}/`)
}

export function activeGroupId(sections: NavSection[], pathname: string): string | null {
  for (const section of sections) {
    for (const entry of section.entries) {
      if (entry.kind === 'group' && entry.children.some((c) => isPathActive(c.path, pathname))) {
        return entry.id
      }
    }
  }
  return null
}

// Quick search. A group whose own label matches keeps all its children.
export function filterSections(sections: NavSection[], query: string): NavSection[] {
  const q = query.trim().toLowerCase()
  if (!q) return sections
  const matches = (label: string, keywords: string[] = []) =>
    [label, ...keywords].some((text) => text.toLowerCase().includes(q))
  return sections
    .map((section) => ({
      ...section,
      entries: section.entries.flatMap((entry): NavEntry[] => {
        if (entry.kind === 'link') return matches(entry.label, entry.keywords) ? [entry] : []
        if (matches(entry.label)) return [entry]
        const children = entry.children.filter((c) => matches(c.label, c.keywords))
        return children.length ? [{ ...entry, children }] : []
      }),
    }))
    .filter((section) => section.entries.length > 0)
}

// Breadcrumb trail for the content header, BunkerWeb style:
// ["Security rules", "WAF rules"] for /rules, ["Origin servers"] for
// /origins/abc. Empty when the page is not in the menu.
export function breadcrumbFor(sections: NavSection[], pathname: string): string[] {
  for (const section of sections) {
    for (const entry of section.entries) {
      if (entry.kind === 'link') {
        if (isPathActive(entry.path, pathname)) return [entry.label]
        continue
      }
      const child = entry.children.find((c) => isPathActive(c.path, pathname))
      if (child) return [entry.label, child.label]
    }
  }
  return []
}

export function flattenLinks(sections: NavSection[]): NavLink[] {
  return sections.flatMap((section) =>
    section.entries.flatMap((entry) => (entry.kind === 'link' ? [entry] : entry.children)),
  )
}
