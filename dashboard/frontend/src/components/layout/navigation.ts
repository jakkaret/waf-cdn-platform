import type { LucideIcon } from 'lucide-react'
import {
  Activity,
  Bell,
  BellRing,
  Brain,
  Cable,
  Globe,
  LayoutDashboard,
  LifeBuoy,
  ListChecks,
  ListFilter,
  Gauge,
  Server,
  Settings,
  ShieldCheck,
  Users,
  Wand2,
} from 'lucide-react'

// Sidebar structure (UX reorganization 2026-10-28): sections follow the
// jobs a site owner does -- look after my websites, watch what happens,
// review rules, set up notifications -- and the platform operator's pages sit
// in their own section that regular users never see.
//
// `access` decides who sees an entry. "operator" entries are hidden from
// regular users; the backend guards those pages on its own (hiding a link is
// not the protection). Rule proposals is "member": the backend lists only the
// ML rules and tuning proposals of the caller's origins.

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
      { kind: 'link', id: 'dashboard', label: 'Dashboard', path: '/', icon: LayoutDashboard, access: 'member', keywords: ['overview', 'home', 'security dashboard', 'kpi'] },
    ],
  },
  {
    id: 'sites',
    label: 'My websites',
    entries: [
      { kind: 'link', id: 'origins', label: 'Origins', path: '/origins', icon: Server, access: 'member', keywords: ['sites', 'websites', 'domains', 'add origin', 'origin servers', 'dns'] },
      { kind: 'link', id: 'tunnels', label: 'Private tunnels', path: '/tunnels', icon: Cable, access: 'member', keywords: ['tunnel', 'frp', 'zero trust', 'no public ip', 'connect'] },
    ],
  },
  {
    id: 'monitoring',
    label: 'Monitoring',
    entries: [
      { kind: 'link', id: 'logs', label: 'Traffic logs', path: '/logs', icon: ListFilter, access: 'member', keywords: ['requests', 'access log', 'blocked requests'] },
      { kind: 'link', id: 'alerts', label: 'Alerts', path: '/alerts', icon: Bell, access: 'member', keywords: ['alert center', 'incidents', 'notifications'] },
      { kind: 'link', id: 'ml-analyst', label: 'ML insights', path: '/ml-analyst', icon: Brain, access: 'member', keywords: ['ai security analyst', 'anomaly', 'machine learning', 'ml verdicts'] },
    ],
  },
  {
    id: 'rules',
    label: 'Rules',
    entries: [
      { kind: 'link', id: 'rule-proposals', label: 'Rule proposals', path: '/rule-proposals', icon: Wand2, access: 'member', keywords: ['ml anomaly rules', 'tuning proposals', 'threshold', 'approve', 'review'] },
      { kind: 'link', id: 'rules', label: 'All rules', path: '/rules', icon: ListChecks, access: 'member', keywords: ['waf rules', 'waf policy', 'modsecurity', 'crs', 'custom rule'] },
    ],
  },
  {
    id: 'settings',
    label: 'Settings',
    entries: [
      { kind: 'link', id: 'notifications', label: 'Notifications', path: '/notifications', icon: BellRing, access: 'member', keywords: ['telegram', 'alert delivery', 'email'] },
      { kind: 'link', id: 'support', label: 'Support', path: '/support', icon: LifeBuoy, access: 'member', keywords: ['help', 'ticket', 'support tickets'] },
    ],
  },
  {
    id: 'admin',
    label: 'Administration',
    entries: [
      { kind: 'link', id: 'settings', label: 'Platform settings', path: '/settings', icon: Settings, access: 'operator', keywords: ['system settings', 'paranoia', 'anomaly limit', 'waf mode'] },
      { kind: 'link', id: 'cdn', label: 'CDN edge nodes', path: '/cdn', icon: Globe, access: 'operator', keywords: ['cache', 'purge', 'edge', 'pop'] },
      { kind: 'link', id: 'diagnostics', label: 'Stack diagnostics', path: '/diagnostics', icon: Activity, access: 'operator', keywords: ['services', 'health', 'postgres', 'clickhouse', 'redis'] },
      { kind: 'link', id: 'ip-rules', label: 'Platform IP list', path: '/ip-rules', icon: ShieldCheck, access: 'operator', keywords: ['block ip', 'allow ip', 'ip access list'] },
      { kind: 'link', id: 'rate-limits', label: 'Platform rate limits', path: '/rate-limits', icon: Gauge, access: 'operator', keywords: ['rate', 'rate limit', 'throttle'] },
      { kind: 'link', id: 'users', label: 'Access control', path: '/users', icon: Users, access: 'operator', keywords: ['users', 'roles'] },
    ],
  },
]

// The tabs of an origin's page. OriginDetail renders these labels and the
// quick search offers them per origin, so both say the same thing.
export type OriginTabId =
  | 'overview'
  | 'domains'
  | 'waf'
  | 'ml'
  | 'ip-access'
  | 'rate-limits'
  | 'shield'
  | 'team'
  | 'postmortem'

export interface OriginTabDef {
  id: OriginTabId
  label: string
  keywords: string[]
}

export const ORIGIN_TABS: OriginTabDef[] = [
  { id: 'overview', label: 'Overview', keywords: ['purge cache', 'cache', 'tech stack', 'cve', 'upstream'] },
  { id: 'domains', label: 'Domains & DNS', keywords: ['domain', 'dns', 'ssl', 'https', 'certificate'] },
  { id: 'waf', label: 'WAF policies', keywords: ['waf policy', 'waf rules', 'custom rule', 'managed ruleset', 'decoy', 'crs'] },
  { id: 'ml', label: 'ML protection', keywords: ['ml gate', 'anomaly', 'enforce', 'machine learning'] },
  { id: 'ip-access', label: 'IP access', keywords: ['block ip', 'allow ip', 'ip block', 'blocklist', 'allowlist', 'ban'] },
  { id: 'rate-limits', label: 'Rate limits', keywords: ['rate', 'rate limit', 'throttle', 'requests per minute'] },
  { id: 'shield', label: 'Bot & login shield', keywords: ['bot', 'captcha', 'otp', 'login'] },
  { id: 'team', label: 'Team & audit log', keywords: ['members', 'invite', 'editor', 'viewer', 'audit'] },
  { id: 'postmortem', label: 'Reports', keywords: ['incident report', 'postmortem', 'report', 'pdf', 'export'] },
]

// The origin page shows five tabs. Each of the nine section ids above still
// works in a link (?tab=ip-access opens Protection with IP rules open), so
// quick search, All rules, Alerts and "Block IP" links keep landing right.
export type OriginViewId = 'overview' | 'protection' | 'domains' | 'team' | 'reports'

export const ORIGIN_VIEWS: { id: OriginViewId; label: string; sections: OriginTabId[] }[] = [
  { id: 'overview', label: 'Overview', sections: ['overview'] },
  { id: 'protection', label: 'Protection', sections: ['waf', 'ml', 'ip-access', 'rate-limits', 'shield'] },
  { id: 'domains', label: 'Domains & DNS', sections: ['domains'] },
  { id: 'team', label: 'Team & history', sections: ['team'] },
  { id: 'reports', label: 'Reports', sections: ['postmortem'] },
]

export const viewOfSection = (section: OriginTabId): OriginViewId =>
  ORIGIN_VIEWS.find((v) => v.sections.includes(section))?.id ?? 'overview'

// What ?tab= lands on: a section id, or "protection" with nothing open.
export function resolveOriginTab(raw: string | null): { view: OriginViewId; section: OriginTabId | null } {
  const tab = raw === 'ssl' ? 'domains' : raw === 'reports' ? 'postmortem' : raw
  if (tab === 'protection') return { view: 'protection', section: null }
  if (isOriginTab(tab)) return { view: viewOfSection(tab), section: tab }
  return { view: 'overview', section: 'overview' }
}

export const isOriginTab = (value: string | null | undefined): value is OriginTabId =>
  ORIGIN_TABS.some((t) => t.id === value)

export const originTabPath = (originId: string, tab: OriginTabId, extra?: Record<string, string>) => {
  const params = new URLSearchParams({ tab, ...(extra ?? {}) })
  return `/origins/${encodeURIComponent(originId)}?${params.toString()}`
}

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
// sub-pages (/origins/123 keeps "Origins" active).
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

// Every word of the query has to appear somewhere in the label or keywords,
// so "block ip" finds "IP access" through its keyword and "rate limit" finds
// "Rate limits".
export function matchesQuery(query: string, label: string, keywords: string[] = []): boolean {
  const words = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return true
  const haystack = [label, ...keywords].join(' ').toLowerCase()
  return words.every((w) => haystack.includes(w))
}

// Quick search. A group whose own label matches keeps all its children.
export function filterSections(sections: NavSection[], query: string): NavSection[] {
  const q = query.trim().toLowerCase()
  if (!q) return sections
  return sections
    .map((section) => ({
      ...section,
      entries: section.entries.flatMap((entry): NavEntry[] => {
        if (entry.kind === 'link') return matchesQuery(q, entry.label, entry.keywords) ? [entry] : []
        if (matchesQuery(q, entry.label)) return [entry]
        const children = entry.children.filter((c) => matchesQuery(q, c.label, c.keywords))
        return children.length ? [{ ...entry, children }] : []
      }),
    }))
    .filter((section) => section.entries.length > 0)
}

export function filterOriginTabs(query: string): OriginTabDef[] {
  if (!query.trim()) return []
  return ORIGIN_TABS.filter((t) => matchesQuery(query, t.label, t.keywords))
}

// Breadcrumb trail for the content header: ["Monitoring", "Alerts"] for
// /alerts, ["My websites", "Origins"] for /origins/abc. Empty when the page
// is not in the menu.
export function breadcrumbFor(sections: NavSection[], pathname: string): string[] {
  for (const section of sections) {
    const prefix = section.label ? [section.label] : []
    for (const entry of section.entries) {
      if (entry.kind === 'link') {
        if (isPathActive(entry.path, pathname)) return [...prefix, entry.label]
        continue
      }
      const child = entry.children.find((c) => isPathActive(c.path, pathname))
      if (child) return [...prefix, entry.label, child.label]
    }
  }
  return []
}

export function flattenLinks(sections: NavSection[]): NavLink[] {
  return sections.flatMap((section) =>
    section.entries.flatMap((entry) => (entry.kind === 'link' ? [entry] : entry.children)),
  )
}
