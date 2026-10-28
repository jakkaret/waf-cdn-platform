import { describe, expect, it } from 'vitest'
import {
  NAV_SECTIONS,
  ORIGIN_TABS,
  activeGroupId,
  breadcrumbFor,
  filterOriginTabs,
  filterSections,
  flattenLinks,
  isOriginTab,
  isPathActive,
  matchesQuery,
  originTabPath,
  visibleSections,
} from './navigation'

const paths = (sections = NAV_SECTIONS) => flattenLinks(sections).map((l) => l.path)

describe('NAV_SECTIONS', () => {
  it('links every page once', () => {
    const all = paths()
    expect(new Set(all).size).toBe(all.length)
    expect([...all].sort()).toEqual(
      [
        '/', '/origins', '/tunnels', '/logs', '/alerts', '/ml-analyst', '/rule-proposals', '/rules',
        '/notifications', '/support', '/settings', '/cdn', '/diagnostics', '/ip-rules', '/rate-limits', '/users',
      ].sort(),
    )
  })

  it('no longer links the pages merged into Rule proposals', () => {
    expect(paths()).not.toContain('/ml-rules')
    expect(paths()).not.toContain('/threshold-proposals')
  })

  it('keeps ML insights in one place only', () => {
    expect(paths().filter((p) => p === '/ml-analyst')).toHaveLength(1)
  })

  it('orders sections by the job they serve', () => {
    expect(NAV_SECTIONS.map((s) => s.id)).toEqual(['main', 'sites', 'monitoring', 'rules', 'settings', 'admin'])
  })
})

describe('visibleSections', () => {
  it('shows everything to an operator', () => {
    expect(paths(visibleSections(NAV_SECTIONS, true))).toHaveLength(16)
  })

  it('hides the whole administration section from a regular user', () => {
    const visible = visibleSections(NAV_SECTIONS, false)
    expect(visible.map((s) => s.id)).not.toContain('admin')
    const visiblePaths = paths(visible)
    for (const p of ['/settings', '/cdn', '/diagnostics', '/ip-rules', '/rate-limits', '/users']) {
      expect(visiblePaths).not.toContain(p)
    }
    expect(visiblePaths).toContain('/support')
    expect(visiblePaths).toContain('/rule-proposals')
    expect(visiblePaths).toHaveLength(10)
  })

  it('drops a group whose children are all hidden', () => {
    const sections = visibleSections(
      [{ id: 's', entries: [{ kind: 'group', id: 'g', label: 'G', icon: NAV_SECTIONS[0].entries[0].icon!, children: [
        { kind: 'link', id: 'x', label: 'X', path: '/x', access: 'operator' },
      ] }] }],
      false,
    )
    expect(sections).toEqual([])
  })
})

describe('isPathActive', () => {
  it('matches the dashboard only on the exact root', () => {
    expect(isPathActive('/', '/')).toBe(true)
    expect(isPathActive('/', '/logs')).toBe(false)
  })

  it('matches sub-pages but not look-alike prefixes', () => {
    expect(isPathActive('/origins', '/origins/abc')).toBe(true)
    expect(isPathActive('/rules', '/rules-old')).toBe(false)
    expect(isPathActive('/settings', '/settings/devices')).toBe(true)
  })
})

describe('activeGroupId', () => {
  it('returns null when the menu has no groups', () => {
    expect(activeGroupId(NAV_SECTIONS, '/logs')).toBeNull()
    expect(activeGroupId(NAV_SECTIONS, '/origins/abc')).toBeNull()
  })
})

describe('breadcrumbFor', () => {
  it('starts with the section label', () => {
    expect(breadcrumbFor(NAV_SECTIONS, '/alerts')).toEqual(['Monitoring', 'Alerts'])
    expect(breadcrumbFor(NAV_SECTIONS, '/origins/abc')).toEqual(['My websites', 'Origins'])
  })

  it('uses the page alone in the unlabeled top section', () => {
    expect(breadcrumbFor(NAV_SECTIONS, '/')).toEqual(['Dashboard'])
  })

  it('is empty for pages outside the menu', () => {
    expect(breadcrumbFor(NAV_SECTIONS, '/onboarding')).toEqual([])
  })
})

describe('matchesQuery', () => {
  it('needs every word somewhere in the label or keywords', () => {
    expect(matchesQuery('block ip', 'IP access', ['block ip'])).toBe(true)
    expect(matchesQuery('rate limit', 'Rate limits')).toBe(true)
    expect(matchesQuery('rate zzz', 'Rate limits')).toBe(false)
  })
})

describe('filterSections', () => {
  it('returns the input for an empty query', () => {
    expect(filterSections(NAV_SECTIONS, '  ')).toBe(NAV_SECTIONS)
  })

  it('matches labels case-insensitively', () => {
    expect(paths(filterSections(NAV_SECTIONS, 'ML INSIGHTS'))).toEqual(['/ml-analyst'])
  })

  it('matches old page names through keywords', () => {
    expect(paths(filterSections(NAV_SECTIONS, 'tuning'))).toEqual(['/rule-proposals'])
    expect(paths(filterSections(NAV_SECTIONS, 'telegram'))).toEqual(['/notifications'])
    expect(paths(filterSections(NAV_SECTIONS, 'purge'))).toEqual(['/cdn'])
  })

  it('returns nothing when nothing matches', () => {
    expect(filterSections(NAV_SECTIONS, 'zzz')).toEqual([])
  })
})

describe('origin tabs', () => {
  it('finds the tabs the review could not reach from the search', () => {
    expect(filterOriginTabs('rate').map((t) => t.id)).toEqual(['rate-limits'])
    expect(filterOriginTabs('block ip').map((t) => t.id)).toEqual(['ip-access'])
    expect(filterOriginTabs('IP access').map((t) => t.id)).toEqual(['ip-access'])
    expect(filterOriginTabs('waf policy').map((t) => t.id)).toEqual(['waf'])
  })

  it('offers nothing for an empty query', () => {
    expect(filterOriginTabs(' ')).toEqual([])
  })

  it('recognises only known tab ids', () => {
    expect(ORIGIN_TABS).toHaveLength(9)
    expect(isOriginTab('rate-limits')).toBe(true)
    expect(isOriginTab('ssl')).toBe(false)
    expect(isOriginTab(null)).toBe(false)
  })

  it('builds a deep link with the tab and extra params', () => {
    expect(originTabPath('abc', 'ip-access', { ip: '1.2.3.4' })).toBe('/origins/abc?tab=ip-access&ip=1.2.3.4')
  })
})

describe('Thai labels', () => {
  it('gives every menu entry and origin tab a Thai label', () => {
    for (const link of flattenLinks(NAV_SECTIONS)) expect(link.labelTh, link.id).toBeTruthy()
    for (const section of NAV_SECTIONS) if (section.label) expect(section.labelTh, section.id).toBeTruthy()
    for (const tab of ORIGIN_TABS) expect(tab.labelTh, tab.id).toBeTruthy()
  })

  it('builds the breadcrumb in the chosen language', () => {
    expect(breadcrumbFor(NAV_SECTIONS, '/alerts', 'th')).toEqual(['การเฝ้าระวัง', 'การแจ้งเตือนภัย'])
    expect(breadcrumbFor(NAV_SECTIONS, '/alerts')).toEqual(['Monitoring', 'Alerts'])
  })

  it('finds pages and origin tabs by their Thai label', () => {
    expect(paths(filterSections(NAV_SECTIONS, 'กฎทั้งหมด'))).toEqual(['/rules'])
    expect(filterOriginTabs('โดเมน').map((t) => t.id)).toEqual(['domains'])
  })
})
