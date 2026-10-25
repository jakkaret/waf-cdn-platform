import { describe, expect, it } from 'vitest'
import {
  NAV_SECTIONS,
  activeGroupId,
  breadcrumbFor,
  filterSections,
  flattenLinks,
  isPathActive,
  visibleSections,
} from './navigation'

const paths = (sections = NAV_SECTIONS) => flattenLinks(sections).map((l) => l.path)

describe('NAV_SECTIONS', () => {
  it('keeps every page the old sidebar linked to, once', () => {
    const all = paths()
    expect(new Set(all).size).toBe(all.length)
    expect([...all].sort()).toEqual(
      [
        '/', '/logs', '/origins', '/rules', '/ip-rules', '/rate-limits', '/ml-rules',
        '/ml-analyst', '/threshold-proposals', '/alerts', '/cdn', '/tunnels', '/users',
        '/settings', '/support',
      ].sort(),
    )
  })

  it('no longer links the removed BOLA and concept pages', () => {
    expect(paths()).not.toContain('/bola')
    expect(paths().some((p) => p.startsWith('/concepts'))).toBe(false)
  })

  it('puts the most-used pages first', () => {
    expect(paths().slice(0, 4)).toEqual(['/', '/origins', '/logs', '/alerts'])
  })
})

describe('visibleSections', () => {
  it('shows everything to an operator', () => {
    expect(paths(visibleSections(NAV_SECTIONS, true))).toHaveLength(15)
  })

  it('hides operator-only pages from a regular user', () => {
    const visible = paths(visibleSections(NAV_SECTIONS, false))
    expect(visible).not.toContain('/ml-rules')
    expect(visible).not.toContain('/ip-rules') // a site's own list is on its origin page
    expect(visible).not.toContain('/rate-limits')
    expect(visible).not.toContain('/users')
    expect(visible).toContain('/support') // every member can reach support
    expect(visible).toHaveLength(11)
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
    expect(isPathActive('/ml-rules', '/ml-rules')).toBe(true)
    expect(isPathActive('/rules', '/rules-old')).toBe(false)
  })
})

describe('activeGroupId', () => {
  it('finds the group holding the current page', () => {
    expect(activeGroupId(NAV_SECTIONS, '/ip-rules')).toBe('security-rules')
    expect(activeGroupId(NAV_SECTIONS, '/threshold-proposals')).toBe('detection')
  })

  it('returns null for top-level pages', () => {
    expect(activeGroupId(NAV_SECTIONS, '/logs')).toBeNull()
    expect(activeGroupId(NAV_SECTIONS, '/origins/abc')).toBeNull()
  })
})

describe('breadcrumbFor', () => {
  it('includes the group for grouped pages', () => {
    expect(breadcrumbFor(NAV_SECTIONS, '/rules')).toEqual(['Security rules', 'WAF rules'])
  })

  it('uses the page alone for top-level pages and their sub-pages', () => {
    expect(breadcrumbFor(NAV_SECTIONS, '/')).toEqual(['Security dashboard'])
    expect(breadcrumbFor(NAV_SECTIONS, '/origins/abc')).toEqual(['Origin servers'])
  })

  it('is empty for pages outside the menu', () => {
    expect(breadcrumbFor(NAV_SECTIONS, '/onboarding')).toEqual([])
  })
})

describe('filterSections', () => {
  it('returns the input for an empty query', () => {
    expect(filterSections(NAV_SECTIONS, '  ')).toBe(NAV_SECTIONS)
  })

  it('matches labels case-insensitively, inside groups too', () => {
    expect(paths(filterSections(NAV_SECTIONS, 'rate'))).toEqual(['/rate-limits'])
    expect(paths(filterSections(NAV_SECTIONS, 'IP ACCESS'))).toEqual(['/ip-rules'])
  })

  it('matches keywords', () => {
    expect(paths(filterSections(NAV_SECTIONS, 'purge'))).toEqual(['/cdn'])
  })

  it('keeps all children when the group label matches', () => {
    expect(paths(filterSections(NAV_SECTIONS, 'detection'))).toEqual(['/ml-analyst', '/threshold-proposals'])
  })

  it('returns nothing when nothing matches', () => {
    expect(filterSections(NAV_SECTIONS, 'zzz')).toEqual([])
  })
})
