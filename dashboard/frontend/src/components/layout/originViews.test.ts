import { describe, it, expect } from 'vitest'
import { ORIGIN_TABS, ORIGIN_VIEWS, resolveOriginTab, viewOfSection } from './navigation'

describe('origin views', () => {
  it('places every section id in exactly one of the six tabs', () => {
    expect(ORIGIN_VIEWS).toHaveLength(6)
    const all = ORIGIN_VIEWS.flatMap((v) => v.sections).sort()
    expect(all).toEqual(ORIGIN_TABS.map((t) => t.id).sort())
  })
  it('keeps old deep links working', () => {
    expect(resolveOriginTab('ip-access')).toEqual({ view: 'protection', section: 'ip-access' })
    expect(resolveOriginTab('shield')).toEqual({ view: 'protection', section: 'shield' })
    expect(resolveOriginTab('postmortem')).toEqual({ view: 'reports', section: 'postmortem' })
    expect(resolveOriginTab('ssl')).toEqual({ view: 'domains', section: 'domains' })
    expect(resolveOriginTab('domains')).toEqual({ view: 'domains', section: 'domains' })
    expect(resolveOriginTab('honeypot')).toEqual({ view: 'honeypot', section: 'honeypot' })
  })
  it('opens Protection with nothing expanded, and falls back to Overview', () => {
    expect(resolveOriginTab('protection')).toEqual({ view: 'protection', section: null })
    expect(resolveOriginTab('reports')).toEqual({ view: 'reports', section: 'postmortem' })
    expect(resolveOriginTab(null)).toEqual({ view: 'overview', section: 'overview' })
    expect(resolveOriginTab('nope')).toEqual({ view: 'overview', section: 'overview' })
  })
  it('maps a section to its tab', () => {
    expect(viewOfSection('rate-limits')).toBe('protection')
    expect(viewOfSection('team')).toBe('team')
  })
})
