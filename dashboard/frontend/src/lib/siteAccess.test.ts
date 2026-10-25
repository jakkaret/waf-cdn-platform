import { describe, expect, it } from 'vitest'
import { looksLikeIp, looksLikePathPattern, rateText } from './siteAccess'

describe('site access helpers', () => {
  it('accepts addresses and CIDR ranges', () => {
    for (const ok of ['198.51.100.7', '192.0.2.0/24', '2001:db8::1', '2001:db8::/48']) expect(looksLikeIp(ok)).toBe(true)
    for (const bad of ['', '300.1.1.1', '1.2.3', '1.2.3.4/33', '1.2.3.4/24/1', 'example.com']) expect(looksLikeIp(bad)).toBe(false)
  })

  it('accepts * or a path', () => {
    expect(looksLikePathPattern('*')).toBe(true)
    expect(looksLikePathPattern('/api/*')).toBe(true)
    expect(looksLikePathPattern('login')).toBe(false)
    expect(looksLikePathPattern('/a b')).toBe(false)
  })

  it('describes a rate', () => {
    expect(rateText(60, 60)).toBe('60 / 1 min')
    expect(rateText(10, 30)).toBe('10 / 30 s')
    expect(rateText(100, 3600)).toBe('100 / 1 h')
  })
})
