import { describe, it, expect } from 'vitest'
import { dnsCheck, connectionCheck, httpsCheck, describeInspect, normalizeDomainInput, liveElsewhere, describeOriginAdjusted } from './connectProgress'
import type { ProgressDomain } from '../api/onboarding'

const base: ProgressDomain = {
  domain_id: 'd1',
  domain_name: 'shop.example.com',
  dns: {
    status: 'pending',
    current: { cname: '', a: ['203.0.113.10'] },
    instructions: {
      cname_record: { type: 'CNAME', name: 'shop.example.com', value: 'cdn.waf-it-kku.online' },
      txt_record: { type: 'TXT', name: '_waf-challenge.shop.example.com', value: 'waf-token-x' },
    },
  },
  connection: { status: 'waiting_agent' },
  https: { status: 'pending' },
  ready: false,
}

describe('dnsCheck', () => {
  it('shows what the domain points at now while waiting', () => {
    const v = dnsCheck(base)
    expect(v.state).toBe('waiting')
    expect(v.detail).toContain('cdn.waf-it-kku.online')
    expect(v.detail).toContain('203.0.113.10')
  })
  it('is done once verified', () => {
    expect(dnsCheck({ ...base, dns: { ...base.dns, status: 'verified' } }).state).toBe('done')
  })
  it('names the nameserver that gave a fresh answer', () => {
    const v = dnsCheck({ ...base, dns: { ...base.dns, current: {
      cname: 'old.vercel-dns-017.com', a: [], via: 'authoritative', nameserver: 'byte.dns-parking.com' } } })
    expect(v.detail).toContain('old.vercel-dns-017.com')
    expect(v.detail).toContain('byte.dns-parking.com')
  })
  it('warns that a resolver answer may be an old cached one', () => {
    const v = dnsCheck({ ...base, dns: { ...base.dns, current: { cname: 'old.example.net', a: [], via: 'resolver' } } })
    expect(v.detail).toContain('TTL')
  })
  it('asks a live site to add the TXT first', () => {
    const d = { ...base, dns: { ...base.dns, current: { cname: 'old.vercel-dns-017.com', a: [], via: 'authoritative' as const, points_here: false } } }
    expect(liveElsewhere(d)).toBe(true)
    expect(dnsCheck(d).detail).toContain('ขั้นที่ 1 เพิ่ม TXT')
  })
  it('keeps the CNAME step open after a TXT verification while the name still points elsewhere', () => {
    const d = { ...base, dns: { ...base.dns, status: 'verified' as const,
      current: { cname: 'old.vercel-dns-017.com', a: [], points_here: false } }, connection: { status: 'connected' as const } }
    expect(dnsCheck(d).state).toBe('waiting')
    expect(dnsCheck(d).detail).toContain('ขั้นที่ 2')
    expect(connectionCheck(d, 'direct').state).toBe('waiting')
    expect(httpsCheck(d).state).toBe('blocked')
  })
  it('is done once a verified name points here', () => {
    const d = { ...base, dns: { ...base.dns, status: 'verified' as const, current: null } }
    expect(liveElsewhere(d)).toBe(false)
    expect(dnsCheck(d).state).toBe('done')
  })
  it('says a matching record is being confirmed instead of waiting', () => {
    const v = dnsCheck({ ...base, dns: { ...base.dns, current: { cname: '', a: [], via: 'authoritative', txt_ok: true } } })
    expect(v.state).toBe('waiting')
    expect(v.detail).toContain('TXT ถูกต้องแล้ว')
  })
})

describe('connectionCheck', () => {
  it('never reports connected for an origin whose mode is unknown', () => {
    // The old wizard said "routing through CloudWAF" with nothing checked.
    expect(connectionCheck({ ...base, connection: { status: 'unknown' } }, null).state).toBe('neutral')
  })
  it('asks for the agent when it has not connected', () => {
    expect(connectionCheck(base, 'agent').state).toBe('waiting')
  })
  it('is blocked on DNS for a direct origin', () => {
    expect(connectionCheck({ ...base, connection: { status: 'waiting_dns' } }, 'direct').state).toBe('blocked')
  })
  it('reports a route nginx refused instead of waiting forever', () => {
    const v = connectionCheck({ ...base, connection: { status: 'error' } }, 'direct')
    expect(v.state).toBe('blocked')
    expect(v.detail).toContain('nginx')
  })
  it('is done when connected', () => {
    expect(connectionCheck({ ...base, connection: { status: 'connected' } }, 'direct').state).toBe('done')
  })
})

describe('httpsCheck', () => {
  it('waits for DNS before a certificate can be issued', () => {
    expect(httpsCheck(base).state).toBe('blocked')
  })
  it('shows issuer and days left when active', () => {
    const v = httpsCheck({ ...base, https: { status: 'active', issuer: "Let's Encrypt", days_remaining: 80 } })
    expect(v.state).toBe('done')
    expect(v.detail).toContain('80')
  })
})

describe('describeInspect', () => {
  it('prefills a direct connection from a reachable server', () => {
    const v = describeInspect({
      domain: 'shop.example.com',
      already_registered: false,
      recommended_mode: 'direct',
      reason: 'reachable',
      origin: { ip: '203.0.113.10', port: 443, scheme: 'https', status: 200 },
    })
    expect(v).toMatchObject({ mode: 'direct', address: '203.0.113.10', port: 443, scheme: 'https', tone: 'success' })
  })
  it('falls back to the agent behind a CDN', () => {
    const v = describeInspect({ domain: 'x.example.com', already_registered: false, reason: 'behind_cdn', cdn: 'Cloudflare' })
    expect(v.mode).toBe('agent')
    expect(v.message).toContain('Cloudflare')
  })
  it('stops on a domain that is already connected', () => {
    expect(describeInspect({ domain: 'x.example.com', already_registered: true }).tone).toBe('danger')
  })
})

describe('normalizeDomainInput', () => {
  it.each([
    ['shop.example.com', 'shop.example.com'],
    ['  Shop.Example.COM  ', 'shop.example.com'],
    ['https://shop.example.com', 'shop.example.com'],
    ['http://shop.example.com/', 'shop.example.com'],
    ['HTTPS://shop.example.com/path/page?q=1#top', 'shop.example.com'],
    ['shop.example.com/', 'shop.example.com'],
    ['shop.example.com:8443/x', 'shop.example.com'],
    ['//shop.example.com', 'shop.example.com'],
    ['https://user:pw@shop.example.com', 'shop.example.com'],
    ['shop.example.com.', 'shop.example.com'],
    ['https://www.example.com/', 'www.example.com'],
  ])('%s -> %s', (input, expected) => {
    expect(normalizeDomainInput(input)).toBe(expected)
  })

  it('leaves text it cannot read as a URL for the validator to reject', () => {
    expect(normalizeDomainInput('not a domain')).toBe('not a domain')
    expect(normalizeDomainInput('')).toBe('')
  })
})

describe('describeOriginAdjusted', () => {
  it('says why a force-HTTPS server was moved to https:443', () => {
    expect(describeOriginAdjusted({ scheme: 'https', port: 443, reason: 'origin_forces_https', status: 308 }))
      .toBe('เซิร์ฟเวอร์บังคับใช้ HTTPS (ตอบ 308) — เปลี่ยนเป็น https:443 ให้แล้ว ไม่งั้นเว็บจะ redirect วนไม่จบ')
  })

  it('says nothing when nothing was changed', () => {
    expect(describeOriginAdjusted(null)).toBeNull()
    expect(describeOriginAdjusted(undefined)).toBeNull()
  })
})
