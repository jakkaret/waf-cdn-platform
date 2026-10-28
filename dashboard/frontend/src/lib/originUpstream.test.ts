import { describe, expect, it } from 'vitest'
import { originUpstreamLabel } from './originUpstream'

describe('originUpstreamLabel', () => {
  it('uses the stored scheme of a direct connection', () => {
    expect(originUpstreamLabel({ ip: '216.198.79.1', port: 443, connection_mode: 'direct', origin_scheme: 'https' })).toBe(
      'https://216.198.79.1:443',
    )
  })

  it('falls back to http for a direct connection without a scheme', () => {
    expect(originUpstreamLabel({ ip: '203.0.113.5', port: 80, connection_mode: 'direct', origin_scheme: null })).toBe('http://203.0.113.5:80')
  })

  it('does not invent a scheme for a tunnel', () => {
    expect(originUpstreamLabel({ ip: '127.0.0.1', port: 3000, connection_mode: 'agent' })).toBe('Tunnel to 127.0.0.1:3000')
    expect(originUpstreamLabel({ ip: '127.0.0.1', port: 3000, is_tunnel: true })).toBe('Tunnel to 127.0.0.1:3000')
  })
})
