import { describe, it, expect } from 'vitest'
import { selectNode } from './systemStatus'

const nodes = [
  { region: 'TH', status: 'degraded', latency_ms: 0 },
  { region: 'MAIN', status: 'healthy', latency_ms: 1560 },
]

describe('selectNode', () => {
  // Production change that would make this fail: the Dashboard card hardcoded a
  // permanent "ONLINE (Healthy)" badge, so it never reflected a real status.
  it('marks a healthy node online with its measured latency', () => {
    const v = selectNode(nodes, 'MAIN')
    expect(v.online).toBe(true)
    expect(v.statusLabel).toBe('ONLINE (Healthy)')
    expect(v.latencyLabel).toBe('~1560 ms')
  })

  it('marks a degraded node NOT online', () => {
    const v = selectNode(nodes, 'TH')
    expect(v.online).toBe(false)
    expect(v.statusLabel).toBe('DEGRADED')
  })

  it('shows n/a latency when the backend reports 0 (not measured)', () => {
    expect(selectNode(nodes, 'TH').latencyLabel).toBe('n/a')
  })

  it('returns an unknown, offline view when the region is absent', () => {
    const v = selectNode(nodes, 'NOPE')
    expect(v.online).toBe(false)
    expect(v.statusLabel).toBe('UNKNOWN')
    expect(v.latencyLabel).toBe('—')
  })

  it('returns unknown when the status payload is missing entirely', () => {
    const v = selectNode(undefined, 'TH')
    expect(v.online).toBe(false)
    expect(v.statusLabel).toBe('UNKNOWN')
  })
})
