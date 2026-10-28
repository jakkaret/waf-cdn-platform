import { describe, expect, it } from 'vitest'
import { nextEdgeState } from './edgeStatus'

describe('nextEdgeState', () => {
  it('is online whenever the check answered', () => {
    expect(nextEdgeState(undefined, true)).toBe('online')
    expect(nextEdgeState('offline', true)).toBe('online')
  })

  it('reports a single failed check as a miss, not an outage', () => {
    expect(nextEdgeState('online', false)).toBe('missed')
    expect(nextEdgeState(undefined, false)).toBe('missed')
    expect(nextEdgeState('unknown', false)).toBe('missed')
  })

  it('is offline after a second miss in a row', () => {
    expect(nextEdgeState('missed', false)).toBe('offline')
    expect(nextEdgeState('offline', false)).toBe('offline')
  })

  it('is unknown without data', () => {
    expect(nextEdgeState('online', undefined)).toBe('unknown')
  })
})
