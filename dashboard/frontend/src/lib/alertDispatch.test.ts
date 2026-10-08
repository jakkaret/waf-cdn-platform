import { describe, it, expect } from 'vitest'
import { getDispatchLabel } from './alertDispatch'

describe('getDispatchLabel', () => {
  it('never treats an HTTP status as a dispatch result', () => {
    expect(getDispatchLabel({ status: '403' } as any).label).toBe('Not tracked')
  })
  it('maps dispatch_status values', () => {
    expect(getDispatchLabel({ dispatch_status: 'sent' }).label).toBe('Sent')
    expect(getDispatchLabel({ dispatch_status: 'failed' }).label).toBe('Failed')
    expect(getDispatchLabel({ dispatched: false }).label).toBe('Not dispatched')
  })
})
