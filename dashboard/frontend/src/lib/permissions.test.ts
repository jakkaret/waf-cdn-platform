import { describe, expect, it } from 'vitest'
import { isOperator, platformRoleLabel } from './permissions'

describe('isOperator', () => {
  it('accepts the new operator role and the legacy admin role', () => {
    expect(isOperator({ role: 'operator' })).toBe(true)
    expect(isOperator({ role: 'admin' })).toBe(true)
  })

  it('rejects every other role and a missing user', () => {
    expect(isOperator({ role: 'user' })).toBe(false)
    expect(isOperator({ role: 'viewer' })).toBe(false)
    expect(isOperator({ role: 'Admin' })).toBe(false)
    expect(isOperator({ role: null })).toBe(false)
    expect(isOperator(null)).toBe(false)
    expect(isOperator(undefined)).toBe(false)
  })
})

describe('platformRoleLabel', () => {
  it('labels operators and users', () => {
    expect(platformRoleLabel({ role: 'admin' })).toBe('Platform operator')
    expect(platformRoleLabel({ role: 'viewer' })).toBe('User')
    expect(platformRoleLabel(null)).toBe('User')
  })
})
