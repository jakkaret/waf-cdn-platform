import { describe, expect, it } from 'vitest'
import { canEditOrigin, canManageOrigin, originRoleOf, platformRoleLabel } from './roles'

const origin = { admin_user_id: 'o', editor_user_ids: ['e'], viewer_user_ids: ['v'] }

describe('roles', () => {
  it('labels platform roles', () => {
    expect(platformRoleLabel('admin')).toBe('Support')
    expect(platformRoleLabel('viewer')).toBe('User')
    expect(platformRoleLabel(undefined)).toBe('User')
  })
  it('works out the origin role', () => {
    expect(originRoleOf(origin, 'o')).toBe('owner')
    expect(originRoleOf(origin, 'e')).toBe('editor')
    expect(originRoleOf(origin, 'v')).toBe('viewer')
    expect(originRoleOf(origin, 'x')).toBeNull()
    expect(originRoleOf(null, 'o')).toBeNull()
  })
  it('owner manages, editor edits, viewer reads', () => {
    expect([canManageOrigin('owner'), canManageOrigin('editor'), canManageOrigin('viewer')]).toEqual([true, false, false])
    expect([canEditOrigin('owner'), canEditOrigin('editor'), canEditOrigin('viewer')]).toEqual([true, true, false])
  })
})
