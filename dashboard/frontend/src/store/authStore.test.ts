import { describe, expect, it } from 'vitest'
import { queryClient } from '../lib/queryClient'
import { useAuthStore } from './authStore'
import { useOriginFilterStore } from './originFilterStore'

// N22: after logout the next person in the same tab must not see anything
// cached for the previous user.
describe('logout', () => {
  it('clears every cached query and resets the origin filter', () => {
    useAuthStore.getState().setAuth({ user_id: 'u1', email: 'a@example.com', username: 'a', role: 'admin' } as never)
    queryClient.setQueryData(['dashboard', 'stats'], { total: 42 })
    useOriginFilterStore.getState().setSelectedOrigin('shop.example.com', 'shop')

    useAuthStore.getState().logout()

    expect(queryClient.getQueryCache().getAll()).toHaveLength(0)
    expect(useOriginFilterStore.getState().selectedOrigin).toBe('ALL')
    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    expect(useAuthStore.getState().user).toBeNull()
  })
})
