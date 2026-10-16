import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'
import { User } from '../types'
import { queryClient } from '../lib/queryClient'
import { useOriginFilterStore } from './originFilterStore'

// The session itself lives in an HttpOnly cookie the browser sends
// automatically; it is deliberately NOT kept here (a JWT in localStorage can
// be read by any XSS). Only non-secret UI state is persisted, per tab
// (sessionStorage, H79), and /api/auth/me is the source of truth on load.
interface AuthState {
  user: User | null
  isAuthenticated: boolean
  sessionChecked: boolean
  setAuth: (user: User) => void
  updateUser: (user: User) => void
  setSessionChecked: () => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      sessionChecked: false,
      setAuth: (user) => set({ user, isAuthenticated: true }),
      updateUser: (user) => set({ user }),
      setSessionChecked: () => set({ sessionChecked: true }),
      logout: () => {
        // N22: drop every cached response and the origin filter of the user
        // who is leaving, so the next sign-in in this tab starts clean.
        queryClient.clear()
        useOriginFilterStore.getState().setSelectedOrigin('ALL', 'All Managed Origins (ทั้งหมด)')
        set({ user: null, isAuthenticated: false })
      },
    }),
    {
      name: 'waf_auth',
      storage: createJSONStorage(() => sessionStorage),
      // persist only non-secret UI hints; never a token
      partialize: (s) => ({ user: s.user, isAuthenticated: s.isAuthenticated }),
    }
  )
)
