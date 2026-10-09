import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { User } from '../types'

// The session itself lives in an HttpOnly cookie the browser sends
// automatically; it is deliberately NOT kept here (a JWT in localStorage can
// be read by any XSS). Only non-secret UI state is persisted, and /api/auth/me
// is the source of truth on load.
interface AuthState {
  user: User | null
  isAuthenticated: boolean
  setAuth: (user: User) => void
  updateUser: (user: User) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      setAuth: (user) => set({ user, isAuthenticated: true }),
      updateUser: (user) => set({ user }),
      logout: () => set({ user: null, isAuthenticated: false }),
    }),
    {
      name: 'waf_auth',
      // persist only non-secret UI hints; never a token
      partialize: (s) => ({ user: s.user, isAuthenticated: s.isAuthenticated }),
    }
  )
)
