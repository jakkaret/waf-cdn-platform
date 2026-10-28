import { OperatorOnly } from './components/OperatorOnly'
import React, { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { useAuthStore } from './store/authStore'
import { useThemeStore } from './store/themeStore'
import { useLangStore } from './i18n'
import { AppLayout } from './components/layout/AppLayout'
import { Toaster } from 'react-hot-toast'

import Login from './pages/Login'
import Register from './pages/Register'
import OAuthSuccess from './pages/OAuthSuccess'
import AcceptInvite from './pages/AcceptInvite'
import VerifyEmail from './pages/VerifyEmail'
import ForgotPassword from './pages/ForgotPassword'
import { EmailVerifyModal } from './components/auth/EmailVerifyGate'
import Dashboard from './pages/Dashboard'
import Logs from './pages/Logs'
import Rules from './pages/Rules'
import IPRules from './pages/IPRules'
import RateLimiting from './pages/RateLimiting'
import Settings from './pages/Settings'
import Devices from './pages/Devices'
import Support from './pages/Support'
import SupportTicket from './pages/SupportTicket'
import Alerts from './pages/Alerts'
import Users from './pages/Users'
import CDN from './pages/CDN'
import RuleProposals from './pages/RuleProposals'
import Notifications from './pages/Notifications'
import StackDiagnostics from './pages/StackDiagnostics'
import Origins from './pages/Origins'
import OriginDetail from './pages/OriginDetail'
import MLAnalyst from './pages/MLAnalyst'
import Tunnels from './pages/Tunnels'
import StatusPage from './pages/StatusPage'
import Onboarding from './pages/Onboarding'
import NotFound from './pages/NotFound'
import { queryClient } from './lib/queryClient'
import { authApi } from './api/auth'


const ProtectedRoute = ({
  children,
  requireAdmin,
}: {
  children: React.ReactNode
  requireAdmin?: boolean
}) => {
  const { isAuthenticated, user, sessionChecked } = useAuthStore()

  // The user is kept only per tab (sessionStorage), so a new tab asks the
  // server (/api/auth/me) before deciding the visitor is signed out.
  if (!isAuthenticated && !sessionChecked) return null
  if (!isAuthenticated) return <Navigate to="/login" replace />
  if (requireAdmin && user?.role !== 'admin') return <Navigate to="/" replace />

  return <AppLayout>{children}</AppLayout>
}

// Signed in, but a full-screen page outside the dashboard frame (email
// verification right after sign-up).
const SessionRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, sessionChecked } = useAuthStore()
  if (!isAuthenticated && !sessionChecked) return null
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

// F-103: an already signed-in user opening /login or /register is sent home.
const PublicOnlyRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated } = useAuthStore()
  if (isAuthenticated) return <Navigate to="/" replace />
  return <>{children}</>
}

export const App: React.FC = () => {
  const { theme } = useThemeStore()
  const lang = useLangStore((s) => s.lang)

  useEffect(() => {
    document.documentElement.lang = lang
  }, [lang])

  // Confirm the session with the server on load (H79): a stale or revoked
  // session clears the store through the 401 interceptor.
  useEffect(() => {
    authApi
      .getMe()
      .then((me) => useAuthStore.getState().setAuth(me))
      .catch(() => {})
      .finally(() => useAuthStore.getState().setSessionChecked())
  }, [])

  useEffect(() => {
    if (typeof document !== 'undefined') {
      if (theme === 'dark') {
        document.documentElement.classList.add('dark')
        document.documentElement.classList.remove('light')
      } else {
        document.documentElement.classList.add('light')
        document.documentElement.classList.remove('dark')
      }
    }
  }, [theme])

  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          {/* Public Routes */}
          <Route path="/login" element={<PublicOnlyRoute><Login /></PublicOnlyRoute>} />
          <Route path="/register" element={<PublicOnlyRoute><Register /></PublicOnlyRoute>} />
          <Route path="/oauth-success" element={<OAuthSuccess />} />
          <Route path="/invites/accept" element={<AcceptInvite />} />
          <Route path="/status" element={<StatusPage />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/verify-email" element={<SessionRoute><VerifyEmail /></SessionRoute>} />

          {/* Protected Routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/logs"
            element={
              <ProtectedRoute>
                <Logs />
              </ProtectedRoute>
            }
          />
          <Route
            path="/rules"
            element={
              <ProtectedRoute>
                <Rules />
              </ProtectedRoute>
            }
          />
          {/* ML anomaly rules and tuning proposals share one review page;
              the old paths keep working as deep links into it. */}
          <Route
            path="/rule-proposals"
            element={
              <ProtectedRoute>
                <RuleProposals />
              </ProtectedRoute>
            }
          />
          <Route path="/threshold-proposals" element={<Navigate to="/rule-proposals?type=tuning" replace />} />
          <Route path="/ml-rules" element={<Navigate to="/rule-proposals?type=ml" replace />} />
          <Route
            path="/notifications"
            element={
              <ProtectedRoute>
                <Notifications />
              </ProtectedRoute>
            }
          />
          <Route
            path="/diagnostics"
            element={
              <ProtectedRoute>
                <OperatorOnly>
                  <StackDiagnostics />
                </OperatorOnly>
              </ProtectedRoute>
            }
          />
          <Route
            path="/ip-rules"
            element={
              <ProtectedRoute>
                <OperatorOnly originTab="IP Access">
                  <IPRules />
                </OperatorOnly>
              </ProtectedRoute>
            }
          />
          <Route
            path="/rate-limits"
            element={
              <ProtectedRoute>
                <OperatorOnly originTab="Rate Limits">
                  <RateLimiting />
                </OperatorOnly>
              </ProtectedRoute>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <Alerts />
              </ProtectedRoute>
            }
          />
          <Route
            path="/cdn"
            element={
              <ProtectedRoute>
                <OperatorOnly originTab="Overview (cache purge)">
                  <CDN />
                </OperatorOnly>
              </ProtectedRoute>
            }
          />
          <Route
            path="/tunnels"
            element={
              <ProtectedRoute>
                <Tunnels />
              </ProtectedRoute>
            }
          />
          <Route
            path="/origins"
            element={
              <ProtectedRoute>
                <Origins />
              </ProtectedRoute>
            }
          />
          <Route
            path="/onboarding"
            element={
              <ProtectedRoute>
                <Onboarding />
              </ProtectedRoute>
            }
          />
          <Route
            path="/origins/:id"
            element={
              <ProtectedRoute>
                <OriginDetail />
              </ProtectedRoute>
            }
          />
          <Route
            path="/ml-analyst"
            element={
              <ProtectedRoute>
                <MLAnalyst />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings/devices"
            element={
              <ProtectedRoute>
                <Devices />
              </ProtectedRoute>
            }
          />
          <Route
            path="/support"
            element={
              <ProtectedRoute>
                <Support />
              </ProtectedRoute>
            }
          />
          <Route
            path="/support/:id"
            element={
              <ProtectedRoute>
                <SupportTicket />
              </ProtectedRoute>
            }
          />

          {/* Admin Routes */}
          <Route
            path="/users"
            element={
              <ProtectedRoute requireAdmin>
                <Users />
              </ProtectedRoute>
            }
          />
          {/* F-029: unknown URLs used to render a blank screen */}
          <Route path="*" element={<NotFound />} />
        </Routes>
        <EmailVerifyModal />
      </BrowserRouter>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: 'var(--bg-surface-elevated)',
            color: 'var(--text-primary)',
            border: '1px solid var(--bg-border)',
            fontSize: '12.5px',
            fontFamily: 'inherit',
            boxShadow: '0 10px 25px -5px rgba(0,0,0,0.3)',
          },
          success: {
            iconTheme: {
              primary: '#10b981',
              secondary: '#ffffff',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#ffffff',
            },
          },
        }}
      />
    </QueryClientProvider>
  )
}

export default App
