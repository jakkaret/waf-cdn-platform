import React, { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useAuthStore } from './store/authStore'
import { useThemeStore } from './store/themeStore'
import { AppLayout } from './components/layout/AppLayout'
import { Toaster } from 'react-hot-toast'

import Login from './pages/Login'
import Register from './pages/Register'
import OAuthSuccess from './pages/OAuthSuccess'
import Dashboard from './pages/Dashboard'
import Logs from './pages/Logs'
import Rules from './pages/Rules'
import IPRules from './pages/IPRules'
import RateLimiting from './pages/RateLimiting'
import Settings from './pages/Settings'
import Alerts from './pages/Alerts'
import Users from './pages/Users'
import CDN from './pages/CDN'
import MLRules from './pages/MLRules'
import Origins from './pages/Origins'
import OriginDetail from './pages/OriginDetail'
import MLAnalyst from './pages/MLAnalyst'
import Tunnels from './pages/Tunnels'
import StatusPage from './pages/StatusPage'
import Onboarding from './pages/Onboarding'
import ConceptsIndex from './pages/concepts/ConceptsIndex'
import AiRuleComposer from './pages/concepts/AiRuleComposer'
import TeamWorkspace from './pages/concepts/TeamWorkspace'
import IncidentPostmortem from './pages/concepts/IncidentPostmortem'
import AiBotControl from './pages/concepts/AiBotControl'
import CveAutoPatch from './pages/concepts/CveAutoPatch'
import SupplyChainMonitor from './pages/concepts/SupplyChainMonitor'
import ApiSchemaGuard from './pages/concepts/ApiSchemaGuard'
import AttackCostShield from './pages/concepts/AttackCostShield'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

const ProtectedRoute = ({
  children,
  requireAdmin,
}: {
  children: React.ReactNode
  requireAdmin?: boolean
}) => {
  const { isAuthenticated, user } = useAuthStore()

  if (!isAuthenticated) return <Navigate to="/login" replace />
  if (requireAdmin && user?.role !== 'admin') return <Navigate to="/" replace />

  return <AppLayout>{children}</AppLayout>
}

export const App: React.FC = () => {
  const { theme } = useThemeStore()

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
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/oauth-success" element={<OAuthSuccess />} />
          <Route path="/status" element={<StatusPage />} />

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
          <Route
            path="/ip-rules"
            element={
              <ProtectedRoute>
                <IPRules />
              </ProtectedRoute>
            }
          />
          <Route
            path="/rate-limits"
            element={
              <ProtectedRoute>
                <RateLimiting />
              </ProtectedRoute>
            }
          />
          <Route
            path="/ml-rules"
            element={
              <ProtectedRoute>
                <MLRules />
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
                <CDN />
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
            path="/concepts"
            element={
              <ProtectedRoute>
                <ConceptsIndex />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/ai-rules"
            element={
              <ProtectedRoute>
                <AiRuleComposer />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/team"
            element={
              <ProtectedRoute>
                <TeamWorkspace />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/postmortem"
            element={
              <ProtectedRoute>
                <IncidentPostmortem />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/ai-bots"
            element={
              <ProtectedRoute>
                <AiBotControl />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/cve-patch"
            element={
              <ProtectedRoute>
                <CveAutoPatch />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/supply-chain"
            element={
              <ProtectedRoute>
                <SupplyChainMonitor />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/api-guard"
            element={
              <ProtectedRoute>
                <ApiSchemaGuard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/concepts/cost-shield"
            element={
              <ProtectedRoute>
                <AttackCostShield />
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

          {/* Admin Routes */}
          <Route
            path="/users"
            element={
              <ProtectedRoute requireAdmin>
                <Users />
              </ProtectedRoute>
            }
          />
        </Routes>
      </BrowserRouter>
      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: 'var(--bg-surface-elevated)',
            color: 'var(--text-primary)',
            border: '1px solid var(--bg-border)',
            fontSize: '12.5px',
            fontFamily: 'Inter, sans-serif',
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
