import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { ThemeToggle } from '../components/ui/ThemeToggle'
import toast from 'react-hot-toast'
import { Shield, ArrowRight, Lock, Mail, Key } from 'lucide-react'

export const Login: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const { access_token } = await authApi.login(email, password)
      useAuthStore.setState({ token: access_token })
      const user = await authApi.getMe()
      setAuth(access_token, user)
      toast.success('Authentication successful')
      navigate('/')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      const message =
        typeof detail === 'string'
          ? detail
          : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ')
          : 'Invalid email or credentials'
      toast.error(message)
      useAuthStore.setState({ token: null })
    } finally {
      setLoading(false)
    }
  }

  const handleGoogleLogin = () => {
    window.location.href = '/api/auth/google'
  }

  return (
    <div className="min-h-screen flex flex-col bg-[var(--bg-app)] text-[var(--text-primary)] relative overflow-hidden select-none">
      {/* Subtle Grid Background Pattern */}
      <div
        className="absolute inset-0 opacity-[0.03] dark:opacity-[0.07] pointer-events-none"
        style={{
          backgroundImage: `radial-gradient(var(--text-primary) 1px, transparent 1px)`,
          backgroundSize: '24px 24px',
        }}
      />

      {/* Top Header */}
      <header className="flex justify-between items-center px-6 py-4 border-b border-[var(--bg-border-subtle)] relative z-10">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-orange-500 to-amber-600 flex items-center justify-center text-white shadow-sm shadow-orange-500/20">
            <Shield size={17} className="stroke-[2.2]" />
          </div>
          <div>
            <span className="font-bold text-[14px] font-mono tracking-tight text-[var(--text-primary)]">
              CloudWAF
            </span>
            <span className="text-[10px] font-mono text-[var(--text-muted)] ml-1.5 uppercase">
              Control Plane
            </span>
          </div>
        </div>
        <ThemeToggle />
      </header>

      {/* Center Auth Card */}
      <main className="flex-1 flex items-center justify-center px-4 py-8 relative z-10">
        <div className="w-full max-w-sm dash-card p-6 sm:p-7 shadow-2xl border border-[var(--bg-border-hover)]">
          <div className="mb-6">
            <div className="flex items-center gap-2 mb-1">
              <Lock size={16} className="text-orange-500" />
              <h1 className="text-[18px] font-bold tracking-tight font-mono m-0">Sign in to SOC</h1>
            </div>
            <p className="text-[12.5px] text-[var(--text-muted)] m-0">
              Enter your authorized administrator credentials
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-[12.5px]">
            <div>
              <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                Work Email / Username
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
                <input
                  type="text"
                  required
                  placeholder="admin@waf.internal"
                  className="w-full dash-input pl-9 font-mono"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                Security Password
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  className="w-full dash-input pl-9 font-mono"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-orange-500 hover:bg-orange-600 text-white font-mono font-semibold text-[13px] py-2.5 rounded-md flex items-center justify-center gap-2 transition-all disabled:opacity-40 shadow-sm cursor-pointer"
            >
              {loading ? (
                <span>Authenticating...</span>
              ) : (
                <>
                  <span>Authenticate Session</span>
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </form>

          <div className="my-5 flex items-center gap-3">
            <div className="flex-1 h-px bg-[var(--bg-border)]" />
            <span className="text-[11px] font-mono text-[var(--text-muted)] uppercase">or SSO</span>
            <div className="flex-1 h-px bg-[var(--bg-border)]" />
          </div>

          <button
            onClick={handleGoogleLogin}
            type="button"
            className="w-full bg-[var(--bg-surface-elevated)] text-[var(--text-primary)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] py-2.5 text-[12.5px] font-medium rounded-md flex items-center justify-center gap-2.5 hover:bg-[var(--bg-hover)] transition-all shadow-sm cursor-pointer font-mono"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
              />
            </svg>
            <span>Single Sign-On (Google)</span>
          </button>

          <p className="mt-5 text-center text-[12px] text-[var(--text-muted)] font-mono">
            Need an account?{' '}
            <Link to="/register" className="text-orange-500 font-semibold hover:underline">
              Create account
            </Link>
          </p>
        </div>
      </main>
    </div>
  )
}

export default Login
