import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { ThemeToggle } from '../components/ui/ThemeToggle'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import {
  Activity,
  ArrowRight,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Mail,
  ShieldCheck,
} from 'lucide-react'

export const Login: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!email.trim() || !password.trim()) {
      toast.error('Please fill in all fields')
      return
    }

    setLoading(true)
    try {
      const { access_token } = await authApi.login(email.trim(), password)
      useAuthStore.setState({ token: access_token })
      const user = await authApi.getMe()
      setAuth(access_token, user)
      toast.success('Signed in successfully')
      navigate('/')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      const message =
        typeof detail === 'string'
          ? detail
          : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ')
          : 'Invalid email or password'
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
    <div className="min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)] relative overflow-hidden flex flex-col justify-between">
      <div className="pointer-events-none absolute inset-0 opacity-70">
        <div className="absolute left-[-12rem] top-[-14rem] h-[28rem] w-[28rem] rounded-full bg-orange-500/10 blur-3xl" />
        <div className="absolute bottom-[-16rem] right-[-10rem] h-[30rem] w-[30rem] rounded-full bg-cyan-500/10 blur-3xl" />
      </div>

      <header className="relative z-10 border-b border-[var(--bg-border-subtle)] bg-[var(--bg-app)]/85 backdrop-blur">
        <div className="max-w-7xl mx-auto flex justify-between items-center px-4 sm:px-8 py-4">
          <Link to="/" className="flex items-center gap-2.5 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500/50">
            <img src="/firewall.png" alt="Firewall WAF" className="w-8 h-8 object-contain rounded-lg drop-shadow-sm" />
            <div className="leading-tight">
              <span className="block font-bold text-[14px] font-mono tracking-tight text-[var(--text-primary)]">
                Firewall WAF
              </span>
              <span className="block text-[10px] font-mono uppercase tracking-[0.12em] text-[var(--text-muted)]">
                Edge Control
              </span>
            </div>
          </Link>
          <ThemeToggle />
        </div>
      </header>

      <main className="relative z-10 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 lg:py-12 flex-1 flex items-center justify-center w-full">
        <div className="w-full grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-center">
          
          {/* Left Brand / Features Section */}
          <section className="hidden lg:flex lg:col-span-7 xl:col-span-7 flex-col justify-between space-y-8 pr-4">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-orange-500/20 bg-orange-500/10 px-3 py-1 text-[11px] font-mono font-semibold uppercase tracking-[0.1em] text-orange-600 dark:text-orange-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.65)]" />
                ModSec CRS Control Plane
              </div>
              <h1 className="mt-6 max-w-xl text-[34px] font-bold leading-tight tracking-tight text-[var(--text-primary)] font-mono">
                Operator access for WAF, CDN edge, and ML rule review.
              </h1>
              <p className="mt-4 max-w-xl text-[13.5px] leading-6 text-[var(--text-secondary)]">
                Sign in to review traffic evidence, edge health, alert routing, and policy changes from the same protected workspace.
              </p>
            </div>

            <div className="grid max-w-lg grid-cols-2 gap-3.5">
              {[
                { icon: ShieldCheck, label: 'WAF policy', value: 'RBAC gated' },
                { icon: Activity, label: 'Signals', value: 'Logs + ML' },
              ].map((item) => {
                const Icon = item.icon
                return (
                  <div key={item.label} className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)]/80 p-4">
                    <Icon size={16} className="text-orange-600 dark:text-orange-400" />
                    <p className="mt-3 mb-0 text-[11px] uppercase tracking-[0.08em] text-[var(--text-muted)] font-mono">
                      {item.label}
                    </p>
                    <p className="mt-1 mb-0 text-[13px] font-semibold text-[var(--text-primary)] font-mono">
                      {item.value}
                    </p>
                  </div>
                )
              })}
            </div>
          </section>

          {/* Right Auth Card Section */}
          <section className="col-span-1 lg:col-span-5 xl:col-span-5 flex items-center justify-center lg:justify-end">
            <div className="w-full max-w-[420px]">
              
              {/* Mobile badge */}
              <div className="mb-5 lg:hidden text-center">
                <div className="inline-flex items-center gap-2 rounded-full border border-orange-500/20 bg-orange-500/10 px-3 py-1 text-[11px] font-mono font-semibold uppercase tracking-[0.1em] text-orange-600 dark:text-orange-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  ModSec CRS Control Plane
                </div>
              </div>

              {/* Segmented Auth Switcher Group */}
              <div className="grid grid-cols-2 p-1 bg-[var(--bg-primary)] rounded-lg border border-[var(--bg-border)] mb-4">
                <Link
                  to="/login"
                  className="py-1.5 text-center text-[12px] font-mono font-semibold rounded-md bg-[var(--bg-surface-elevated)] text-orange-600 dark:text-orange-400 shadow-sm border border-[var(--bg-border)]"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="py-1.5 text-center text-[12px] font-mono font-medium rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  Register
                </Link>
              </div>

              <div className="dash-card border-[var(--bg-border)] bg-[var(--bg-surface)] p-5 shadow-xl sm:p-6">
                <div className="mb-5 flex items-start justify-between gap-4">
                  <div>
                    <h2 className="m-0 text-[20px] font-bold tracking-tight text-[var(--text-primary)] font-mono">
                      Sign in
                    </h2>
                    <p className="mt-1 mb-0 text-[12.5px] leading-5 text-[var(--text-muted)]">
                      Continue to the Firewall WAF operations console.
                    </p>
                  </div>
                  <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 p-2 text-orange-600 dark:text-orange-400">
                    <KeyRound size={18} />
                  </div>
                </div>

                <form onSubmit={handleSubmit} className="space-y-4 text-[13px]">
                  <div>
                    <label className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      Email or username
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        type="text"
                        required
                        autoComplete="username"
                        placeholder="operator@example.com"
                        className="w-full dash-input pl-9 pr-3 py-2 text-[13px]"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      Password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        autoComplete="current-password"
                        placeholder="Password"
                        className="w-full dash-input pl-9 pr-10 py-2 text-[13px]"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        className="absolute right-2.5 top-2 p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] focus:outline-none focus:ring-2 focus:ring-orange-500/40 transition-colors cursor-pointer"
                      >
                        {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                      </button>
                    </div>
                  </div>

                  <Button type="submit" disabled={loading} isLoading={loading} variant="brand" className="w-full py-2.5">
                    {loading ? (
                      'Verifying access...'
                    ) : (
                      <>
                        <span>Sign in to console</span>
                        <ArrowRight size={14} />
                      </>
                    )}
                  </Button>
                </form>

                <div className="my-5 flex items-center gap-3">
                  <div className="flex-1 h-px bg-[var(--bg-border)]" />
                  <span className="text-[11px] text-[var(--text-muted)] font-mono uppercase tracking-wider">
                    Or continue with
                  </span>
                  <div className="flex-1 h-px bg-[var(--bg-border)]" />
                </div>

                <button
                  onClick={handleGoogleLogin}
                  type="button"
                  className="w-full bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] py-2 text-[12.5px] font-medium rounded-md flex items-center justify-center gap-2.5 transition-colors focus:outline-none focus:ring-2 focus:ring-orange-500/40 cursor-pointer"
                >
                  <svg className="w-4 h-4" viewBox="0 0 24 24" aria-hidden="true">
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
                  <span>Continue with Google</span>
                </button>

                <p className="mt-5 text-center text-[12px] text-[var(--text-muted)]">
                  Need an operator account?{' '}
                  <Link to="/register" className="text-orange-600 dark:text-orange-500 font-semibold underline-offset-4 hover:underline">
                    Create one
                  </Link>
                </p>
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  )
}

export default Login
