import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { ThemeToggle } from '../components/ui/ThemeToggle'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import {
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Mail,
  ShieldCheck,
  User,
  UsersRound,
} from 'lucide-react'

const passwordChecks = [
  { label: '8+ characters', test: (value: string) => value.length >= 8 },
  { label: 'Uppercase letter', test: (value: string) => /[A-Z]/.test(value) },
  { label: 'Number', test: (value: string) => /[0-9]/.test(value) },
  { label: 'Symbol', test: (value: string) => /[^A-Za-z0-9]/.test(value) },
]

export const Register: React.FC = () => {
  const [formData, setFormData] = useState({ username: '', email: '', password: '', confirmPassword: '' })
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)

  const score = passwordChecks.filter((check) => check.test(formData.password)).length
  const strengthColor = score === 0 ? 'var(--text-muted)' : score <= 2 ? '#ef4444' : score === 3 ? '#f59e0b' : '#10b981'
  const strengthLabel = score === 0 ? 'No password yet' : score <= 2 ? 'Weak' : score === 3 ? 'Good' : 'Strong'
  const passwordsMatch = formData.confirmPassword.length > 0 && formData.password === formData.confirmPassword

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.username.trim() || !formData.email.trim() || !formData.password || !formData.confirmPassword) {
      toast.error('Please fill in all fields')
      return
    }

    if (score < 4) {
      toast.error('Use a stronger password before creating this account')
      return
    }

    if (formData.password !== formData.confirmPassword) {
      toast.error('Password confirmation does not match')
      return
    }

    setLoading(true)
    try {
      await authApi.register({
        email: formData.email.trim(),
        password: formData.password,
        username: formData.username.trim(),
      })
      const { access_token } = await authApi.login(formData.email.trim(), formData.password)
      useAuthStore.setState({ token: access_token })
      const user = await authApi.getMe()
      setAuth(access_token, user)
      toast.success('Account created successfully')
      navigate('/')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      const message =
        typeof detail === 'string'
          ? detail
          : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ')
          : 'Registration failed'
      toast.error(message)
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
                Secure Workspace Enrollment
              </div>
              <h1 className="mt-6 max-w-xl text-[34px] font-bold leading-tight tracking-tight text-[var(--text-primary)] font-mono">
                Create access for the WAF operations workspace.
              </h1>
              <p className="mt-4 max-w-xl text-[13.5px] leading-6 text-[var(--text-secondary)]">
                The first local account becomes admin. Later local accounts begin as viewer until an admin changes the role.
              </p>
            </div>

            <div className="grid max-w-2xl grid-cols-3 gap-3">
              {[
                { icon: ShieldCheck, label: 'Bootstrap', value: 'First admin' },
                { icon: UsersRound, label: 'Default role', value: 'Viewer' },
                { icon: KeyRound, label: 'Password', value: 'Argon2 hash' },
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
            <div className="w-full max-w-[440px]">
              
              {/* Mobile badge */}
              <div className="mb-5 lg:hidden text-center">
                <div className="inline-flex items-center gap-2 rounded-full border border-orange-500/20 bg-orange-500/10 px-3 py-1 text-[11px] font-mono font-semibold uppercase tracking-[0.1em] text-orange-600 dark:text-orange-400">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  Secure Workspace Enrollment
                </div>
              </div>

              {/* Segmented Auth Switcher Group */}
              <div className="grid grid-cols-2 p-1 bg-[var(--bg-primary)] rounded-lg border border-[var(--bg-border)] mb-4">
                <Link
                  to="/login"
                  className="py-1.5 text-center text-[12px] font-mono font-medium rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  to="/register"
                  className="py-1.5 text-center text-[12px] font-mono font-semibold rounded-md bg-[var(--bg-surface-elevated)] text-orange-600 dark:text-orange-400 shadow-sm border border-[var(--bg-border)]"
                >
                  Register
                </Link>
              </div>

              <div className="dash-card border-[var(--bg-border)] bg-[var(--bg-surface)] p-5 shadow-xl sm:p-6">
                <div className="mb-5 flex items-start justify-between gap-4">
                  <div>
                    <h2 className="m-0 text-[20px] font-bold tracking-tight text-[var(--text-primary)] font-mono">
                      Create account
                    </h2>
                    <p className="mt-1 mb-0 text-[12.5px] leading-5 text-[var(--text-muted)]">
                      Set up local access for Firewall WAF.
                    </p>
                  </div>
                  <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 p-2 text-orange-600 dark:text-orange-400">
                    <ShieldCheck size={18} />
                  </div>
                </div>

                <div className="mb-4 rounded-lg border border-[var(--bg-border-subtle)] bg-[var(--bg-primary)] px-3 py-2.5 text-[12px] leading-5 text-[var(--text-secondary)]">
                  <span className="font-semibold text-[var(--text-primary)]">Role policy:</span> first account is admin; later accounts start as viewer.
                </div>

                <form onSubmit={handleSubmit} className="space-y-4 text-[13px]">
                  <div>
                    <label className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      Username
                    </label>
                    <div className="relative">
                      <User className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        type="text"
                        required
                        autoComplete="username"
                        placeholder="operator-name"
                        className="w-full dash-input pl-9 pr-3 py-2 text-[13px]"
                        value={formData.username}
                        onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      Email
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        type="email"
                        required
                        autoComplete="email"
                        placeholder="operator@example.com"
                        className="w-full dash-input pl-9 pr-3 py-2 text-[13px]"
                        value={formData.email}
                        onChange={(e) => setFormData({ ...formData, email: e.target.value })}
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
                        autoComplete="new-password"
                        placeholder="Password"
                        className="w-full dash-input pl-9 pr-10 py-2 text-[13px]"
                        value={formData.password}
                        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
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

                    <div className="mt-2 space-y-2">
                      <div className="flex gap-1 h-1">
                        {[1, 2, 3, 4].map((i) => (
                          <div
                            key={i}
                            className="flex-1 rounded-full transition-colors"
                            style={{ backgroundColor: score >= i ? strengthColor : 'var(--bg-border)' }}
                          />
                        ))}
                      </div>
                      <div className="flex items-center justify-between text-[11px] font-mono">
                        <span style={{ color: strengthColor }}>{strengthLabel}</span>
                        <span className="text-[var(--text-muted)]">{formData.password.length} chars</span>
                      </div>
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] text-[var(--text-muted)]">
                        {passwordChecks.map((check) => {
                          const passed = check.test(formData.password)
                          return (
                            <span key={check.label} className="flex items-center gap-1.5">
                              <CheckCircle2 size={12} className={passed ? 'text-emerald-500' : 'text-[var(--text-dim)]'} />
                              {check.label}
                            </span>
                          )
                        })}
                      </div>
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      Confirm password
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        type={showPassword ? 'text' : 'password'}
                        required
                        autoComplete="new-password"
                        placeholder="Confirm password"
                        className="w-full dash-input pl-9 pr-3 py-2 text-[13px]"
                        value={formData.confirmPassword}
                        onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                      />
                    </div>
                    {formData.confirmPassword && (
                      <p className={`mt-1.5 mb-0 text-[11px] ${passwordsMatch ? 'text-emerald-500' : 'text-red-500'}`}>
                        {passwordsMatch ? 'Passwords match' : 'Passwords do not match'}
                      </p>
                    )}
                  </div>

                  <Button type="submit" disabled={loading} isLoading={loading} variant="brand" className="w-full py-2.5">
                    {loading ? (
                      'Creating workspace access...'
                    ) : (
                      <>
                        <span>Create account / Register</span>
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
                  Already have access?{' '}
                  <Link to="/login" className="text-orange-600 dark:text-orange-500 font-semibold underline-offset-4 hover:underline">
                    Sign in
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

export default Register
