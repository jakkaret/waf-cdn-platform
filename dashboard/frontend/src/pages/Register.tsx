import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { ThemeToggle } from '../components/ui/ThemeToggle'
import toast from 'react-hot-toast'
import { Shield, ArrowRight, User, Mail, Key } from 'lucide-react'

export const Register: React.FC = () => {
  const [formData, setFormData] = useState({ username: '', email: '', password: '' })
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)

  const score = (() => {
    let s = 0
    const p = formData.password
    if (p.length >= 8) s++
    if (/[A-Z]/.test(p)) s++
    if (/[0-9]/.test(p)) s++
    if (/[^A-Za-z0-9]/.test(p)) s++
    return s
  })()

  const strengthColor =
    score === 0 ? '' : score <= 2 ? '#ef4444' : score === 3 ? '#f59e0b' : '#10b981'
  const strengthLabel =
    score === 0 ? '' : score <= 2 ? 'Weak' : score === 3 ? 'Good' : 'Strong'

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await authApi.register({
        email: formData.email,
        password: formData.password,
        username: formData.username,
      })
      const { access_token } = await authApi.login(formData.email, formData.password)
      useAuthStore.setState({ token: access_token })
      const user = await authApi.getMe()
      setAuth(access_token, user)
      toast.success('Account provisioned successfully')
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

  return (
    <div className="min-h-screen flex flex-col bg-[var(--bg-app)] text-[var(--text-primary)] relative overflow-hidden select-none">
      {/* Subtle Background Pattern */}
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

      {/* Center Form Card */}
      <main className="flex-1 flex items-center justify-center px-4 py-8 relative z-10">
        <div className="w-full max-w-sm dash-card p-6 sm:p-7 shadow-2xl border border-[var(--bg-border-hover)]">
          <div className="mb-6">
            <h1 className="text-[18px] font-bold tracking-tight font-mono mb-1">Create Admin Account</h1>
            <p className="text-[12.5px] text-[var(--text-muted)] m-0">
              Provision credentials for CloudWAF security access
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4 text-[12.5px]">
            <div>
              <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                Username
              </label>
              <div className="relative">
                <User className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
                <input
                  type="text"
                  required
                  placeholder="admin_sec"
                  className="w-full dash-input pl-9 font-mono"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                Work Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
                <input
                  type="email"
                  required
                  placeholder="secops@company.com"
                  className="w-full dash-input pl-9 font-mono"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                />
              </div>
            </div>

            <div>
              <label className="block text-[11px] font-bold uppercase font-mono text-[var(--text-secondary)] mb-1.5">
                Password
              </label>
              <div className="relative">
                <Key className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••"
                  className="w-full dash-input pl-9 font-mono"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                />
              </div>
              {formData.password && (
                <div className="mt-2 space-y-1">
                  <div className="flex gap-1 h-[3px]">
                    {[1, 2, 3, 4].map((i) => (
                      <div
                        key={i}
                        className="flex-1 rounded-full transition-colors"
                        style={{
                          backgroundColor: score >= i ? strengthColor : 'var(--bg-border)',
                        }}
                      />
                    ))}
                  </div>
                  <div className="flex justify-between text-[11px] font-mono">
                    <span style={{ color: strengthColor }} className="font-semibold">
                      {strengthLabel}
                    </span>
                    <span className="text-[var(--text-muted)]">{formData.password.length} chars</span>
                  </div>
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-orange-500 hover:bg-orange-600 text-white font-mono font-semibold text-[13px] py-2.5 rounded-md flex items-center justify-center gap-2 transition-all disabled:opacity-40 shadow-sm cursor-pointer"
            >
              {loading ? (
                <span>Provisioning Account...</span>
              ) : (
                <>
                  <span>Create Account</span>
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </form>

          <p className="mt-5 text-center text-[12px] text-[var(--text-muted)] font-mono">
            Already have an account?{' '}
            <Link to="/login" className="text-orange-500 font-semibold hover:underline">
              Sign in
            </Link>
          </p>
        </div>
      </main>
    </div>
  )
}

export default Register
