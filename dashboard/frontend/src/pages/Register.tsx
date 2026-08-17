import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import toast from 'react-hot-toast'
import { Shield, User, Mail, Lock, ArrowRight, CheckCircle, Globe, Zap } from 'lucide-react'

export const Register: React.FC = () => {
  const [formData, setFormData] = useState({ username: '', email: '', password: '' })
  const [loading, setLoading] = useState(false)
  const [focusedField, setFocusedField] = useState<string | null>(null)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await authApi.register(formData)
      toast.success('Registration successful! Please login.')
      navigate('/login')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      const message = typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ')
          : 'Registration failed'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  const getStrengthScore = (pass: string) => {
    let score = 0
    if (pass.length > 5) score += 1
    if (pass.length > 8) score += 1
    if (/[A-Z]/.test(pass)) score += 1
    if (/[0-9]/.test(pass)) score += 1
    if (/[^A-Za-z0-9]/.test(pass)) score += 1
    return score
  }

  const score = getStrengthScore(formData.password)
  const strengthLabels = ['', 'Weak', 'Fair', 'Good', 'Strong', 'Very Strong']
  const strengthColors = ['', '#fc8181', '#f6ad55', '#76e4f7', '#68d391', '#68d391']
  const strengthLabel = formData.password ? strengthLabels[score] || '' : ''
  const strengthColor = formData.password ? strengthColors[score] || '' : ''

  const inputClasses = (field: string) =>
    `relative flex items-center rounded-xl border transition-all duration-200 ${
      focusedField === field
        ? 'border-accent/40 bg-accent/[0.03] shadow-[0_0_0_3px_rgba(102,126,234,0.08)]'
        : 'border-white/[0.08] bg-white/[0.02] hover:border-white/[0.12]'
    }`

  const iconClasses = (field: string) =>
    `pl-4 transition-colors duration-200 ${focusedField === field ? 'text-accent' : 'text-white/20'}`

  return (
    <div className="min-h-screen flex auth-bg">
      {/* Left Panel — Brand Showcase */}
      <div className="hidden lg:flex lg:w-[45%] relative overflow-hidden flex-col justify-between p-12">
        {/* Grid pattern */}
        <div className="absolute inset-0 auth-grid" />

        {/* Gradient orbs */}
        <div className="absolute top-1/3 right-1/4 w-[350px] h-[350px] bg-accent-dark/10 rounded-full blur-[120px] animate-breathe" />
        <div className="absolute bottom-1/4 left-1/3 w-[300px] h-[300px] bg-accent/8 rounded-full blur-[100px] animate-breathe" style={{ animationDelay: '1.2s' }} />

        {/* Content */}
        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl gradient-brand flex items-center justify-center shadow-glow">
              <Shield size={22} className="text-white" />
            </div>
            <div>
              <h1 className="text-xl font-extrabold text-white tracking-tight font-heading leading-none">WAF</h1>
              <span className="text-[10px] text-accent-light font-semibold tracking-[0.2em] uppercase">Security Platform</span>
            </div>
          </div>
        </div>

        <div className="relative z-10 max-w-md">
          <h2 className="text-[38px] font-extrabold text-white leading-[1.1] tracking-tight font-heading mb-5">
            Start securing<br/>
            <span className="bg-gradient-to-r from-accent to-accent-dark bg-clip-text text-transparent">your infrastructure</span>
          </h2>
          <p className="text-[15px] text-white/40 leading-relaxed mb-10">
            Create your account to access enterprise-grade protection with ML-powered threat intelligence.
          </p>

          {/* Feature list */}
          <div className="flex flex-col gap-4">
            {[
              { icon: <Globe size={16} />, title: 'Global Edge Network', desc: 'Multi-region CDN with WAF at every edge' },
              { icon: <Zap size={16} />, title: 'Instant Setup', desc: 'One-click deployment, no config needed' },
              { icon: <CheckCircle size={16} />, title: 'Free Tier Available', desc: 'Start with 5 origin servers, no credit card' },
            ].map((feat, i) => (
              <div
                key={i}
                className="flex items-start gap-3 animate-fade-in-up"
                style={{ animationDelay: `${0.3 + i * 0.12}s` }}
              >
                <div className="w-8 h-8 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-accent-light shrink-0 mt-0.5">
                  {feat.icon}
                </div>
                <div>
                  <p className="text-[13px] font-semibold text-white/70">{feat.title}</p>
                  <p className="text-[12px] text-white/30 mt-0.5">{feat.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 text-[12px] text-white/20 font-medium">
          © 2026 WAF Security Platform. All rights reserved.
        </div>
      </div>

      {/* Right Panel — Register Form */}
      <div className="flex-1 flex items-center justify-center p-6 sm:p-10 relative">
        {/* Subtle glow */}
        <div className="absolute bottom-0 left-0 w-[300px] h-[300px] bg-accent-dark/5 rounded-full blur-[100px] pointer-events-none" />

        <div className="w-full max-w-[400px] relative z-10">
          {/* Mobile logo */}
          <div className="lg:hidden flex items-center gap-3 mb-10">
            <div className="w-10 h-10 rounded-xl gradient-brand flex items-center justify-center shadow-glow">
              <Shield size={20} className="text-white" />
            </div>
            <div>
              <h1 className="text-lg font-extrabold text-white tracking-tight font-heading leading-none">WAF</h1>
              <span className="text-[10px] text-accent-light font-semibold tracking-[0.2em] uppercase">Security</span>
            </div>
          </div>

          <div className="mb-8">
            <h2 className="text-[28px] font-extrabold text-white tracking-tight font-heading leading-tight">Create account</h2>
            <p className="text-[14px] text-white/35 mt-2">Get started with your security dashboard</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div>
              <label className="block text-[11px] font-bold text-white/30 uppercase tracking-[0.08em] mb-2.5">Username</label>
              <div className={inputClasses('username')}>
                <div className={iconClasses('username')}>
                  <User size={16} />
                </div>
                <input
                  id="register-username"
                  type="text"
                  required
                  placeholder="johndoe"
                  className="w-full bg-transparent px-3 py-3 text-[14px] text-white placeholder:text-white/15 outline-none"
                  value={formData.username}
                  onChange={e => setFormData({ ...formData, username: e.target.value })}
                  onFocus={() => setFocusedField('username')}
                  onBlur={() => setFocusedField(null)}
                />
              </div>
            </div>

            {/* Email */}
            <div>
              <label className="block text-[11px] font-bold text-white/30 uppercase tracking-[0.08em] mb-2.5">Email Address</label>
              <div className={inputClasses('email')}>
                <div className={iconClasses('email')}>
                  <Mail size={16} />
                </div>
                <input
                  id="register-email"
                  type="email"
                  required
                  placeholder="you@company.com"
                  className="w-full bg-transparent px-3 py-3 text-[14px] text-white placeholder:text-white/15 outline-none"
                  value={formData.email}
                  onChange={e => setFormData({ ...formData, email: e.target.value })}
                  onFocus={() => setFocusedField('email')}
                  onBlur={() => setFocusedField(null)}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-[11px] font-bold text-white/30 uppercase tracking-[0.08em] mb-2.5">Password</label>
              <div className={inputClasses('password')}>
                <div className={iconClasses('password')}>
                  <Lock size={16} />
                </div>
                <input
                  id="register-password"
                  type="password"
                  required
                  placeholder="••••••••"
                  className="w-full bg-transparent px-3 py-3 text-[14px] text-white placeholder:text-white/15 outline-none"
                  value={formData.password}
                  onChange={e => setFormData({ ...formData, password: e.target.value })}
                  onFocus={() => setFocusedField('password')}
                  onBlur={() => setFocusedField(null)}
                />
              </div>

              {/* Password strength meter */}
              {formData.password && (
                <div className="mt-3 animate-slide-down">
                  <div className="flex gap-1.5 h-[3px] mb-2">
                    {[1, 2, 3, 4].map(i => (
                      <div
                        key={i}
                        className="flex-1 rounded-full transition-all duration-500"
                        style={{
                          backgroundColor: score >= i ? strengthColor : 'rgba(255,255,255,0.06)',
                          boxShadow: score >= i ? `0 0 6px ${strengthColor}40` : 'none',
                        }}
                      />
                    ))}
                  </div>
                  <div className="flex justify-between items-center">
                    <span
                      className="text-[11px] font-semibold transition-colors duration-300"
                      style={{ color: strengthColor || 'rgba(255,255,255,0.2)' }}
                    >
                      {strengthLabel}
                    </span>
                    <span className="text-[11px] text-white/15">{formData.password.length} characters</span>
                  </div>
                </div>
              )}
            </div>
            
            {/* Submit */}
            <button
              id="register-submit"
              type="submit"
              disabled={loading}
              className="w-full mt-2 gradient-brand text-white font-semibold text-[14px] py-3 rounded-xl
                         shadow-md hover:shadow-glow transition-all duration-300
                         shimmer-hover press-scale
                         disabled:opacity-50 disabled:cursor-not-allowed
                         flex items-center justify-center gap-2"
            >
              {loading ? (
                <svg className="animate-spin h-4 w-4 text-current" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
              ) : (
                <>
                  Create Account
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          <p className="mt-8 text-center text-[13px] text-white/25">
            Already have an account?{' '}
            <Link to="/login" className="text-accent font-semibold hover:text-accent-light transition-colors">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}

export default Register
