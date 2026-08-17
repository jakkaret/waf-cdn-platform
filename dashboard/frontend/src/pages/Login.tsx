import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'
import { Shield, Mail, Lock, ArrowRight, Fingerprint, Radar, ShieldCheck } from 'lucide-react'

export const Login: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [focusedField, setFocusedField] = useState<string | null>(null)
  const navigate = useNavigate()
  const setAuth = useAuthStore(state => state.setAuth)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const { access_token } = await authApi.login(email, password)
      
      // Temporarily set token in store to allow getMe to work
      useAuthStore.setState({ token: access_token })
      
      const user = await authApi.getMe()
      setAuth(access_token, user)
      toast.success('Logged in successfully')
      navigate('/')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      const message = typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ')
          : 'Login failed'
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
    <div className="min-h-screen flex auth-bg">
      {/* Left Panel — Brand Showcase */}
      <div className="hidden lg:flex lg:w-[45%] relative overflow-hidden flex-col justify-between p-12">
        {/* Grid pattern */}
        <div className="absolute inset-0 auth-grid" />
        
        {/* Gradient orbs */}
        <div className="absolute top-1/4 left-1/4 w-[400px] h-[400px] bg-accent/10 rounded-full blur-[120px] animate-breathe" />
        <div className="absolute bottom-1/4 right-1/4 w-[300px] h-[300px] bg-accent-dark/10 rounded-full blur-[100px] animate-breathe" style={{ animationDelay: '1s' }} />
        
        {/* Content */}
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
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
          <h2 className="text-[40px] font-extrabold text-white leading-[1.1] tracking-tight font-heading mb-5">
            Protect your<br/>
            <span className="bg-gradient-to-r from-accent to-accent-dark bg-clip-text text-transparent">digital perimeter</span>
          </h2>
          <p className="text-[15px] text-white/40 leading-relaxed mb-10">
            Enterprise-grade Web Application Firewall with AI-powered threat detection, real-time monitoring, and global CDN edge protection.
          </p>

          {/* Feature pills */}
          <div className="flex flex-col gap-3">
            {[
              { icon: <ShieldCheck size={16} />, text: 'AI-Powered Threat Detection' },
              { icon: <Radar size={16} />, text: 'Real-time Traffic Monitoring' },
              { icon: <Fingerprint size={16} />, text: 'Zero-day Attack Prevention' },
            ].map((feat, i) => (
              <div
                key={i}
                className="flex items-center gap-3 text-[13px] text-white/50 animate-fade-in-up"
                style={{ animationDelay: `${0.3 + i * 0.1}s` }}
              >
                <div className="w-8 h-8 rounded-lg bg-white/[0.04] border border-white/[0.06] flex items-center justify-center text-accent-light shrink-0">
                  {feat.icon}
                </div>
                <span className="font-medium">{feat.text}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="relative z-10 text-[12px] text-white/20 font-medium">
          © 2026 WAF Security Platform. All rights reserved.
        </div>
      </div>

      {/* Right Panel — Login Form */}
      <div className="flex-1 flex items-center justify-center p-6 sm:p-10 relative">
        {/* Subtle top-right glow */}
        <div className="absolute top-0 right-0 w-[300px] h-[300px] bg-accent/5 rounded-full blur-[100px] pointer-events-none" />

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
            <h2 className="text-[28px] font-extrabold text-white tracking-tight font-heading leading-tight">Welcome back</h2>
            <p className="text-[14px] text-white/35 mt-2">Sign in to access your security dashboard</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email field */}
            <div>
              <label className="block text-[11px] font-bold text-white/30 uppercase tracking-[0.08em] mb-2.5">Email Address</label>
              <div className={`relative flex items-center rounded-xl border transition-all duration-200 ${
                focusedField === 'email'
                  ? 'border-accent/40 bg-accent/[0.03] shadow-[0_0_0_3px_rgba(102,126,234,0.08)]'
                  : 'border-white/[0.08] bg-white/[0.02] hover:border-white/[0.12]'
              }`}>
                <div className={`pl-4 transition-colors duration-200 ${focusedField === 'email' ? 'text-accent' : 'text-white/20'}`}>
                  <Mail size={16} />
                </div>
                <input
                  id="login-email"
                  type="email"
                  required
                  placeholder="you@company.com"
                  className="w-full bg-transparent px-3 py-3 text-[14px] text-white placeholder:text-white/15 outline-none"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  onFocus={() => setFocusedField('email')}
                  onBlur={() => setFocusedField(null)}
                />
              </div>
            </div>

            {/* Password field */}
            <div>
              <label className="block text-[11px] font-bold text-white/30 uppercase tracking-[0.08em] mb-2.5">Password</label>
              <div className={`relative flex items-center rounded-xl border transition-all duration-200 ${
                focusedField === 'password'
                  ? 'border-accent/40 bg-accent/[0.03] shadow-[0_0_0_3px_rgba(102,126,234,0.08)]'
                  : 'border-white/[0.08] bg-white/[0.02] hover:border-white/[0.12]'
              }`}>
                <div className={`pl-4 transition-colors duration-200 ${focusedField === 'password' ? 'text-accent' : 'text-white/20'}`}>
                  <Lock size={16} />
                </div>
                <input
                  id="login-password"
                  type="password"
                  required
                  placeholder="••••••••"
                  className="w-full bg-transparent px-3 py-3 text-[14px] text-white placeholder:text-white/15 outline-none"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  onFocus={() => setFocusedField('password')}
                  onBlur={() => setFocusedField(null)}
                />
              </div>
            </div>
            
            {/* Sign In button */}
            <button
              id="login-submit"
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
                  Sign In
                  <ArrowRight size={16} />
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="my-7 flex items-center gap-4">
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/[0.08] to-transparent"></div>
            <span className="text-[11px] text-white/20 font-medium tracking-wider uppercase">or continue with</span>
            <div className="flex-1 h-px bg-gradient-to-r from-transparent via-white/[0.08] to-transparent"></div>
          </div>

          {/* Google OAuth */}
          <button
            id="login-google"
            onClick={handleGoogleLogin}
            className="w-full flex items-center justify-center gap-2.5 py-2.5 rounded-xl
                       bg-white/[0.04] border border-white/[0.08]
                       text-[13px] font-medium text-white/60
                       hover:bg-white/[0.07] hover:border-white/[0.12] hover:text-white/80
                       transition-all duration-200 press-scale"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
              <path fill="#34A853" d="M12 24c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 21.53 7.7 24 12 24z" />
              <path fill="#FBBC05" d="M5.84 15.1c-.22-.66-.35-1.36-.35-2.1s.13-1.44.35-2.1V8.06H2.18C1.43 9.55 1 11.22 1 13s.43 3.45 1.18 4.94l3.66-2.84z" />
              <path fill="#EA4335" d="M12 4.69c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 1.18 14.97 0 12 0 7.7 0 3.99 2.47 2.18 6.06l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
            </svg>
            Continue with Google
          </button>

          <p className="mt-8 text-center text-[13px] text-white/25">
            Don't have an account?{' '}
            <Link to="/register" className="text-accent font-semibold hover:text-accent-light transition-colors">
              Create account
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}

export default Login
