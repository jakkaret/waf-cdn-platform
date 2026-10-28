import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { ThemeToggle } from '../components/ui/ThemeToggle'
import { LanguageToggle } from '../components/ui/LanguageToggle'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import { passwordChecks } from '../lib/passwordRules'
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
import { useT } from '../i18n'


export const Register: React.FC = () => {
  const [formData, setFormData] = useState({ username: '', email: '', password: '', confirmPassword: '' })
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)
  const { t } = useT()

  const score = passwordChecks.filter((check) => check.test(formData.password)).length
  const strengthColor = score === 0 ? 'var(--text-muted)' : score <= 2 ? '#ef4444' : score === 3 ? '#f59e0b' : '#10b981'
  const strengthLabel =
    score === 0 ? t('No password yet', 'ยังไม่ได้ตั้งรหัสผ่าน') : score <= 2 ? t('Weak', 'อ่อน') : score === 3 ? t('Good', 'พอใช้') : t('Strong', 'แข็งแรง')
  const passwordsMatch = formData.confirmPassword.length > 0 && formData.password === formData.confirmPassword

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.username.trim() || !formData.email.trim() || !formData.password || !formData.confirmPassword) {
      toast.error(t('Please fill in all fields', 'กรุณากรอกข้อมูลให้ครบ'))
      return
    }

    if (score < 4) {
      toast.error(t('Use a stronger password before creating this account', 'ตั้งรหัสผ่านให้แข็งแรงกว่านี้ก่อนสร้างบัญชี'))
      return
    }

    if (formData.password !== formData.confirmPassword) {
      toast.error(t('Password confirmation does not match', 'ยืนยันรหัสผ่านไม่ตรงกัน'))
      return
    }

    setLoading(true)
    try {
      await authApi.register({
        email: formData.email.trim(),
        password: formData.password,
        username: formData.username.trim(),
      })
      await authApi.login(formData.email.trim(), formData.password) // sets the HttpOnly session cookie
      const user = await authApi.getMe()
      setAuth(user)
      toast.success(t('Account created. Verify your email with the code we sent.', 'สร้างบัญชีแล้ว ยืนยันอีเมลด้วยรหัสที่ส่งไปให้'))
      navigate('/verify-email')
    } catch (err: any) {
      // Matches Login.tsx's identical login->getMe flow: if getMe() throws
      // after the token was already set into the store, reset it here too
      // -- otherwise a real bearer token sits in the persisted store while
      // isAuthenticated stays false, and axios keeps attaching it to
      // subsequent requests as a stale/orphaned credential.
      useAuthStore.getState().logout()
      const detail = err.response?.data?.detail
      const message =
        typeof detail === 'string'
          ? detail
          : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ')
          : t('Registration failed', 'สมัครสมาชิกไม่สำเร็จ')
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  const handleGoogleLogin = () => {
    window.location.href = '/api/auth/google'
  }

  return (
    <div className="min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)] flex flex-col">
      <header className="border-b border-[var(--bg-border-subtle)] bg-[var(--bg-app)]/85 backdrop-blur">
        <div className="max-w-7xl mx-auto flex justify-between items-center px-4 sm:px-8 py-4">
          <Link to="/" className="flex items-center gap-2.5 rounded-md focus:outline-none focus:ring-2 focus:ring-orange-500/50">
            <img src="/itkku-logo.png" alt="IT KKU" className="w-9 h-9 object-contain" />
            <div className="leading-tight">
              <span className="block font-bold text-[15px] tracking-tight">
                <span className="text-[#a34830] dark:text-[#d0674a]">IT</span> <span className="text-[#89898a] dark:text-[#a3a3a4]">KKU</span>
              </span>
              <span className="block text-[10px] font-mono tracking-[0.12em] text-[var(--text-muted)]">
                WAF &amp; CDN
              </span>
            </div>
          </Link>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <LanguageToggle />
          </div>
        </div>
      </header>

      <main className="flex-1 mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-10 lg:py-14 w-full">
        <div className="w-full grid grid-cols-1 lg:grid-cols-12 gap-10 lg:gap-14 items-start">

          {/* Left: what you're getting access to. Shown on mobile too, below
              the form -- previously `hidden lg:flex` dropped this entire
              panel below 1024px, so a phone user saw only a bare form with
              no context on what role they'd land in or what it can do. */}
          <section className="order-2 lg:order-1 flex lg:col-span-7 xl:col-span-7 flex-col gap-8 pr-4">
            <div className="hidden lg:block">
              <h1 className="max-w-xl text-[32px] font-bold leading-tight tracking-tight text-[var(--text-primary)] font-mono">
                {t('Create access for the WAF operations workspace.', 'สร้างบัญชีเพื่อเข้าใช้ศูนย์ควบคุม WAF')}
              </h1>
              <p className="mt-3 max-w-lg text-[13.5px] leading-6 text-[var(--text-secondary)]">
                {t(
                  'The first local account becomes admin. Later local accounts begin as viewer until an admin changes the role.',
                  'บัญชีแรกของระบบจะเป็น admin บัญชีถัดไปเริ่มเป็น viewer จนกว่า admin จะเปลี่ยนสิทธิ์ให้',
                )}
              </p>
            </div>

            <div className="grid max-w-lg grid-cols-3 gap-3.5">
              {[
                { icon: ShieldCheck, label: t('Bootstrap', 'บัญชีแรก'), value: t('First admin', 'เป็น admin') },
                { icon: UsersRound, label: t('Default role', 'สิทธิ์เริ่มต้น'), value: t('User', 'ผู้ใช้') },
                { icon: KeyRound, label: t('Password', 'รหัสผ่าน'), value: 'Argon2 hash' },
              ].map((item) => {
                const Icon = item.icon
                return (
                  <div key={item.label} className="dash-card p-4">
                    <Icon size={16} className="text-orange-600 dark:text-orange-400" />
                    <p className="mt-3 mb-0 text-[11px] tracking-[0.08em] text-[var(--text-muted)] font-mono">
                      {item.label}
                    </p>
                    <p className="mt-1 mb-0 text-[13px] font-semibold text-[var(--text-primary)] font-mono">
                      {item.value}
                    </p>
                  </div>
                )
              })}
            </div>

            <div className="dash-card p-5 max-w-lg">
              <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0 mb-3">
                {t('What an operator account can do', 'บัญชีผู้ดูแลทำอะไรได้บ้าง')}
              </h3>
              <ul className="m-0 p-0 list-none space-y-2.5 text-[12.5px] text-[var(--text-secondary)]">
                {[
                  t('Review blocked and allowed traffic across every protected origin', 'ตรวจทราฟฟิกที่ถูกบล็อกและที่ผ่านได้ของทุก origin ที่ป้องกันอยู่'),
                  t('Attach domains, issue tunnel tokens, and manage WAF policy', 'ผูกโดเมน ออก tunnel token และจัดการนโยบาย WAF'),
                  t('Approve or reject ML-suggested rules before they take effect', 'อนุมัติหรือปฏิเสธกฎที่ ML เสนอก่อนนำไปใช้จริง'),
                ].map((line) => (
                  <li key={line} className="flex items-start gap-2.5">
                    <CheckCircle2 size={14} className="text-emerald-500 shrink-0 mt-0.5" />
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>
          </section>

          {/* Right: the actual form */}
          <section className="order-1 lg:order-2 col-span-1 lg:col-span-5 xl:col-span-5 flex justify-center lg:justify-end">
            <div className="w-full max-w-[420px]">

              {/* Mobile heading */}
              <div className="mb-5 lg:hidden">
                <h1 className="text-[24px] font-bold leading-tight tracking-tight text-[var(--text-primary)] font-mono">
                  {t('Create workspace access', 'สร้างบัญชีเข้าใช้งาน')}
                </h1>
              </div>

              {/* Segmented Auth Switcher Group */}
              <div className="grid grid-cols-2 p-1 bg-[var(--bg-primary)] rounded-lg border border-[var(--bg-border)] mb-4">
                <Link
                  to="/login"
                  className="py-1.5 text-center text-[12px] font-mono font-medium rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  {t('Sign In', 'ลงชื่อเข้าใช้')}
                </Link>
                <Link
                  to="/register"
                  className="py-1.5 text-center text-[12px] font-mono font-semibold rounded-md bg-[var(--bg-surface-elevated)] text-orange-600 dark:text-orange-400 shadow-sm border border-[var(--bg-border)]"
                >
                  {t('Register', 'สมัครสมาชิก')}
                </Link>
              </div>

              <div className="dash-card border-[var(--bg-border)] bg-[var(--bg-surface)] p-5 shadow-xl sm:p-6">
                <div className="mb-5 flex items-start justify-between gap-4">
                  <div>
                    <h2 className="m-0 text-[20px] font-bold tracking-tight text-[var(--text-primary)] font-mono">
                      {t('Create account', 'สร้างบัญชี')}
                    </h2>
                    <p className="mt-1 mb-0 text-[12.5px] leading-5 text-[var(--text-muted)]">
                      {t('Set up local access for IT KKU WAF.', 'สร้างบัญชีสำหรับเข้าใช้ IT KKU WAF')}
                    </p>
                  </div>
                  <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 p-2 text-orange-600 dark:text-orange-400">
                    <ShieldCheck size={18} />
                  </div>
                </div>

                <div className="mb-4 rounded-lg border border-[var(--bg-border-subtle)] bg-[var(--bg-primary)] px-3 py-2.5 text-[12px] leading-5 text-[var(--text-secondary)]">
                  <span className="font-semibold text-[var(--text-primary)]">{t('Role policy:', 'นโยบายสิทธิ์:')}</span>{' '}
                  {t('first account is admin; later accounts start as viewer.', 'บัญชีแรกเป็น admin บัญชีถัดไปเริ่มเป็น viewer')}
                </div>

                <form onSubmit={handleSubmit} className="space-y-4 text-[13px]">
                  <div>
                    <label htmlFor="register-username" className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      {t('Username', 'ชื่อผู้ใช้')}
                    </label>
                    <div className="relative">
                      <User className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        id="register-username"
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
                    <label htmlFor="register-email" className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      {t('Email', 'อีเมล')}
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        id="register-email"
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
                    <label htmlFor="register-password" className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      {t('Password', 'รหัสผ่าน')}
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        id="register-password"
                        type={showPassword ? 'text' : 'password'}
                        required
                        autoComplete="new-password"
                        placeholder={t('Password', 'รหัสผ่าน')}
                        className="w-full dash-input pl-9 pr-10 py-2 text-[13px]"
                        value={formData.password}
                        onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? t('Hide password', 'ซ่อนรหัสผ่าน') : t('Show password', 'แสดงรหัสผ่าน')}
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
                        <span className="text-[var(--text-muted)]">{formData.password.length} {t('chars', 'ตัวอักษร')}</span>
                      </div>
                      <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] text-[var(--text-muted)]">
                        {passwordChecks.map((check) => {
                          const passed = check.test(formData.password)
                          return (
                            <span key={check.label} className="flex items-center gap-1.5">
                              <CheckCircle2 size={12} className={passed ? 'text-emerald-500' : 'text-[var(--text-dim)]'} />
                              {t(check.label, check.labelTh)}
                            </span>
                          )
                        })}
                      </div>
                    </div>
                  </div>

                  <div>
                    <label htmlFor="register-confirm-password" className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                      {t('Confirm password', 'ยืนยันรหัสผ่าน')}
                    </label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                      <input
                        id="register-confirm-password"
                        type={showPassword ? 'text' : 'password'}
                        required
                        autoComplete="new-password"
                        placeholder={t('Confirm password', 'ยืนยันรหัสผ่าน')}
                        className="w-full dash-input pl-9 pr-3 py-2 text-[13px]"
                        value={formData.confirmPassword}
                        onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                      />
                    </div>
                    {formData.confirmPassword && (
                      <p className={`mt-1.5 mb-0 text-[11px] ${passwordsMatch ? 'text-emerald-500' : 'text-red-500'}`}>
                        {passwordsMatch ? t('Passwords match', 'รหัสผ่านตรงกัน') : t('Passwords do not match', 'รหัสผ่านไม่ตรงกัน')}
                      </p>
                    )}
                  </div>

                  <Button type="submit" disabled={loading} isLoading={loading} variant="brand" className="w-full py-2.5">
                    {loading ? (
                      t('Creating workspace access...', 'กำลังสร้างบัญชี...')
                    ) : (
                      <>
                        <span>{t('Create account', 'สร้างบัญชี')}</span>
                        <ArrowRight size={14} />
                      </>
                    )}
                  </Button>
                </form>

                <div className="my-5 flex items-center gap-3">
                  <div className="flex-1 h-px bg-[var(--bg-border)]" />
                  <span className="text-[11px] text-[var(--text-muted)] font-mono">
                    {t('Or continue with', 'หรือดำเนินการต่อด้วย')}
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
                  <span>{t('Continue with Google', 'ดำเนินการต่อด้วย Google')}</span>
                </button>

                <p className="mt-5 text-center text-[12px] text-[var(--text-muted)]">
                  {t('Already have access?', 'มีบัญชีอยู่แล้ว?')}{' '}
                  <Link to="/login" className="text-orange-600 dark:text-orange-500 font-semibold underline-offset-4 hover:underline">
                    {t('Sign in', 'ลงชื่อเข้าใช้')}
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
