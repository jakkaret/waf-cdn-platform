import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { ArrowLeft, ArrowRight, Check, Eye, EyeOff, KeyRound, Lock, Mail, MonitorSmartphone, RotateCw } from 'lucide-react'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { AuthShell } from '../components/auth/AuthShell'
import { OtpInput } from '../components/auth/OtpInput'
import { Button } from '../components/ui/Button'
import { passwordChecks, passwordScore } from '../lib/passwordRules'
import { formatCountdown } from '../lib/emailGate'

// Forgot password: a 6-digit code goes to the mailbox (the answer is the same
// whether or not the address has an account), then the code plus a new
// password resets it and signs the account out on every device.

const RESEND_SECONDS = 60

export const ForgotPassword: React.FC = () => {
  const navigate = useNavigate()
  const [step, setStep] = useState<'email' | 'reset'>('email')
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [invalid, setInvalid] = useState(false)
  const [error, setError] = useState('')
  const [wait, setWait] = useState(0)

  useEffect(() => {
    if (wait <= 0) return
    const t = setTimeout(() => setWait((w) => w - 1), 1000)
    return () => clearTimeout(t)
  }, [wait])

  const score = passwordScore(password)
  const matches = confirm.length > 0 && password === confirm

  const requestCode = async (e?: React.FormEvent) => {
    e?.preventDefault()
    if (!email.trim()) return
    setLoading(true)
    try {
      const res = await authApi.forgotPassword(email.trim())
      toast.success(res.message)
      setStep('reset')
      setWait(RESEND_SECONDS)
    } catch (err: any) {
      toast.error(err.response?.status === 429 ? 'ขอรหัสถี่เกินไป รอสักครู่แล้วลองใหม่' : 'ส่งคำขอไม่สำเร็จ')
    } finally {
      setLoading(false)
    }
  }

  const reset = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (code.length !== 6) {
      setError('กรอกรหัส 6 หลักจากอีเมล')
      return
    }
    if (score < passwordChecks.length) {
      setError('รหัสผ่านใหม่ยังไม่ผ่านเงื่อนไขด้านล่าง')
      return
    }
    if (!matches) {
      setError('ยืนยันรหัสผ่านไม่ตรงกัน')
      return
    }
    setLoading(true)
    try {
      const res = await authApi.resetPassword(email.trim(), code, password)
      useAuthStore.getState().logout()
      toast.success(res.message, { duration: 6000 })
      navigate('/login', { replace: true })
    } catch (err: any) {
      const detail = err.response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'ตั้งรหัสผ่านใหม่ไม่สำเร็จ')
      setInvalid(true)
      setTimeout(() => setInvalid(false), 400)
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthShell>
      <div className="flex justify-center">
        <div className="w-full max-w-[440px]">
          <div className="dash-card border-[var(--bg-border)] bg-[var(--bg-surface)] p-5 shadow-xl sm:p-7">
            <div className="mb-6 flex items-start justify-between gap-4">
              <div>
                <h1 className="m-0 text-[20px] font-bold tracking-tight text-[var(--text-primary)]">
                  {step === 'email' ? 'ลืมรหัสผ่าน' : 'ตั้งรหัสผ่านใหม่'}
                </h1>
                <p className="mt-1.5 mb-0 text-[12.5px] leading-5 text-[var(--text-muted)]">
                  {step === 'email' ? (
                    'กรอกอีเมลของบัญชี เราจะส่งรหัส 6 หลักไปให้'
                  ) : (
                    <>
                      กรอกรหัสที่ส่งไปที่{' '}
                      <span className="font-mono font-semibold text-[var(--text-primary)] break-all">{email}</span>
                    </>
                  )}
                </p>
              </div>
              <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 p-2 text-orange-600 dark:text-orange-400">
                <KeyRound size={18} />
              </div>
            </div>

            {step === 'email' ? (
              <form onSubmit={requestCode} className="space-y-4 text-[13px]">
                <div>
                  <label htmlFor="forgot-email" className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                    Email
                  </label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                    <input
                      id="forgot-email"
                      type="email"
                      required
                      autoComplete="username"
                      placeholder="operator@example.com"
                      className="w-full dash-input pl-9 pr-3 py-2 text-[13px]"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </div>
                </div>
                <Button type="submit" variant="brand" className="w-full py-2.5" disabled={loading} isLoading={loading}>
                  <span>ส่งรหัส</span>
                  <ArrowRight size={14} />
                </Button>
              </form>
            ) : (
              <form onSubmit={reset} className="space-y-4 text-[13px]">
                <div>
                  <OtpInput value={code} onChange={setCode} disabled={loading} invalid={invalid} autoFocus />
                  <div className="mt-2.5 flex items-center justify-between text-[12px]">
                    <span className="text-[var(--text-muted)]">รหัสใช้ได้ 10 นาที</span>
                    <button
                      type="button"
                      disabled={wait > 0 || loading}
                      onClick={() => requestCode()}
                      className="inline-flex items-center gap-1.5 font-semibold text-orange-600 dark:text-orange-500 disabled:text-[var(--text-muted)] disabled:cursor-not-allowed hover:underline underline-offset-4 cursor-pointer"
                    >
                      <RotateCw size={12} />
                      {wait > 0 ? `ส่งใหม่ได้ใน ${formatCountdown(wait)}` : 'ส่งรหัสใหม่'}
                    </button>
                  </div>
                </div>

                <div>
                  <label htmlFor="reset-password" className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                    รหัสผ่านใหม่
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={15} />
                    <input
                      id="reset-password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete="new-password"
                      className="w-full dash-input pl-9 pr-10 py-2 text-[13px]"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      className="absolute right-0.5 top-1/2 -translate-y-1/2 w-9 h-9 flex items-center justify-center rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
                    >
                      {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                  <ul className="mt-2 mb-0 p-0 list-none grid grid-cols-2 gap-x-3 gap-y-1 text-[11px]">
                    {passwordChecks.map((c) => {
                      const ok = c.test(password)
                      return (
                        <li key={c.label} className={`flex items-center gap-1.5 ${ok ? 'text-emerald-500' : 'text-[var(--text-muted)]'}`}>
                          <Check size={11} className={ok ? '' : 'opacity-30'} /> {c.label}
                        </li>
                      )
                    })}
                  </ul>
                </div>

                <div>
                  <label htmlFor="reset-confirm" className="block text-[11.5px] font-semibold text-[var(--text-secondary)] mb-1.5">
                    ยืนยันรหัสผ่านใหม่
                  </label>
                  <input
                    id="reset-confirm"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    className="w-full dash-input px-3 py-2 text-[13px]"
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                  />
                </div>

                <div className="flex items-start gap-2 rounded-lg border border-sky-500/25 bg-sky-500/5 p-2.5 text-[11.5px] leading-5 text-[var(--text-secondary)]">
                  <MonitorSmartphone size={14} className="text-sky-500 shrink-0 mt-0.5" />
                  <span>ตั้งรหัสผ่านใหม่แล้ว ทุกอุปกรณ์ที่เข้าระบบอยู่จะถูกออกจากระบบ รวมถึงเครื่องนี้</span>
                </div>

                <p className="m-0 min-h-[18px] text-[12px] text-red-500" role="alert">
                  {error}
                </p>
                <Button type="submit" variant="brand" className="w-full py-2.5" disabled={loading} isLoading={loading}>
                  ตั้งรหัสผ่านใหม่
                </Button>
                <button
                  type="button"
                  onClick={() => {
                    setStep('email')
                    setCode('')
                    setError('')
                  }}
                  className="w-full text-center text-[12px] text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
                >
                  ใช้อีเมลอื่น
                </button>
              </form>
            )}

            <div className="my-5 h-px bg-[var(--bg-border)]" />
            <Link
              to="/login"
              className="flex items-center justify-center gap-1.5 text-[12px] text-[var(--text-muted)] hover:text-[var(--text-primary)] underline-offset-4 hover:underline"
            >
              <ArrowLeft size={12} /> กลับไปหน้าเข้าสู่ระบบ
            </Link>
          </div>
        </div>
      </div>
    </AuthShell>
  )
}

export default ForgotPassword
