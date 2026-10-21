import React, { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import { Check, Lock, MailCheck, RotateCw, ShieldAlert, ShieldCheck } from 'lucide-react'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import { AuthShell } from '../components/auth/AuthShell'
import { OtpInput } from '../components/auth/OtpInput'
import { Button } from '../components/ui/Button'
import {
  GATE_COPY,
  LOCKED_UNTIL_VERIFIED,
  OPEN_BEFORE_VERIFIED,
  WHY_VERIFY,
  formatCountdown,
  isGateAction,
} from '../lib/emailGate'

// Confirm the 6-digit code mailed after sign-up (api/auth.py /verify-email).
// Reached right after Register, from the AppLayout banner, or from the
// locked-feature dialog (?action= says which feature, ?next= where to go back).

const safeNext = (value: string | null) => (value && value.startsWith('/') && !value.startsWith('//') ? value : '/')

export const VerifyEmail: React.FC = () => {
  const [params] = useSearchParams()
  const action = isGateAction(params.get('action')) ? (params.get('action') as keyof typeof GATE_COPY) : null
  const next = safeNext(params.get('next'))
  const navigate = useNavigate()
  const { user, updateUser } = useAuthStore()
  const [code, setCode] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [invalid, setInvalid] = useState(false)
  const [error, setError] = useState('')
  const [wait, setWait] = useState(0)
  const [sending, setSending] = useState(false)
  const requested = useRef(false)

  // Count the resend cooldown down once a second.
  useEffect(() => {
    if (wait <= 0) return
    const t = setTimeout(() => setWait((w) => w - 1), 1000)
    return () => clearTimeout(t)
  }, [wait])

  const send = async (initial: boolean) => {
    setSending(true)
    try {
      const res = await authApi.sendVerifyCode()
      if (res.verified) {
        navigate(next, { replace: true })
        return
      }
      setWait(res.retry_after ?? 60)
      if (!initial && res.sent) toast.success('ส่งรหัสใหม่แล้ว')
    } catch (err: any) {
      const status = err.response?.status
      if (status === 429) setWait(60)
      else toast.error('ส่งรหัสไม่สำเร็จ ลองใหม่อีกครั้ง')
    } finally {
      setSending(false)
    }
  }

  // Sign-up already mailed a code; this asks for one only when none is live
  // (the backend answers "wait N seconds" instead of sending twice).
  useEffect(() => {
    if (requested.current) return
    requested.current = true
    if (user?.email_verified) navigate(next, { replace: true })
    else send(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const submit = async (value: string) => {
    if (value.length !== 6 || submitting) return
    setSubmitting(true)
    setError('')
    try {
      const res = await authApi.confirmVerifyCode(value)
      updateUser(res.user)
      toast.success('ยืนยันอีเมลแล้ว ใช้งานได้ครบทุกส่วน')
      navigate(next, { replace: true })
    } catch (err: any) {
      const detail = err.response?.data?.detail
      setError(typeof detail === 'string' ? detail : 'รหัสไม่ถูกต้อง')
      setInvalid(true)
      setTimeout(() => setInvalid(false), 400)
      setCode('')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <AuthShell>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-12 items-start">
        <section className="lg:col-span-6 flex justify-center lg:justify-start">
          <div className="w-full max-w-[440px]">
            <div className="dash-card border-[var(--bg-border)] bg-[var(--bg-surface)] p-5 shadow-xl sm:p-7">
              <div className="mb-6 flex items-start justify-between gap-4">
                <div>
                  <h1 className="m-0 text-[20px] font-bold tracking-tight text-[var(--text-primary)]">ยืนยันอีเมลของคุณ</h1>
                  <p className="mt-1.5 mb-0 text-[12.5px] leading-5 text-[var(--text-muted)]">
                    กรอกรหัส 6 หลักที่ส่งไปที่
                    <br />
                    <span className="font-mono font-semibold text-[var(--text-primary)] break-all">{user?.email}</span>
                  </p>
                </div>
                <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 p-2 text-orange-600 dark:text-orange-400">
                  <MailCheck size={18} />
                </div>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  submit(code)
                }}
              >
                <OtpInput value={code} onChange={setCode} onComplete={submit} disabled={submitting} invalid={invalid} autoFocus />
                <p className="mt-3 mb-0 min-h-[18px] text-center text-[12px] text-red-500" role="alert">
                  {error}
                </p>
                <Button
                  type="submit"
                  variant="brand"
                  className="w-full py-2.5 mt-2"
                  disabled={code.length !== 6 || submitting}
                  isLoading={submitting}
                >
                  {submitting ? 'กำลังตรวจรหัส...' : 'ยืนยันอีเมล'}
                </Button>
              </form>

              <div className="mt-4 flex items-center justify-between gap-3 text-[12px]">
                <span className="text-[var(--text-muted)]">รหัสใช้ได้ 10 นาที · ใช้ได้ครั้งเดียว</span>
                <button
                  type="button"
                  disabled={wait > 0 || sending}
                  onClick={() => send(false)}
                  className="inline-flex items-center gap-1.5 font-semibold text-orange-600 dark:text-orange-500 disabled:text-[var(--text-muted)] disabled:cursor-not-allowed hover:underline underline-offset-4 cursor-pointer"
                >
                  <RotateCw size={12} className={sending ? 'animate-spin' : ''} />
                  {wait > 0 ? `ส่งใหม่ได้ใน ${formatCountdown(wait)}` : 'ส่งรหัสใหม่'}
                </button>
              </div>
              <p className="mt-2 mb-0 text-[11.5px] text-[var(--text-muted)]">ไม่เห็นอีเมล? ดูในโฟลเดอร์ Junk/Spam หรือ Promotions</p>

              <div className="my-5 h-px bg-[var(--bg-border)]" />
              <button
                type="button"
                onClick={() => navigate(next === '/verify-email' ? '/' : next)}
                className="w-full text-center text-[12px] text-[var(--text-muted)] hover:text-[var(--text-primary)] underline-offset-4 hover:underline cursor-pointer"
              >
                ไว้ทีหลัง (บางส่วนจะยังใช้ไม่ได้)
              </button>
            </div>
          </div>
        </section>

        <aside className="lg:col-span-6 space-y-4">
          {action && (
            <div className="dash-card p-5 border-amber-500/30">
              <h2 className="m-0 mb-2 flex items-center gap-2 text-[13.5px] font-bold text-amber-600 dark:text-amber-400">
                <ShieldAlert size={15} /> {GATE_COPY[action].title}
              </h2>
              <ul className="m-0 pl-4 space-y-1.5 text-[12.5px] leading-5 text-[var(--text-secondary)]">
                {GATE_COPY[action].impacts.map((t) => (
                  <li key={t}>{t}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="dash-card p-5">
            <h2 className="m-0 mb-3 flex items-center gap-2 text-[13.5px] font-bold text-[var(--text-primary)]">
              <ShieldCheck size={15} className="text-orange-500" /> ทำไมต้องยืนยันอีเมล
            </h2>
            <ul className="m-0 pl-4 space-y-1.5 text-[12.5px] leading-5 text-[var(--text-secondary)]">
              {WHY_VERIFY.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </div>
          <div className="dash-card p-5 grid grid-cols-1 sm:grid-cols-2 gap-5">
            <div>
              <p className="m-0 mb-2 text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)]">ใช้ได้หลังยืนยัน</p>
              <ul className="m-0 p-0 list-none space-y-1.5 text-[12.5px]">
                {LOCKED_UNTIL_VERIFIED.map((t) => (
                  <li key={t} className="flex items-center gap-2 text-[var(--text-secondary)]">
                    <Lock size={12} className="text-amber-500 shrink-0" /> {t}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="m-0 mb-2 text-[11px] font-mono uppercase tracking-wider text-[var(--text-muted)]">ใช้ได้เลยตอนนี้</p>
              <ul className="m-0 p-0 list-none space-y-1.5 text-[12.5px]">
                {OPEN_BEFORE_VERIFIED.map((t) => (
                  <li key={t} className="flex items-center gap-2 text-[var(--text-secondary)]">
                    <Check size={12} className="text-emerald-500 shrink-0" /> {t}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </aside>
      </div>
    </AuthShell>
  )
}

export default VerifyEmail
