import React from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { MailCheck, ShieldAlert, ArrowRight } from 'lucide-react'
import { Modal } from '../ui/Modal'
import { Button } from '../ui/Button'
import { useAuthStore } from '../../store/authStore'
import { GATE_COPY, GateAction, WHY_VERIFY, useEmailGateStore } from '../../lib/emailGate'

// What an unverified account sees when it reaches a locked feature: the
// dialog (opened by a guarded button or by the axios interceptor on a 403
// email_unverified), the inline notice on pages that are all about a locked
// feature, and the banner in AppLayout.

export const isUnverified = (user: { email_verified?: boolean } | null | undefined) =>
  !!user && user.email_verified === false

const verifyHref = (action: GateAction | null, next: string) =>
  `/verify-email?${new URLSearchParams({ ...(action ? { action } : {}), next }).toString()}`

const ImpactList: React.FC<{ action: GateAction | null }> = ({ action }) => (
  <div className="space-y-3 text-[12.5px]">
    {action && (
      <div className="rounded-lg border border-amber-500/30 bg-[var(--warning-subtle)] p-3">
        <p className="m-0 mb-1.5 flex items-center gap-1.5 font-semibold text-amber-600 dark:text-amber-400">
          <ShieldAlert size={14} /> ส่วนนี้กระทบอะไรบ้าง
        </p>
        <ul className="m-0 pl-4 space-y-1 text-[var(--text-secondary)] leading-5">
          {GATE_COPY[action].impacts.map((t) => (
            <li key={t}>{t}</li>
          ))}
        </ul>
      </div>
    )}
    <div>
      <p className="m-0 mb-1.5 font-semibold text-[var(--text-primary)]">ทำไมต้องยืนยันอีเมล</p>
      <ul className="m-0 pl-4 space-y-1 text-[var(--text-secondary)] leading-5">
        {WHY_VERIFY.map((t) => (
          <li key={t}>{t}</li>
        ))}
      </ul>
    </div>
  </div>
)

export const EmailVerifyModal: React.FC = () => {
  const { open, action, close } = useEmailGateStore()
  const user = useAuthStore((s) => s.user)
  const navigate = useNavigate()
  const location = useLocation()
  const title = action ? GATE_COPY[action].title : 'ยืนยันอีเมลก่อนใช้งานส่วนนี้'

  return (
    <Modal open={open} onClose={close} title={title} description={user?.email ? `รหัส 6 หลักจะส่งไปที่ ${user.email}` : undefined}>
      <ImpactList action={action} />
      <div className="mt-5 flex flex-col-reverse sm:flex-row sm:justify-end gap-2">
        <Button variant="ghost" onClick={close}>
          ไว้ทีหลัง
        </Button>
        <Button
          variant="brand"
          icon={<MailCheck size={14} />}
          onClick={() => {
            close()
            navigate(verifyHref(action, location.pathname + location.search))
          }}
        >
          ยืนยันอีเมลตอนนี้
        </Button>
      </div>
    </Modal>
  )
}

// Inline card for a page whose whole purpose is locked (e.g. Get Started).
export const EmailVerifyNotice: React.FC<{ action: GateAction }> = ({ action }) => {
  const navigate = useNavigate()
  const location = useLocation()
  return (
    <div className="dash-card p-5 sm:p-6 border-amber-500/30">
      <div className="flex items-start gap-3">
        <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 p-2 text-orange-600 dark:text-orange-400 shrink-0">
          <MailCheck size={18} />
        </div>
        <div className="min-w-0 flex-1">
          <h3 className="m-0 text-[15px] font-bold text-[var(--text-primary)]">{GATE_COPY[action].title}</h3>
          <p className="mt-1 mb-4 text-[12.5px] text-[var(--text-muted)]">ใช้เวลาไม่ถึงนาที: กรอกรหัส 6 หลักที่ส่งไปที่อีเมลของคุณ</p>
          <ImpactList action={action} />
          <Button
            className="mt-5"
            variant="brand"
            onClick={() => navigate(verifyHref(action, location.pathname + location.search))}
          >
            <span>ยืนยันอีเมล</span>
            <ArrowRight size={14} />
          </Button>
        </div>
      </div>
    </div>
  )
}

// Wrap a click on a locked feature: opens the dialog instead for an
// unverified account. The backend refuses either way.
export function useVerifiedGuard() {
  const user = useAuthStore((s) => s.user)
  const show = useEmailGateStore((s) => s.show)
  return (action: GateAction, run: () => void) => {
    if (isUnverified(user)) show(action)
    else run()
  }
}
