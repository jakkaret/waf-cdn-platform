import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api/axios'
import { useAuthStore } from '../store/authStore'
import { LanguageToggle } from '../components/ui/LanguageToggle'
import { tr, useT } from '../i18n'

// Landing page of an origin-sharing invitation (N9/H64). Access goes to the
// signed-in account that opens the emailed link.
const AcceptInvite: React.FC = () => {
  const { isAuthenticated, sessionChecked } = useAuthStore()
  const navigate = useNavigate()
  const { t } = useT()
  const token = new URLSearchParams(window.location.search).get('token') || ''
  const [state, setState] = useState<'idle' | 'working' | 'done' | 'error'>('idle')
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!token || !isAuthenticated || state !== 'idle') return
    setState('working')
    api
      .post<{ origin_id: string; role: string }>('/invites/accept', { token })
      .then((res) => {
        setState('done')
        setMessage(tr(`You now have ${res.data.role} access.`, `ตอนนี้คุณมีสิทธิ์ ${res.data.role} แล้ว`))
        setTimeout(() => navigate(`/origins/${res.data.origin_id}`), 1200)
      })
      .catch((e) => {
        setState('error')
        setMessage(e.response?.data?.detail || tr('This invitation could not be accepted.', 'รับคำเชิญนี้ไม่ได้'))
      })
  }, [token, isAuthenticated, state, navigate])

  let body: React.ReactNode
  if (!token) body = <p>{t('This link has no invitation code.', 'ลิงก์นี้ไม่มีรหัสคำเชิญ')}</p>
  else if (!isAuthenticated && !sessionChecked) body = <p>{t('Checking your session...', 'กำลังตรวจสอบการเข้าสู่ระบบ...')}</p>
  else if (!isAuthenticated)
    body = (
      <p>
        {t('Sign in first, then open the invitation link again.', 'ลงชื่อเข้าใช้ก่อน แล้วเปิดลิงก์คำเชิญอีกครั้ง')}{' '}
        <Link to="/login" className="underline">{t('Sign in', 'ลงชื่อเข้าใช้')}</Link>
      </p>
    )
  else body = <p>{state === 'working' ? t('Accepting the invitation...', 'กำลังรับคำเชิญ...') : message}</p>

  return (
    <div className="relative min-h-screen flex items-center justify-center p-6">
      <div className="absolute top-4 right-4">
        <LanguageToggle />
      </div>
      <div className="max-w-md w-full rounded-xl border p-6 space-y-3">
        <h1 className="text-lg font-semibold">{t('Origin invitation', 'คำเชิญเข้าร่วม origin')}</h1>
        {body}
      </div>
    </div>
  )
}

export default AcceptInvite
