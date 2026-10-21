import React from 'react'
import { useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import { Info, Globe } from 'lucide-react'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { ConnectSiteFlow } from '../components/ConnectSiteFlow'
import { EmailVerifyNotice, isUnverified } from '../components/auth/EmailVerifyGate'
import { useAuthStore } from '../store/authStore'

// The wizard used to be four steps (origin → domain → verify → agent) with
// its own copy of the domain logic, and it resumed from an account-wide
// status, so a user who had finished one origin landed on "ตั้งค่าเสร็จแล้ว!"
// before adding the next. It is now the same ConnectSiteFlow as Origins →
// Add Origin; what remains to do is shown, and checked, on the origin's
// Domains tab.

export const Onboarding: React.FC = () => {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in pb-16">
      <TopBar
        title="Get Started"
        subtitle="เชื่อมเว็บของคุณเข้ากับ WAF จากชื่อโดเมน"
        badge={<Badge color="brand">Connect</Badge>}
      />

      {isUnverified(user) ? <EmailVerifyNotice action="create_origin" /> : <div className="dash-card p-5 sm:p-6 space-y-4">
        <h3 className="text-[14.5px] font-bold font-mono m-0 flex items-center gap-2">
          <Globe size={16} className="text-orange-500" />
          เว็บของคุณอยู่ที่โดเมนไหน
        </h3>
        <ConnectSiteFlow
          onDone={(originId) => {
            queryClient.invalidateQueries({ queryKey: ['origins'] })
            navigate(`/origins/${originId}?tab=domains`)
          }}
        />
      </div>}

      <div className="dash-card p-4 text-[11px] font-mono text-[var(--text-secondary)] leading-relaxed flex items-start gap-2">
        <Info size={13} className="text-sky-500 shrink-0 mt-0.5" />
        <p className="m-0">
          ระบบดู DNS ปัจจุบันของโดเมนและลองเชื่อมต่อเซิร์ฟเวอร์ให้ ถ้าเซิร์ฟเวอร์มี public IP จะต่อตรงได้เลยโดยไม่ต้องติดตั้งอะไร
          ถ้าอยู่หลัง NAT/firewall จะใช้ Agent แทน จากนั้นตั้ง DNS แค่ 1 record (CNAME) แล้วหน้าโดเมนจะตรวจ DNS, การเชื่อมต่อ และ HTTPS
          ให้อัตโนมัติ
        </p>
      </div>
    </div>
  )
}

export default Onboarding
