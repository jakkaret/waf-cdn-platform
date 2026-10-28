import React from 'react'
import { Link } from 'react-router-dom'
import { Lock } from 'lucide-react'
import { useAuthStore } from '../store/authStore'
import { isOperator } from '../lib/permissions'
import { useT } from '../i18n'

// A platform-wide page that only the operator may open. A regular user who
// lands on it (an old bookmark) is pointed at the origin tab that holds the
// same setting for their own sites. The backend guards the data either way;
// this only keeps the page from rendering controls that would all fail.
// Thai names of the origin tabs App.tsx passes in.
const ORIGIN_TAB_TH: Record<string, string> = { 'IP Access': 'การเข้าถึงตาม IP', 'Rate Limits': 'Rate limit' }

export const OperatorOnly: React.FC<{ originTab?: string; children: React.ReactNode }> = ({ originTab, children }) => {
  const user = useAuthStore((s) => s.user)
  const { t } = useT()
  if (isOperator(user)) return <>{children}</>
  const tabName = originTab ? t(originTab, ORIGIN_TAB_TH[originTab] ?? originTab) : ''
  return (
    <div className="dash-card p-5 mt-3.5 max-w-xl text-[13px] text-[var(--text-secondary)] space-y-2">
      <p className="m-0 flex items-center gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
        <Lock size={15} aria-hidden="true" />
        {t('This page is for the platform operator', 'หน้านี้สำหรับผู้ดูแลแพลตฟอร์ม')}
      </p>
      {originTab ? (
        <p className="m-0">
          {t('Your sites have their own: open an origin in', 'เว็บของคุณมีการตั้งค่าของตัวเอง: เปิด origin ใน')}{' '}
          <Link to="/origins" className="text-[var(--accent)] hover:underline">Origins</Link>{' '}
          {t('and use its', 'แล้วใช้แท็บ')} <strong>{tabName}</strong>
          {t(' tab.', '')}
        </p>
      ) : (
        <p className="m-0">
          {t('Everything for your own sites is in', 'ทุกอย่างของเว็บคุณอยู่ใน')}{' '}
          <Link to="/origins" className="text-[var(--accent)] hover:underline">Origins</Link>.
        </p>
      )}
    </div>
  )
}
