import React from 'react'
import { Link } from 'react-router-dom'
import { LanguageToggle } from '../components/ui/LanguageToggle'
import { useT } from '../i18n'

// F-029: rendered for any URL no route matches (previously a blank screen).
export const NotFound: React.FC = () => {
  const { t } = useT()
  return (
    <div className="relative min-h-screen flex items-center justify-center bg-[var(--bg-primary)] text-[var(--text-primary)] p-6">
      <div className="absolute top-4 right-4">
        <LanguageToggle />
      </div>
      <div className="text-center space-y-3">
        <div className="font-mono text-[42px] font-bold text-orange-500">404</div>
        <p className="text-[14px] m-0">{t('Page not found', 'ไม่พบหน้าที่คุณต้องการ')}</p>
        <Link to="/" className="inline-block mt-2 text-[13px] font-mono text-orange-500 hover:underline">
          ← {t('Back to the dashboard', 'กลับหน้าแดชบอร์ด')}
        </Link>
      </div>
    </div>
  )
}

export default NotFound
