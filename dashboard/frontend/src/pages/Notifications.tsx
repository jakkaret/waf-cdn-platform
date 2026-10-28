import React from 'react'
import { Link } from 'react-router-dom'
import { TopBar } from '../components/layout/TopBar'
import { TelegramConnection } from '../components/alerts/TelegramConnection'
import { NotificationSettings } from '../components/alerts/NotificationSettings'
import { useT } from '../i18n'

// Where notifications are delivered and which ones each site sends. The
// alerts themselves are read in the Alert center (/alerts).
export const Notifications: React.FC = () => {
  const { t } = useT()
  return (
  <div className="animate-fade-in pb-12 space-y-4">
    <TopBar
      title={t('Notifications', 'ช่องทางแจ้งเตือน')}
      subtitle={t(
        'Choose where alerts are delivered and which events of each site you want to hear about.',
        'เลือกช่องทางรับการแจ้งเตือน และเหตุการณ์ของแต่ละเว็บที่ต้องการรับ',
      )}
    />
    <TelegramConnection />
    <NotificationSettings />
    <p className="m-0 text-[12.5px] text-[var(--text-muted)]">
      {t('Telegram is the only delivery channel today. Every alert is also listed in', 'ตอนนี้ส่งได้ทาง Telegram เท่านั้น การแจ้งเตือนทั้งหมดยังดูได้ที่')}{' '}
      <Link to="/alerts" className="text-[var(--accent)] hover:underline">{t('Alerts', 'การแจ้งเตือนภัย')}</Link>.
    </p>
  </div>
  )
}

export default Notifications
