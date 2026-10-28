import React from 'react'
import { Link } from 'react-router-dom'
import { TopBar } from '../components/layout/TopBar'
import { TelegramConnection } from '../components/alerts/TelegramConnection'
import { NotificationSettings } from '../components/alerts/NotificationSettings'

// Where notifications are delivered and which ones each site sends. The
// alerts themselves are read in the Alert center (/alerts).
export const Notifications: React.FC = () => (
  <div className="animate-fade-in pb-12 space-y-4">
    <TopBar
      title="Notifications"
      subtitle="Choose where alerts are delivered and which events of each site you want to hear about."
    />
    <TelegramConnection />
    <NotificationSettings />
    <p className="m-0 text-[12.5px] text-[var(--text-muted)]">
      Telegram is the only delivery channel today. Every alert is also listed in{' '}
      <Link to="/alerts" className="text-[var(--accent)] hover:underline">Alerts</Link>.
    </p>
  </div>
)

export default Notifications
