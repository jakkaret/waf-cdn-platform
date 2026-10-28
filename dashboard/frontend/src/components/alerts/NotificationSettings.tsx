import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Send } from 'lucide-react'
import toast from 'react-hot-toast'
import { alertsApi } from '../../api/alerts'
import { Button } from '../ui/Button'
import {
  NotificationPrefs, PrefKind, ROLE_LABEL, SENSITIVITY_LABEL, SENSITIVITY_LABEL_TH, Sensitivity, SitePrefs, sensitivityHint, visibleKinds,
} from '../../lib/notificationPrefs'
import { useT } from '../../i18n'

// Per site: which Telegram messages this person gets, and (owner/editor) how
// big an attack burst must be before it counts as an incident.

const LEVELS: Sensitivity[] = ['low', 'medium', 'high']

const Switch: React.FC<{ on: boolean; disabled?: boolean; label: string; onChange: (v: boolean) => void }> = ({ on, disabled, label, onChange }) => (
  <button
    type="button"
    role="switch"
    aria-checked={on}
    aria-label={label}
    disabled={disabled}
    onClick={() => onChange(!on)}
    className={`relative w-9 h-5 rounded-full shrink-0 transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${on ? 'bg-orange-500' : 'bg-[var(--bg-border)]'}`}
  >
    <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${on ? 'translate-x-4' : ''}`} />
  </button>
)

const SiteCard: React.FC<{ site: SitePrefs; levels: NotificationPrefs['levels'] }> = ({ site, levels }) => {
  const qc = useQueryClient()
  const { t, lang } = useT()
  const sensitivityName = (s: Sensitivity) => (lang === 'th' ? SENSITIVITY_LABEL_TH[s] : SENSITIVITY_LABEL[s])
  const refresh = () => qc.invalidateQueries({ queryKey: ['notification-prefs'] })
  const prefs = useMutation({
    mutationFn: (changes: Partial<Record<PrefKind, boolean>>) => alertsApi.setPreferences(site.origin_id, changes),
    onSuccess: () => {
      refresh()
      toast.success(t('Notification settings saved', 'บันทึกการตั้งค่าการแจ้งเตือนแล้ว'))
    },
    onError: () => toast.error(t('Could not save. Try again.', 'บันทึกไม่สำเร็จ ลองใหม่อีกครั้ง')),
  })
  const level = useMutation({
    mutationFn: (s: Sensitivity) => alertsApi.setSensitivity(site.origin_id, s),
    onSuccess: (s) => {
      refresh()
      qc.invalidateQueries({ queryKey: ['alert-incidents'] })
      toast.success(t(`Sensitivity set to ${SENSITIVITY_LABEL[s]}`, `ตั้งความไวเป็น${SENSITIVITY_LABEL_TH[s]}แล้ว`))
    },
    onError: () => toast.error(t('Could not change the sensitivity', 'เปลี่ยนความไวไม่สำเร็จ')),
  })

  return (
    <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] p-3.5 space-y-3 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-[var(--text-primary)] break-words">{site.label || t('Unnamed site', 'เว็บไม่มีชื่อ')}</div>
          <div className="text-[11.5px] text-[var(--text-muted)]">{t('You are', 'คุณเป็น')} {ROLE_LABEL[site.role]}</div>
        </div>
        <div className="inline-flex rounded-md border border-[var(--bg-border)] overflow-hidden text-[12px]" role="radiogroup" aria-label={t('Attack alert sensitivity', 'ความไวในการแจ้งเตือนการโจมตี')}>
          {LEVELS.map((l) => (
            <button
              key={l}
              type="button"
              role="radio"
              aria-checked={site.sensitivity === l}
              disabled={!site.can_set_sensitivity || level.isPending}
              title={site.can_set_sensitivity ? undefined : t("The site's Owner or Editor sets its sensitivity", 'Owner หรือ Editor ของเว็บเป็นผู้ตั้งความไว')}
              onClick={() => site.sensitivity !== l && level.mutate(l)}
              className={`px-3 py-1 cursor-pointer disabled:cursor-not-allowed ${site.sensitivity === l ? 'bg-orange-600 text-white font-semibold' : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]'}`}
            >
              {sensitivityName(l)}
            </button>
          ))}
        </div>
      </div>
      <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
        {t(`${SENSITIVITY_LABEL[site.sensitivity]} sensitivity:`, `ความไว${SENSITIVITY_LABEL_TH[site.sensitivity]}:`)}{' '}
        {sensitivityHint(site.sensitivity, levels, lang)}
      </p>
      <ul className="m-0 p-0 list-none space-y-2">
        {visibleKinds(site).map(({ kind, label, labelTh }) => (
          <li key={kind} className="flex items-center justify-between gap-3 text-[12.5px] text-[var(--text-primary)]">
            <span className="min-w-0">{t(label, labelTh)}</span>
            <Switch
              on={site.prefs[kind]}
              label={t(label, labelTh)}
              disabled={!site.changeable.includes(kind) || prefs.isPending}
              onChange={(v) => prefs.mutate({ [kind]: v })}
            />
          </li>
        ))}
      </ul>
    </div>
  )
}

export const NotificationSettings: React.FC = () => {
  const { data, isLoading, isError } = useQuery({ queryKey: ['notification-prefs'], queryFn: alertsApi.getPreferences })
  const sites = data?.sites ?? []
  const { t } = useT()
  const test = useMutation({
    mutationFn: alertsApi.sendTest,
    onSuccess: () => toast.success(t('Test message sent. Check Telegram.', 'ส่งข้อความทดสอบแล้ว ดูที่ Telegram')),
    onError: (err: any) => toast.error(err.response?.data?.detail || t('Could not send the test message. Try again.', 'ส่งข้อความทดสอบไม่สำเร็จ ลองใหม่อีกครั้ง')),
  })

  return (
    <section className="dash-card overflow-hidden" aria-labelledby="notif-sites-heading">
      <div className="px-4 py-3 border-b border-[var(--bg-border-subtle)]">
        <h2 id="notif-sites-heading" className="m-0 text-[14px] font-semibold text-[var(--text-primary)]">{t('What each site sends you', 'แต่ละเว็บส่งอะไรให้คุณบ้าง')}</h2>
        <p className="m-0 text-[12px] text-[var(--text-muted)]">
          {t('Pick which events of each site reach your Telegram.', 'เลือกเหตุการณ์ของแต่ละเว็บที่จะส่งไปยัง Telegram ของคุณ')}
        </p>
      </div>
      <div className="p-4 space-y-3">
        {isLoading && <p className="m-0 text-[12.5px] text-[var(--text-muted)]">{t('Loading your sites…', 'กำลังโหลดเว็บของคุณ…')}</p>}
        {isError && <p className="m-0 text-[12.5px] text-red-600 dark:text-red-400">{t('Could not load notification settings. Reload the page to try again.', 'โหลดการตั้งค่าการแจ้งเตือนไม่สำเร็จ รีโหลดหน้าเพื่อลองใหม่')}</p>}
        {data && !data.telegram_connected && (
          <p className="m-0 text-[12px] text-amber-700 dark:text-amber-400">
            {t('Telegram is not connected. You can set these now; messages start once you connect.', 'ยังไม่ได้เชื่อม Telegram ตั้งค่าไว้ก่อนได้ ข้อความจะเริ่มส่งเมื่อเชื่อมแล้ว')}
          </p>
        )}
        {data?.telegram_connected && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] px-3.5 py-2.5">
            <p className="m-0 min-w-0 text-[12px] text-[var(--text-muted)]">
              {t('Send a test message to your Telegram only, listing what you currently receive.', 'ส่งข้อความทดสอบไปที่ Telegram ของคุณคนเดียว พร้อมรายการที่คุณได้รับอยู่')}
            </p>
            <Button variant="secondary" size="sm" icon={<Send size={13} />} isLoading={test.isPending} onClick={() => test.mutate()}>
              {t('Send test message', 'ส่งข้อความทดสอบ')}
            </Button>
          </div>
        )}
        {data && sites.length === 0 ? (
          <p className="m-0 text-[12.5px] text-[var(--text-muted)]">{t('This account has no sites yet. Add an origin to choose its notifications.', 'บัญชีนี้ยังไม่มีเว็บ เพิ่ม origin ก่อนจึงจะเลือกการแจ้งเตือนได้')}</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-2">
            {sites.map((s) => (
              <SiteCard key={s.origin_id} site={s} levels={data!.levels} />
            ))}
          </div>
        )}
      </div>
    </section>
  )
}

export default NotificationSettings
