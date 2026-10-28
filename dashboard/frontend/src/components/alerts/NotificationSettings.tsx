import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Send } from 'lucide-react'
import toast from 'react-hot-toast'
import { alertsApi } from '../../api/alerts'
import { Button } from '../ui/Button'
import {
  NotificationPrefs, PrefKind, ROLE_LABEL, SENSITIVITY_LABEL, Sensitivity, SitePrefs, sensitivityHint, visibleKinds,
} from '../../lib/notificationPrefs'

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
  const refresh = () => qc.invalidateQueries({ queryKey: ['notification-prefs'] })
  const prefs = useMutation({
    mutationFn: (changes: Partial<Record<PrefKind, boolean>>) => alertsApi.setPreferences(site.origin_id, changes),
    onSuccess: () => {
      refresh()
      toast.success('Notification settings saved')
    },
    onError: () => toast.error('Could not save. Try again.'),
  })
  const level = useMutation({
    mutationFn: (s: Sensitivity) => alertsApi.setSensitivity(site.origin_id, s),
    onSuccess: (s) => {
      refresh()
      qc.invalidateQueries({ queryKey: ['alert-incidents'] })
      toast.success(`Sensitivity set to ${SENSITIVITY_LABEL[s]}`)
    },
    onError: () => toast.error('Could not change the sensitivity'),
  })

  return (
    <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] p-3.5 space-y-3 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-[var(--text-primary)] break-words">{site.label || 'Unnamed site'}</div>
          <div className="text-[11.5px] text-[var(--text-muted)]">You are {ROLE_LABEL[site.role]}</div>
        </div>
        <div className="inline-flex rounded-md border border-[var(--bg-border)] overflow-hidden text-[12px]" role="radiogroup" aria-label="Attack alert sensitivity">
          {LEVELS.map((l) => (
            <button
              key={l}
              type="button"
              role="radio"
              aria-checked={site.sensitivity === l}
              disabled={!site.can_set_sensitivity || level.isPending}
              title={site.can_set_sensitivity ? undefined : "The site's Owner or Editor sets its sensitivity"}
              onClick={() => site.sensitivity !== l && level.mutate(l)}
              className={`px-3 py-1 cursor-pointer disabled:cursor-not-allowed ${site.sensitivity === l ? 'bg-orange-600 text-white font-semibold' : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]'}`}
            >
              {SENSITIVITY_LABEL[l]}
            </button>
          ))}
        </div>
      </div>
      <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
        {SENSITIVITY_LABEL[site.sensitivity]} sensitivity: {sensitivityHint(site.sensitivity, levels)}
      </p>
      <ul className="m-0 p-0 list-none space-y-2">
        {visibleKinds(site).map(({ kind, label }) => (
          <li key={kind} className="flex items-center justify-between gap-3 text-[12.5px] text-[var(--text-primary)]">
            <span className="min-w-0">{label}</span>
            <Switch
              on={site.prefs[kind]}
              label={label}
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
  const test = useMutation({
    mutationFn: alertsApi.sendTest,
    onSuccess: () => toast.success('Test message sent. Check Telegram.'),
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Could not send the test message. Try again.'),
  })

  return (
    <section className="dash-card overflow-hidden" aria-labelledby="notif-sites-heading">
      <div className="px-4 py-3 border-b border-[var(--bg-border-subtle)]">
        <h2 id="notif-sites-heading" className="m-0 text-[14px] font-semibold text-[var(--text-primary)]">What each site sends you</h2>
        <p className="m-0 text-[12px] text-[var(--text-muted)]">
          Pick which events of each site reach your Telegram.
        </p>
      </div>
      <div className="p-4 space-y-3">
        {isLoading && <p className="m-0 text-[12.5px] text-[var(--text-muted)]">Loading your sites…</p>}
        {isError && <p className="m-0 text-[12.5px] text-red-600 dark:text-red-400">Could not load notification settings. Reload the page to try again.</p>}
        {data && !data.telegram_connected && (
          <p className="m-0 text-[12px] text-amber-700 dark:text-amber-400">
            Telegram is not connected. You can set these now; messages start once you connect.
          </p>
        )}
        {data?.telegram_connected && (
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] px-3.5 py-2.5">
            <p className="m-0 min-w-0 text-[12px] text-[var(--text-muted)]">
              Send a test message to your Telegram only, listing what you currently receive.
            </p>
            <Button variant="secondary" size="sm" icon={<Send size={13} />} isLoading={test.isPending} onClick={() => test.mutate()}>
              Send test message
            </Button>
          </div>
        )}
        {data && sites.length === 0 ? (
          <p className="m-0 text-[12.5px] text-[var(--text-muted)]">This account has no sites yet. Add an origin to choose its notifications.</p>
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
