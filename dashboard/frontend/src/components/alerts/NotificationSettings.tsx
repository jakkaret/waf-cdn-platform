import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown } from 'lucide-react'
import toast from 'react-hot-toast'
import { alertsApi } from '../../api/alerts'
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
    className={`relative w-9 h-5 rounded-full shrink-0 transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 ${on ? 'bg-orange-500' : 'bg-[var(--bg-border)]'}`}
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
      toast.success('บันทึกการแจ้งเตือนแล้ว')
    },
    onError: () => toast.error('บันทึกไม่สำเร็จ ลองใหม่อีกครั้ง'),
  })
  const level = useMutation({
    mutationFn: (s: Sensitivity) => alertsApi.setSensitivity(site.origin_id, s),
    onSuccess: (s) => {
      refresh()
      qc.invalidateQueries({ queryKey: ['alert-incidents'] })
      toast.success(`ตั้งความไวเป็น ${SENSITIVITY_LABEL[s]} แล้ว`)
    },
    onError: () => toast.error('เปลี่ยนความไวไม่สำเร็จ'),
  })

  return (
    <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] p-3.5 space-y-3 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[13px] font-semibold text-[var(--text-primary)] break-words">{site.label || 'เว็บไม่มีชื่อ'}</div>
          <div className="text-[11.5px] text-[var(--text-muted)]">คุณเป็น {ROLE_LABEL[site.role]}</div>
        </div>
        <div className="inline-flex rounded-md border border-[var(--bg-border)] overflow-hidden text-[12px]" role="radiogroup" aria-label="ความไวการแจ้งเตือนการโจมตี">
          {LEVELS.map((l) => (
            <button
              key={l}
              type="button"
              role="radio"
              aria-checked={site.sensitivity === l}
              disabled={!site.can_set_sensitivity || level.isPending}
              title={site.can_set_sensitivity ? undefined : 'Owner หรือ Editor เป็นคนตั้งความไวของเว็บนี้'}
              onClick={() => site.sensitivity !== l && level.mutate(l)}
              className={`px-3 py-1 cursor-pointer disabled:cursor-not-allowed ${site.sensitivity === l ? 'bg-orange-500 text-white font-semibold' : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]'}`}
            >
              {SENSITIVITY_LABEL[l]}
            </button>
          ))}
        </div>
      </div>
      <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
        ความไว “{SENSITIVITY_LABEL[site.sensitivity]}”: {sensitivityHint(site.sensitivity, levels)}
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
  const [open, setOpen] = useState(false)
  const { data } = useQuery({ queryKey: ['notification-prefs'], queryFn: alertsApi.getPreferences })
  const sites = data?.sites ?? []

  return (
    <div className="dash-card overflow-hidden mt-3.5">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="w-full flex items-center justify-between gap-2 px-4 py-3 text-left cursor-pointer hover:bg-[var(--bg-hover)]"
      >
        <div className="min-w-0">
          <h3 className="m-0 text-[13.5px] font-bold text-[var(--text-primary)]">ตั้งค่าการแจ้งเตือน</h3>
          <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
            เลือกว่าจะรับเรื่องไหนของแต่ละเว็บทาง Telegram{sites.length ? ` · ${sites.length} เว็บ` : ''}
          </p>
        </div>
        <ChevronDown size={15} className={`shrink-0 text-[var(--text-muted)] transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3">
          {data && !data.telegram_connected && (
            <p className="m-0 text-[12px] text-amber-600 dark:text-amber-400">ยังไม่ได้เชื่อม Telegram ตั้งค่าไว้ก่อนได้ จะเริ่มส่งเมื่อเชื่อมแล้ว</p>
          )}
          {sites.length === 0 ? (
            <p className="m-0 text-[12.5px] text-[var(--text-muted)]">ยังไม่มีเว็บในบัญชีนี้</p>
          ) : (
            <div className="grid gap-3 md:grid-cols-2">
              {sites.map((s) => (
                <SiteCard key={s.origin_id} site={s} levels={data!.levels} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default NotificationSettings
