import React from 'react'
import { useT } from '../../i18n'

// A 24-hour "HH:MM" picker. The native time input follows the browser's
// language (12-hour with AM/PM on an English browser), which clashes with
// the Thai "น." times shown everywhere else in the report.

interface Props {
  id: string
  value: string
  onChange: (value: string) => void
  disabled?: boolean
  label: string
}

const HOURS = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'))
const STEP_MINUTES = Array.from({ length: 12 }, (_, i) => String(i * 5).padStart(2, '0'))

export const TimeSelect: React.FC<Props> = ({ id, value, onChange, disabled, label }) => {
  const { t, lang } = useT()
  const [h = '00', m = '00'] = (value || '00:00').split(':')
  // Keep an exact minute (e.g. "now" = 14:07) selectable alongside the 5-minute steps.
  const minutes = STEP_MINUTES.includes(m) ? STEP_MINUTES : [...STEP_MINUTES, m].sort()
  const cls =
    'dash-input h-9 !py-0 pl-2.5 pr-7 w-[72px] text-[14px] leading-none tabular-nums cursor-pointer disabled:cursor-not-allowed disabled:opacity-60'
  return (
    <div className="flex items-center gap-1.5" role="group" aria-label={label}>
      <select id={`${id}-h`} aria-label={`${label} ${t('hour', 'ชั่วโมง')}`} value={h} disabled={disabled} onChange={(e) => onChange(`${e.target.value}:${m}`)} className={cls}>
        {HOURS.map((x) => (
          <option key={x} value={x}>{x}</option>
        ))}
      </select>
      <span className="text-[var(--text-muted)]">:</span>
      <select id={`${id}-m`} aria-label={`${label} ${t('minute', 'นาที')}`} value={m} disabled={disabled} onChange={(e) => onChange(`${h}:${e.target.value}`)} className={cls}>
        {minutes.map((x) => (
          <option key={x} value={x}>{x}</option>
        ))}
      </select>
      {lang === 'th' && <span className="text-[13px] text-[var(--text-muted)]">น.</span>}
    </div>
  )
}

export default TimeSelect
