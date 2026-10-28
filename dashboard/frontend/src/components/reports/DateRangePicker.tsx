import React, { useEffect, useMemo, useRef, useState } from 'react'
import { CalendarDays, ChevronLeft, ChevronRight, X } from 'lucide-react'
import {
  type DateKey,
  RETENTION_DAYS,
  WEEKDAYS_EN,
  WEEKDAYS_TH,
  addMonths,
  dayLabelTh,
  daysInclusive,
  earliestDay,
  monthGrid,
  monthLabelTh,
  monthOf,
  pickDay,
} from '../../lib/reportRange'
import { useT } from '../../i18n'

// Pick a first and a last day the way hotel sites do: the field opens a
// two-month calendar, the first click sets the start, the second the end,
// and the calendar closes. Times are chosen afterwards, outside this picker.

interface Props {
  start: DateKey | null
  end: DateKey | null
  today: DateKey
  onChange: (start: DateKey | null, end: DateKey | null, done: boolean) => void
  disabled?: boolean
}

export const DateRangePicker: React.FC<Props> = ({ start, end, today, onChange, disabled }) => {
  const { t, lang } = useT()
  const [open, setOpen] = useState(false)
  const [hover, setHover] = useState<DateKey | null>(null)
  const [right, setRight] = useState<DateKey>(monthOf(end || today))
  const box = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const min = earliestDay(today)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false)
        trigger.current?.focus()
      }
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  const openPicker = () => {
    setRight(monthOf(end || start || today))
    setHover(null)
    setOpen(true)
  }

  // The day the range would end on if the pointer clicked now.
  const previewEnd = start && !end && hover && hover >= start ? hover : end
  const count = start ? daysInclusive(start, previewEnd || start) : null

  const months = useMemo(() => [addMonths(right, -1), right], [right])
  const canPrev = addMonths(right, -1) > monthOf(min)
  const canNext = right < monthOf(today)

  const click = (day: DateKey) => {
    const next = pickDay({ start, end }, day)
    onChange(next.start, next.end, next.done)
    if (next.done) {
      setOpen(false)
      trigger.current?.focus()
    }
  }

  const half = (label: string, value: DateKey | null, active: boolean) => (
    <span className={`flex-1 min-w-0 px-3 py-2 text-left ${active ? 'bg-[var(--accent-subtle)]' : ''}`}>
      <span className="block text-[11.5px] text-[var(--text-muted)]">{label}</span>
      <span className={`block truncate text-[14px] font-semibold ${value ? 'text-[var(--text-primary)]' : 'text-[var(--text-muted)] font-normal'}`}>
        {value ? dayLabelTh(value, lang) : t('Pick a day', 'เลือกวัน')}
      </span>
    </span>
  )

  return (
    <div ref={box} className="relative w-full max-w-[560px]">
      <button
        ref={trigger}
        type="button"
        disabled={disabled}
        onClick={() => (open ? setOpen(false) : openPicker())}
        aria-haspopup="dialog"
        aria-expanded={open}
        className="w-full flex items-stretch rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:border-[var(--bg-border-hover)] overflow-hidden disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--accent)]"
      >
        <span className="flex items-center pl-3 text-[var(--text-muted)]">
          <CalendarDays size={17} />
        </span>
        {half(t('Start day', 'วันเริ่ม'), start, open && (!start || !!end))}
        <span className="flex items-center px-1">
          <span className="whitespace-nowrap rounded-full border border-[var(--bg-border)] px-2.5 py-0.5 text-[12px] font-medium text-[var(--text-secondary)] tabular-nums">
            {start && end ? t(`${daysInclusive(start, end)} days`, `${daysInclusive(start, end)} วัน`) : t('— days', '— วัน')}
          </span>
        </span>
        {half(t('End day', 'วันสิ้นสุด'), end, open && !!start && !end)}
      </button>

      {open && (
        <div
          role="dialog"
          aria-label={t('Pick a date range', 'เลือกช่วงวันที่')}
          className="absolute left-0 top-full z-40 mt-2 w-full sm:w-[min(640px,calc(100vw-32px))] rounded-xl border border-[var(--bg-border)] bg-[var(--bg-surface)] p-4 shadow-2xl"
        >
          <div className="flex items-center gap-2 pb-3 border-b border-[var(--bg-border-subtle)]">
            <span className="text-[13.5px] font-semibold text-[var(--text-primary)]">
              {!start || end ? t('Pick the start day', 'เลือกวันเริ่ม') : t('Pick the end day', 'เลือกวันสิ้นสุด')}
            </span>
            {count !== null && (
              <span className="rounded-full bg-[var(--accent-subtle)] px-2.5 py-0.5 text-[12px] font-semibold text-[var(--accent)] tabular-nums">
                {t(`${count} days`, `${count} วัน`)}
              </span>
            )}
            <span className="flex-1" />
            <button
              type="button"
              onClick={() => setOpen(false)}
              aria-label={t('Close calendar', 'ปิดปฏิทิน')}
              className="p-1 rounded-md text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer"
            >
              <X size={16} />
            </button>
          </div>

          <div className="relative grid grid-cols-1 sm:grid-cols-2 gap-6 pt-3">
            <button
              type="button"
              onClick={() => setRight(addMonths(right, -1))}
              disabled={!canPrev}
              aria-label={t('Previous month', 'เดือนก่อนหน้า')}
              className="absolute left-0 top-2.5 p-1 rounded-md text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
            >
              <ChevronLeft size={18} />
            </button>
            <button
              type="button"
              onClick={() => setRight(addMonths(right, 1))}
              disabled={!canNext}
              aria-label={t('Next month', 'เดือนถัดไป')}
              className="absolute right-0 top-2.5 p-1 rounded-md text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
            >
              <ChevronRight size={18} />
            </button>
            {months.map((m, mi) => (
              <div key={m} className={mi === 0 ? 'hidden sm:block' : ''}>
                <div className="text-center text-[13.5px] font-semibold text-[var(--text-primary)] h-8 leading-8">{monthLabelTh(m, lang)}</div>
                <div className="grid grid-cols-7 text-center text-[11.5px] text-[var(--text-muted)] mt-1">
                  {(lang === 'en' ? WEEKDAYS_EN : WEEKDAYS_TH).map((w) => (
                    <span key={w} className="h-7 leading-7">{w}</span>
                  ))}
                </div>
                <div className="grid grid-cols-7" onMouseLeave={() => setHover(null)}>
                  {monthGrid(m).flat().map((day, i) => {
                    if (!day) return <span key={`e${i}`} className="h-9" />
                    const off = day < min || day > today
                    const isStart = day === start
                    const isEnd = day === previewEnd
                    const inRange = !!start && !!previewEnd && day > start && day < previewEnd
                    const edge = isStart || isEnd
                    return (
                      <span
                        key={day}
                        className={`h-9 flex items-center justify-center ${inRange ? 'bg-[var(--accent-subtle)]' : ''} ${
                          isStart && previewEnd && previewEnd !== start ? 'bg-gradient-to-r from-transparent from-50% to-[var(--accent-subtle)] to-50%' : ''
                        } ${isEnd && start && previewEnd !== start ? 'bg-gradient-to-l from-transparent from-50% to-[var(--accent-subtle)] to-50%' : ''}`}
                      >
                        <button
                          type="button"
                          disabled={off}
                          onClick={() => click(day)}
                          onMouseEnter={() => setHover(day)}
                          aria-pressed={edge}
                          aria-label={`${dayLabelTh(day, lang)}${day === today ? t(' (today)', ' (วันนี้)') : ''}`}
                          className={`h-9 w-9 rounded-full text-[13px] tabular-nums cursor-pointer disabled:cursor-not-allowed disabled:text-[var(--text-dim)] disabled:line-through ${
                            edge
                              ? 'bg-[var(--accent-fill)] text-white font-semibold'
                              : 'text-[var(--text-primary)] hover:bg-[var(--bg-hover)] hover:ring-1 hover:ring-[var(--accent-border)]'
                          } ${day === today && !edge ? 'ring-1 ring-[var(--bg-border-hover)] font-semibold' : ''}`}
                        >
                          {Number(day.slice(8))}
                        </button>
                      </span>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-3 mt-3 border-t border-[var(--bg-border-subtle)] text-[12px] text-[var(--text-muted)]">
            <span>{t(`You can go back ${RETENTION_DAYS} days, as long as logs are kept · pick the times after the days`, `เลือกได้ย้อนหลัง ${RETENTION_DAYS} วันตามระยะที่ระบบเก็บ log · เลือกเวลาได้หลังเลือกวัน`)}</span>
            <span className="flex-1" />
            {(start || end) && (
              <button
                type="button"
                onClick={() => onChange(null, null, false)}
                className="font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                {t('Clear dates', 'ล้างวันที่')}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export default DateRangePicker
