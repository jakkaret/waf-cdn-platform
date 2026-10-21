import React, { useEffect, useRef } from 'react'
import { normalizeOtp } from '../../lib/emailGate'

// Six digit boxes for an emailed code. Typing moves to the next box,
// Backspace to the previous, and pasting "123 456" fills all six. The value
// is a plain string of up to six digits; onComplete fires when it is full.

interface OtpInputProps {
  value: string
  onChange: (value: string) => void
  onComplete?: (value: string) => void
  disabled?: boolean
  invalid?: boolean
  autoFocus?: boolean
}

const LENGTH = 6

export const OtpInput: React.FC<OtpInputProps> = ({ value, onChange, onComplete, disabled, invalid, autoFocus }) => {
  const refs = useRef<Array<HTMLInputElement | null>>([])
  const digits = Array.from({ length: LENGTH }, (_, i) => value[i] ?? '')

  useEffect(() => {
    if (autoFocus) refs.current[0]?.focus()
  }, [autoFocus])

  const focus = (i: number) => refs.current[Math.max(0, Math.min(LENGTH - 1, i))]?.focus()

  const set = (next: string) => {
    const clean = normalizeOtp(next)
    onChange(clean)
    if (clean.length === LENGTH) onComplete?.(clean)
  }

  const handleChange = (i: number, raw: string) => {
    let typed = normalizeOtp(raw)
    // a digit typed next to the one already in the box (no selection)
    if (typed.length === 2 && digits[i]) typed = typed.startsWith(digits[i]) ? typed[1] : typed[0]
    if (!typed) return
    if (typed.length > 1) {
      // autofill or a paste into one box
      set(value.slice(0, i) + typed)
      focus(i + typed.length)
      return
    }
    const next = (value.slice(0, i) + typed + value.slice(i + 1)).slice(0, LENGTH)
    set(next)
    focus(i + 1)
  }

  const handleKeyDown = (i: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace') {
      e.preventDefault()
      if (digits[i]) {
        set(value.slice(0, i) + value.slice(i + 1))
      } else if (i > 0) {
        set(value.slice(0, i - 1) + value.slice(i))
        focus(i - 1)
      }
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault()
      focus(i - 1)
    } else if (e.key === 'ArrowRight') {
      e.preventDefault()
      focus(i + 1)
    }
  }

  return (
    <div
      className={`flex items-center justify-center gap-2 sm:gap-2.5 ${invalid ? 'animate-shake' : ''}`}
      onPaste={(e) => {
        e.preventDefault()
        const pasted = normalizeOtp(e.clipboardData.getData('text'))
        if (pasted) {
          set(pasted)
          focus(pasted.length)
        }
      }}
    >
      {digits.map((d, i) => (
        <React.Fragment key={i}>
          {i === LENGTH / 2 && <span className="w-2.5 h-0.5 rounded bg-[var(--bg-border-hover)] shrink-0" aria-hidden="true" />}
          <input
            ref={(el) => {
              refs.current[i] = el
            }}
            type="text"
            inputMode="numeric"
            autoComplete={i === 0 ? 'one-time-code' : 'off'}
            aria-label={`รหัสหลักที่ ${i + 1}`}
            maxLength={i === 0 ? LENGTH : 1}
            disabled={disabled}
            value={d}
            onChange={(e) => handleChange(i, e.target.value)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            onFocus={(e) => e.target.select()}
            className={`w-10 h-12 sm:w-12 sm:h-14 text-center font-mono text-[22px] sm:text-[24px] font-bold rounded-lg border bg-[var(--bg-primary)] text-[var(--text-primary)] outline-none transition-all caret-orange-500 disabled:opacity-50 ${
              invalid
                ? 'border-red-500/70 shadow-[0_0_0_3px_var(--danger-subtle)]'
                : d
                  ? 'border-orange-500/60 bg-[var(--accent-subtle)]'
                  : 'border-[var(--bg-border)]'
            } focus:border-[var(--accent)] focus:shadow-[0_0_0_3px_var(--accent-subtle)]`}
          />
        </React.Fragment>
      ))}
    </div>
  )
}

export default OtpInput
