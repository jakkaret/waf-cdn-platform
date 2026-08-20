import React from 'react'

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'outline' | 'ghost' | 'brand' | 'success'
  size?: 'xs' | 'sm' | 'md' | 'lg'
  icon?: React.ReactNode
  isLoading?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      children,
      variant = 'primary',
      size = 'md',
      icon,
      isLoading,
      className = '',
      disabled,
      ...props
    },
    ref
  ) => {
    const base =
      'inline-flex items-center justify-center gap-1.5 font-medium rounded-md transition-all duration-150 focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer'

    const variants: Record<string, string> = {
      primary:
        'bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white shadow-sm border border-transparent active:scale-[0.98]',
      brand:
        'bg-orange-500 hover:bg-orange-600 text-white shadow-sm border border-transparent active:scale-[0.98]',
      secondary:
        'bg-[var(--bg-surface-elevated)] text-[var(--text-primary)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] hover:bg-[var(--bg-hover)] shadow-sm active:scale-[0.98]',
      danger:
        'bg-red-500/10 text-red-500 border border-red-500/30 hover:bg-red-500/20 active:scale-[0.98]',
      success:
        'bg-emerald-500/10 text-emerald-500 border border-emerald-500/30 hover:bg-emerald-500/20 active:scale-[0.98]',
      outline:
        'bg-transparent text-[var(--accent)] border border-[var(--accent)]/50 hover:bg-[var(--accent-subtle)] active:scale-[0.98]',
      ghost:
        'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] border border-transparent',
    }

    const sizes: Record<string, string> = {
      xs: 'px-2 py-0.5 text-[11px]',
      sm: 'px-2.5 py-1 text-[11.5px]',
      md: 'px-3 py-1.5 text-[12.5px]',
      lg: 'px-4 py-2 text-[13.5px]',
    }

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
        {...props}
      >
        {isLoading ? (
          <svg className="animate-spin -ml-0.5 mr-1.5 h-3.5 w-3.5 text-current" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
        ) : icon ? (
          <span className="shrink-0 flex items-center justify-center">{icon}</span>
        ) : null}
        {children}
      </button>
    )
  }
)
Button.displayName = 'Button'
