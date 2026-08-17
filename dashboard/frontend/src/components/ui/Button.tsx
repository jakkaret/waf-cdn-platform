import React from 'react'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'outline' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  icon?: React.ReactNode
  isLoading?: boolean
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(({
  children,
  variant = 'primary',
  size = 'md',
  icon,
  isLoading,
  className = '',
  disabled,
  ...props
}, ref) => {
  const baseStyle = "inline-flex items-center justify-center gap-2 font-semibold transition-all duration-200 focus:outline-none rounded-[10px] disabled:opacity-40 disabled:cursor-not-allowed press-scale"
  
  const variants = {
    primary: "gradient-brand text-white hover:shadow-glow shimmer-hover",
    secondary: "bg-white/[0.05] text-white/70 hover:bg-white/[0.08] hover:text-white/90 border border-white/[0.06]",
    danger: "bg-danger/[0.08] text-danger hover:bg-danger/[0.14] border border-danger/[0.12]",
    outline: "bg-transparent text-accent-light border border-accent/20 hover:bg-accent/[0.06] hover:border-accent/30",
    ghost: "bg-transparent text-white/35 hover:text-white/60 hover:bg-white/[0.04]",
  }

  const sizes = {
    sm: "px-3 py-1.5 text-[11px]",
    md: "px-4 py-2 text-[13px]",
    lg: "px-6 py-2.5 text-[14px]",
  }

  return (
    <button
      ref={ref}
      disabled={disabled || isLoading}
      className={`${baseStyle} ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    >
      {isLoading ? (
        <svg className="animate-spin -ml-1 mr-1.5 h-3.5 w-3.5 text-current" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
      ) : icon ? (
        <span className="w-4 h-4 flex items-center justify-center">{icon}</span>
      ) : null}
      {children}
    </button>
  )
})
Button.displayName = 'Button'
