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
  const baseStyle = "inline-flex items-center justify-center gap-2 font-medium transition-all focus:outline-none rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
  
  const variants = {
    primary: "gradient-brand text-white hover:brightness-110 shadow-md",
    secondary: "bg-white/10 text-text-primary hover:bg-white/15 border border-white/10",
    danger: "bg-danger/10 text-danger hover:bg-danger/20 border border-danger/20",
    outline: "bg-transparent text-accent-light border border-accent/30 hover:bg-accent/10",
    ghost: "bg-transparent text-text-muted hover:text-text-primary hover:bg-white/5",
  }

  const sizes = {
    sm: "px-3 py-1.5 text-[12px]",
    md: "px-4 py-2 text-[13.5px]",
    lg: "px-6 py-3 text-[15px]",
  }

  return (
    <button
      ref={ref}
      disabled={disabled || isLoading}
      className={`${baseStyle} ${variants[variant]} ${sizes[size]} ${className}`}
      {...props}
    >
      {isLoading ? (
        <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-current" fill="none" viewBox="0 0 24 24">
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
