import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['DM Sans', '-apple-system', 'sans-serif'],
        heading: ['Inter', 'DM Sans', '-apple-system', 'sans-serif'],
        mono: ['IBM Plex Mono', 'Courier New', 'monospace'],
      },
      colors: {
        bg: {
          primary: '#0d1117',
          surface: '#161b27',
          surface2: '#1e2438',
          border: 'rgba(255,255,255,0.07)',
        },
        accent: {
          DEFAULT: '#667eea',
          dark: '#764ba2',
          light: '#a5b4fc',
          tg: '#229ed9',
        },
        success: '#68d391',
        warning: '#f6ad55',
        danger: '#fc8181',
        info: '#76e4f7',
        text: {
          primary: '#e4e8f0',
          muted: 'rgba(255,255,255,0.4)',
          subtle: 'rgba(255,255,255,0.2)',
        },
      },
      boxShadow: {
        card: '0 2px 8px rgba(0,0,0,0.06)',
        'card-hover': '0 8px 20px rgba(0,0,0,0.1)',
        modal: '0 20px 60px rgba(0,0,0,0.3)',
        glow: '0 0 20px rgba(102,126,234,0.15)',
        'glow-lg': '0 0 40px rgba(102,126,234,0.2)',
      },
      animation: {
        'fade-in-up': 'fadeInUp 0.45s cubic-bezier(0.16, 1, 0.3, 1) both',
        'scale-in': 'scaleIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) both',
        'slide-down': 'slideDown 0.3s ease-out both',
        'float': 'float 3s ease-in-out infinite',
        'breathe': 'breathe 2s ease-in-out infinite',
        'gradient': 'gradient-shift 4s ease infinite',
      },
      keyframes: {
        fadeInUp: {
          from: { opacity: '0', transform: 'translateY(16px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        scaleIn: {
          from: { opacity: '0', transform: 'scale(0.95)' },
          to: { opacity: '1', transform: 'scale(1)' },
        },
        slideDown: {
          from: { opacity: '0', transform: 'translateY(-8px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-6px)' },
        },
        breathe: {
          '0%, 100%': { opacity: '0.4' },
          '50%': { opacity: '0.8' },
        },
        'gradient-shift': {
          '0%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
          '100%': { backgroundPosition: '0% 50%' },
        },
      },
    },
  },
  plugins: [],
} satisfies Config
