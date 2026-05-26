import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['DM Sans', '-apple-system', 'sans-serif'],
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
      },
    },
  },
  plugins: [],
} satisfies Config
