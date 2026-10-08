import React from 'react'
import { Link } from 'react-router-dom'

// F-029: rendered for any URL no route matches (previously a blank screen).
export const NotFound: React.FC = () => (
  <div className="min-h-screen flex items-center justify-center bg-[var(--bg-primary)] text-[var(--text-primary)] p-6">
    <div className="text-center space-y-3">
      <div className="font-mono text-[42px] font-bold text-orange-500">404</div>
      <p className="text-[14px] m-0">ไม่พบหน้าที่คุณต้องการ (Page not found)</p>
      <Link to="/" className="inline-block mt-2 text-[13px] font-mono text-orange-500 hover:underline">
        ← กลับหน้าแดชบอร์ด
      </Link>
    </div>
  </div>
)

export default NotFound
