import React from 'react'
import { Link } from 'react-router-dom'
import { useAuthStore } from '../store/authStore'

// A platform-wide page that only the operator may open. A regular user who
// lands on it (an old bookmark) is pointed at the origin tab that holds the
// same setting for their own sites.
export const OperatorOnly: React.FC<{ originTab: string; children: React.ReactNode }> = ({ originTab, children }) => {
  const user = useAuthStore((s) => s.user)
  if (user?.role === 'admin') return <>{children}</>
  return (
    <div className="dash-card p-5 mt-3.5 font-mono text-[12px] text-[var(--text-muted)] space-y-2">
      <p className="m-0 text-[var(--text-primary)] font-bold">This list belongs to the platform operator.</p>
      <p className="m-0">
        Your sites have their own: open an origin in <Link to="/origins" className="text-orange-500">Origin servers</Link> and
        use its <strong>{originTab}</strong> tab.
      </p>
    </div>
  )
}
