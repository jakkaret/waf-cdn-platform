import React from 'react'
import { Link } from 'react-router-dom'
import { Lock } from 'lucide-react'
import { useAuthStore } from '../store/authStore'
import { isOperator } from '../lib/permissions'

// A platform-wide page that only the operator may open. A regular user who
// lands on it (an old bookmark) is pointed at the origin tab that holds the
// same setting for their own sites. The backend guards the data either way;
// this only keeps the page from rendering controls that would all fail.
export const OperatorOnly: React.FC<{ originTab?: string; children: React.ReactNode }> = ({ originTab, children }) => {
  const user = useAuthStore((s) => s.user)
  if (isOperator(user)) return <>{children}</>
  return (
    <div className="dash-card p-5 mt-3.5 max-w-xl text-[13px] text-[var(--text-secondary)] space-y-2">
      <p className="m-0 flex items-center gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
        <Lock size={15} aria-hidden="true" />
        This page is for the platform operator
      </p>
      {originTab ? (
        <p className="m-0">
          Your sites have their own: open an origin in <Link to="/origins" className="text-[var(--accent)] hover:underline">Origins</Link>{' '}
          and use its <strong>{originTab}</strong> tab.
        </p>
      ) : (
        <p className="m-0">
          Everything for your own sites is in <Link to="/origins" className="text-[var(--accent)] hover:underline">Origins</Link>.
        </p>
      )}
    </div>
  )
}
