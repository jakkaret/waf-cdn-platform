import React from 'react'
import { Globe, ShieldCheck, XCircle, CheckCircle2 } from 'lucide-react'

// The auth screens' hero visual: what actually happens to a request before it
// reaches an origin. Real architecture, not a decorative illustration — every
// label here is true of the running system, not a claimed metric.
export const DecisionPipeline: React.FC = () => {
  return (
    <div className="dash-card p-5 sm:p-6 max-w-md">
      <div className="flex items-center gap-2 mb-5">
        <span className="status-ping">
          <span className="status-ping-pulse bg-[var(--success)]" />
          <span className="status-ping-dot bg-[var(--success)]" />
        </span>
        <span className="font-mono text-[11px] font-semibold uppercase tracking-[0.1em] text-[var(--text-secondary)]">
          ModSecurity CRS 3.3 · always on
        </span>
      </div>

      <div className="font-mono text-[12.5px] leading-relaxed">
        <div className="flex items-center gap-3">
          <Globe size={15} className="text-[var(--text-muted)] shrink-0" />
          <span className="text-[var(--text-primary)] font-semibold">Request arrives</span>
        </div>

        <div className="pl-[7px] border-l-2 border-[var(--bg-border)] ml-1 my-1 h-4" />

        <div className="flex items-center gap-3">
          <ShieldCheck size={15} className="text-[var(--accent)] shrink-0" />
          <span className="text-[var(--text-primary)]">
            Scored against OWASP CRS <span className="text-[var(--text-muted)]">(SQLi, XSS, traversal, …)</span>
          </span>
        </div>

        <div className="pl-[7px] border-l-2 border-[var(--bg-border)] ml-1 my-1 h-4" />

        <div className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-2 items-center">
          <div className="flex items-center gap-3">
            <XCircle size={15} className="text-[var(--danger)] shrink-0" />
            <span className="text-[var(--text-secondary)]">Malicious pattern matched</span>
          </div>
          <span
            className="mono-chip text-[var(--danger)]"
            style={{ borderColor: 'var(--danger)', backgroundColor: 'var(--danger-subtle)' }}
          >
            403 + logged
          </span>

          <div className="flex items-center gap-3">
            <CheckCircle2 size={15} className="text-[var(--success)] shrink-0" />
            <span className="text-[var(--text-secondary)]">Nothing matched</span>
          </div>
          <span
            className="mono-chip text-[var(--success)]"
            style={{ borderColor: 'var(--success)', backgroundColor: 'var(--success-subtle)' }}
          >
            forwarded
          </span>
        </div>
      </div>

      <p className="mt-5 pt-4 border-t border-[var(--bg-border-subtle)] text-[12px] leading-5 text-[var(--text-muted)]">
        Every decision your operators review in the console is made here, at the edge — before a
        single byte reaches the origin.
      </p>
    </div>
  )
}

export default DecisionPipeline
