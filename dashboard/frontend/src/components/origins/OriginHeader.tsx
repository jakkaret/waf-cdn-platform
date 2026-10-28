import React from 'react'
import { Link } from 'react-router-dom'
import { AlertCircle, AlertTriangle, ArrowRight, Cable, ChevronLeft, ChevronRight, Lock, Server, User } from 'lucide-react'
import type { Origin, OriginOverview } from '../../types'
import { ORIGIN_ROLE_LABEL, type OriginRole } from '../../lib/roles'
import { onCount, PROT_KEYS, type Health, type ProtKey, type ProtState } from '../../lib/originSummary'
import { originUpstreamLabel } from '../../lib/originUpstream'
import { originTabPath } from '../layout/navigation'
import { ProtIcons, StatusPill } from './OriginBits'

// Top of an origin page: breadcrumb with previous/next origin, the name with
// one status pill and the viewer's role, four facts (connection, blocked in
// 24 h, protections, domains), then a banner when something needs fixing.

interface Props {
  origin: Origin
  role: OriginRole | null
  health: Health
  overview?: OriginOverview
  prot: Record<ProtKey, { state: ProtState; summary: string }>
  canEdit: boolean
  position?: { index: number; total: number; prevId: string; nextId: string; prevLabel: string; nextLabel: string }
  actions?: React.ReactNode
}

const BANNER: Record<string, { title: string; body: string }> = {
  'Tunnel offline': { title: 'Tunnel agent not connected', body: 'The agent on your server is offline, so visitors cannot reach this website. Restart the agent on the server.' },
  Offline: { title: 'Your server is not responding', body: 'The edge cannot reach this origin, so visitors get an error page. Check that the web server is running and its firewall allows the WAF.' },
  'Pending setup': { title: 'Setup is not finished', body: 'Add the DNS record shown under Domains & DNS to finish connecting this website.' },
  'Pending DNS': { title: 'DNS does not point to the edge yet', body: 'Visitors still reach your server directly and are not protected. Add the record shown under Domains & DNS.' },
  Inactive: { title: 'This origin is inactive', body: 'The WAF is not serving it. Check the origin settings on the Overview tab.' },
}

const fmt = (n: number) => n.toLocaleString('en-US')

export const OriginHeader: React.FC<Props> = ({ origin, role, health, overview, prot, canEdit, position, actions }) => {
  const serving = health.tone === 'ok'
  const blocked = overview?.blocked_24h
  const domains = overview?.domains
  const banner = health.needsAction ? BANNER[health.label] : undefined
  const step = health.step
  const stepHref = step?.path ?? (step?.tab ? originTabPath(origin.origin_id, step.tab) : undefined)

  return (
    <div className="space-y-3">
      <nav aria-label="Breadcrumb" className="flex items-center gap-2 text-[13px] text-[var(--text-muted)]">
        <Link to="/origins" className="inline-flex items-center gap-1.5 text-[var(--text-secondary)] hover:text-[var(--text-primary)] no-underline">
          <ChevronLeft size={14} />
          Origins
        </Link>
        <span>/</span>
        <span className="truncate text-[var(--text-primary)]">{origin.label}</span>
        <span className="flex-1" />
        {position && position.total > 1 && (
          <span className="inline-flex items-center gap-1">
            <span className="hidden sm:inline font-mono text-[12px] tabular-nums">
              {position.index + 1} of {position.total}
            </span>
            <Link
              to={`/origins/${encodeURIComponent(position.prevId)}`}
              aria-label={`Previous origin: ${position.prevLabel}`}
              title={position.prevLabel}
              className="w-8 h-8 grid place-items-center rounded-lg border border-[var(--bg-border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            >
              <ChevronLeft size={15} />
            </Link>
            <Link
              to={`/origins/${encodeURIComponent(position.nextId)}`}
              aria-label={`Next origin: ${position.nextLabel}`}
              title={position.nextLabel}
              className="w-8 h-8 grid place-items-center rounded-lg border border-[var(--bg-border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)]"
            >
              <ChevronRight size={15} />
            </Link>
          </span>
        )}
      </nav>

      <section className="dash-card p-[18px]">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="m-0 text-[22px] font-semibold tracking-[-0.01em] text-[var(--text-primary)] break-all">{origin.label}</h1>
          <StatusPill tone={health.tone}>{health.label}</StatusPill>
          {role && (
            <span
              className="inline-flex items-center gap-1.5 h-6 px-2 rounded-md border border-[var(--bg-border)] text-[12px] font-medium text-[var(--text-secondary)]"
              title={role === 'owner' ? 'Owner manages everything' : role === 'editor' ? 'Editor changes settings' : 'Viewer can only look'}
            >
              {role === 'viewer' ? <Lock size={12} /> : <User size={12} />}
              You are {ORIGIN_ROLE_LABEL[role]}
            </span>
          )}
          <span className="flex-1" />
          {actions}
        </div>

        <div className="mt-4 grid grid-cols-2 lg:grid-cols-4 rounded-[10px] border border-[var(--bg-border)]">
          <div className="px-4 py-3 min-w-0">
            <div className="text-[12.5px] text-[var(--text-muted)]">Connection</div>
            <div className="mt-1 flex items-center gap-2 text-[15px] font-semibold text-[var(--text-primary)]">
              {origin.is_tunnel ? <Cable size={16} /> : <Server size={16} />}
              {origin.is_tunnel ? 'Private tunnel' : 'Direct to server'}
            </div>
            <div className="font-mono text-[12px] text-[var(--text-muted)] truncate" title={originUpstreamLabel(origin)}>
              {originUpstreamLabel(origin)}
            </div>
          </div>
          <div className="px-4 py-3 min-w-0 border-l border-[var(--bg-border)]">
            <div className="text-[12.5px] text-[var(--text-muted)]">Blocked · last 24 h</div>
            <div className="mt-1 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">
              {!serving || blocked == null ? '—' : fmt(blocked)}
            </div>
            <div className="text-[12px] text-[var(--text-muted)] truncate">
              {!serving ? 'Not serving traffic' : overview?.requests_24h != null ? `of ${fmt(overview.requests_24h)} requests` : 'Log store unavailable'}
            </div>
          </div>
          <div className="px-4 py-3 min-w-0 border-t lg:border-t-0 lg:border-l border-[var(--bg-border)]">
            <div className="text-[12.5px] text-[var(--text-muted)]">Protection · {onCount(prot)} of {PROT_KEYS.length} on</div>
            <div className="mt-1.5">
              <ProtIcons states={prot} />
            </div>
          </div>
          <div className="px-4 py-3 min-w-0 border-t lg:border-t-0 border-l border-[var(--bg-border)]">
            <div className="text-[12.5px] text-[var(--text-muted)]">Domains</div>
            <div className="mt-1 text-[22px] font-semibold tabular-nums text-[var(--text-primary)]">
              {domains ? domains.verified : '—'} <small className="text-[13px] font-normal text-[var(--text-muted)]">/ {domains ? domains.total : '—'}</small>
            </div>
            <div className="text-[12px] text-[var(--text-muted)] truncate">
              {!domains ? '' : domains.total === 0 ? (origin.is_tunnel ? 'Served through the tunnel' : 'No domain yet') : domains.verified === domains.total ? 'DNS verified' : 'Waiting for DNS'}
            </div>
          </div>
        </div>
      </section>

      {banner && (
        <div
          role="status"
          className={`flex flex-wrap items-start gap-3 rounded-[10px] border px-3.5 py-3 text-[13.5px] ${
            health.tone === 'bad'
              ? 'bg-[var(--danger-subtle)] border-red-600/30'
              : 'bg-[var(--warning-subtle)] border-amber-600/35'
          }`}
        >
          {health.tone === 'bad' ? (
            <AlertCircle size={18} className="mt-0.5 text-red-600 dark:text-red-400" />
          ) : (
            <AlertTriangle size={18} className="mt-0.5 text-amber-600 dark:text-amber-400" />
          )}
          <div className="flex-1 min-w-[200px]">
            <b className="block font-semibold text-[var(--text-primary)]">{banner.title}</b>
            <span className="text-[var(--text-secondary)]">{banner.body}</span>
          </div>
          {canEdit && step && stepHref && (
            <Link
              to={stepHref}
              className="self-center inline-flex items-center gap-1.5 h-8 px-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] text-[12.5px] font-medium text-[var(--text-primary)] hover:bg-[var(--bg-hover)] no-underline"
            >
              {step.label}
              <ArrowRight size={14} />
            </Link>
          )}
        </div>
      )}

      {!canEdit && (
        <div role="status" className="flex items-start gap-3 rounded-[10px] border border-[var(--bg-border)] bg-[var(--bg-surface)] px-3.5 py-3 text-[13.5px]">
          <Lock size={18} className="mt-0.5 text-[var(--text-muted)]" />
          <div>
            <b className="block font-semibold text-[var(--text-primary)]">View only</b>
            <span className="text-[var(--text-secondary)]">You can see everything here, but only an Owner or Editor can change it.</span>
          </div>
        </div>
      )}
    </div>
  )
}

export default OriginHeader
