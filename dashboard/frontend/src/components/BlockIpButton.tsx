import React, { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Ban, ChevronDown } from 'lucide-react'
import { getOrigins } from '../api/origins'
import { useAuthStore } from '../store/authStore'
import { isBlockableIp } from '../lib/alertActions'
import { originTabPath } from './layout/navigation'
import type { Origin } from '../types'

// "Block IP" from wherever an IP is shown. It never blocks anything itself:
// it opens the origin's IP access tab with the IP filled in, where the role
// is checked and the block is reviewed and confirmed. With a known origin it
// goes straight there; otherwise it asks which origin to block it on.

interface Props {
  ip: string
  originId?: string | null
  note?: string
  size?: 'sm' | 'md'
}

export const BlockIpButton: React.FC<Props> = ({ ip, originId, note, size = 'sm' }) => {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)

  const { data: list = [] } = useQuery({
    queryKey: ['origins-selector-list', user?.user_id],
    queryFn: () => getOrigins().then((r) => r.data?.origins || []).catch(() => [] as Origin[]),
    enabled: !!user && !originId,
    staleTime: 30_000,
  })
  const origins = (Array.isArray(list) ? list : []).filter(
    (o) => o?.origin_id && !['archived', 'deleted'].includes((o.status || '').toLowerCase()),
  )

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  if (!isBlockableIp(ip)) return null

  const go = (id: string) => {
    setOpen(false)
    navigate(originTabPath(id, 'ip-access', note ? { ip, note } : { ip }))
  }

  const cls = `inline-flex items-center gap-1 rounded-md border border-red-600/30 text-red-700 dark:text-red-300 hover:bg-red-500/10 font-medium cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
    size === 'sm' ? 'h-7 px-2 text-[12px]' : 'h-9 px-3 text-[12.5px]'
  }`

  if (originId) {
    return (
      <button type="button" className={cls} onClick={() => go(originId)} aria-label={`Block ${ip}`}>
        <Ban size={12} aria-hidden="true" />
        Block IP
      </button>
    )
  }
  if (origins.length === 1) {
    return (
      <button type="button" className={cls} onClick={() => go(origins[0].origin_id)} aria-label={`Block ${ip} on ${origins[0].label}`}>
        <Ban size={12} aria-hidden="true" />
        Block IP
      </button>
    )
  }
  if (origins.length === 0) return null

  return (
    <div ref={rootRef} className="relative inline-block">
      <button type="button" className={cls} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <Ban size={12} aria-hidden="true" />
        Block IP
        <ChevronDown size={12} aria-hidden="true" />
      </button>
      {open && (
        <div role="menu" aria-label={`Block ${ip} on`} className="absolute right-0 z-30 mt-1 w-60 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface-elevated)] p-1 shadow-lg">
          <p className="m-0 px-2.5 py-1.5 text-[11.5px] text-[var(--text-muted)]">Block on which origin?</p>
          {origins.map((o) => (
            <button
              key={o.origin_id}
              type="button"
              role="menuitem"
              onClick={() => go(o.origin_id)}
              className="block w-full truncate rounded-md px-2.5 py-1.5 text-left text-[13px] text-[var(--text-primary)] hover:bg-[var(--nav-hover)] cursor-pointer"
            >
              {o.label || o.ip}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export default BlockIpButton
