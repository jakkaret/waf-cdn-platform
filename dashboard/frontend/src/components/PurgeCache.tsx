import React, { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2, CheckCircle2, Loader2 } from 'lucide-react'
import { Button } from './ui/Button'
import { ConfirmDialog } from './ui/ConfirmDialog'
import { cdnApi, PurgeEdgeStatus } from '../api/cdn'

// Edge cache purge for one site. The dashboard queues the job; every edge
// pulls it from control-api within a few seconds and deletes its own cached
// copies (services/cdn_purge.py, cdn/edge/entrypoint.d/99-rulesync.sh). The
// per-edge ticks below come from the edges' own acknowledgements.

const fieldClass = 'dash-input h-9 font-mono text-[12.5px]'
const EDGE_LABEL: Record<string, string> = { 'edge-th': 'Thailand', 'edge-asia': 'Hong Kong' }

interface Props {
  domains: string[]
  canEdit: boolean
}

export const PurgeCache: React.FC<Props> = ({ domains, canEdit }) => {
  const [host, setHost] = useState(domains[0] || '')
  const [path, setPath] = useState('/*')
  const [jobId, setJobId] = useState<number | null>(null)
  const [confirmAll, setConfirmAll] = useState(false)
  const selected = domains.includes(host) ? host : domains[0] || ''
  const targetPath = path.trim() || '/*'
  const wholeSite = targetPath === '/*' || targetPath === '/'

  const purge = useMutation({
    mutationFn: () => cdnApi.purgeCache(selected, targetPath),
    onSuccess: (res) => {
      setJobId(res.job_id)
      toast.success(`Purge of ${res.host}${res.path} sent to every edge`)
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Could not purge the cache. Nothing was removed.'),
    onSettled: () => setConfirmAll(false),
  })

  const { data: status } = useQuery({
    queryKey: ['cdn-purge', jobId],
    queryFn: () => cdnApi.getPurgeStatus(jobId as number),
    enabled: jobId !== null,
    // Poll until every edge that is polling has applied it.
    refetchInterval: (q) => {
      const edges = Object.values(q.state.data?.edges || {}) as PurgeEdgeStatus[]
      return edges.length > 0 && edges.every((e) => e.applied || !e.polling) ? false : 2000
    },
  })

  if (domains.length === 0) return null

  return (
    <div className="dash-card p-5 space-y-3">
      <div className="flex items-center gap-2 pb-3 border-b border-[var(--bg-border-subtle)]">
        <Trash2 size={15} className="text-[var(--text-muted)]" aria-hidden="true" />
        <h3 className="text-[14px] font-semibold text-[var(--text-primary)] m-0">Purge cache</h3>
      </div>
      <p className="m-0 text-[13px] leading-relaxed text-[var(--text-muted)]">
        Removes the copies the edges keep, so the next visitor gets a fresh page from your server. Enter one path
        (<span className="font-mono">/pricing</span>), a prefix (<span className="font-mono">/static/*</span>) or the whole site
        (<span className="font-mono">/*</span>).
      </p>
      {canEdit ? (
        <form
          className="flex flex-col gap-2 sm:flex-row sm:items-center"
          onSubmit={(e) => {
            e.preventDefault()
            if (!selected) return
            // A whole-site purge sends every visitor to the origin at once.
            if (wholeSite) setConfirmAll(true)
            else purge.mutate()
          }}
        >
          <label htmlFor="purge-host" className="sr-only">Domain</label>
          <select id="purge-host" value={selected} onChange={(e) => setHost(e.target.value)} className={`${fieldClass} sm:w-56`}>
            {domains.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
          <label htmlFor="purge-path" className="sr-only">Path</label>
          <input id="purge-path" value={path} onChange={(e) => setPath(e.target.value)} placeholder="/*" className={`${fieldClass} flex-1 min-w-0`} />
          <Button variant="brand" size="md" type="submit" isLoading={purge.isPending} icon={<Trash2 size={13} />}>
            Purge
          </Button>
        </form>
      ) : (
        <p className="m-0 text-[13px] text-[var(--text-muted)]">Only an Owner or Editor of this site can purge its cache.</p>
      )}
      {jobId !== null && (
        <ul className="m-0 p-0 list-none flex flex-wrap gap-x-4 gap-y-1 text-[12.5px]" aria-live="polite">
          {Object.entries(status?.edges || {}).map(([name, e]) => (
            <li key={name} className="flex items-center gap-1.5">
              {e.applied ? (
                <CheckCircle2 size={13} className="text-emerald-600" aria-hidden="true" />
              ) : (
                <Loader2 size={13} className={e.polling ? 'animate-spin motion-reduce:animate-none text-[var(--text-muted)]' : 'text-red-600'} aria-hidden="true" />
              )}
              <span className="text-[var(--text-secondary)]">
                {EDGE_LABEL[name] || name}:{' '}
                {e.applied ? 'purged' : e.polling ? 'purging…' : 'not answering (it will purge when it is back)'}
              </span>
            </li>
          ))}
        </ul>
      )}
      <ConfirmDialog
        open={confirmAll}
        onCancel={() => setConfirmAll(false)}
        onConfirm={() => {
          if (!purge.isPending) purge.mutate()
        }}
        title={`Purge all of ${selected}?`}
        message="Every cached page of this site is removed from every edge. Until the cache fills again, all requests go to your server, which can slow it down."
        confirmText={purge.isPending ? 'Purging…' : 'Purge whole site'}
        isDanger
      />
    </div>
  )
}

export default PurgeCache
