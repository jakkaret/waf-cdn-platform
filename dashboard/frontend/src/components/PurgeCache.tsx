import React, { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2, CheckCircle2, Loader2 } from 'lucide-react'
import { Button } from './ui/Button'
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
  const selected = domains.includes(host) ? host : domains[0] || ''

  const purge = useMutation({
    mutationFn: () => cdnApi.purgeCache(selected, path.trim() || '/*'),
    onSuccess: (res) => {
      setJobId(res.job_id)
      toast.success(`ส่งคำสั่งล้าง cache ${res.host}${res.path} ไปทุก edge แล้ว`)
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'ล้าง cache ไม่สำเร็จ'),
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
        <Trash2 size={15} className="text-amber-500" aria-hidden="true" />
        <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">Edge Cache Purge</h3>
      </div>
      <p className="m-0 text-[12px] leading-relaxed text-[var(--text-muted)]">
        ลบหน้าที่ edge เก็บ cache ไว้ ผู้เข้าชมคนถัดไปจะได้หน้าใหม่จากเซิร์ฟเวอร์ ใส่ path เดียว (<span className="font-mono">/pricing</span>),
        ขึ้นต้นด้วย (<span className="font-mono">/static/*</span>) หรือทั้งเว็บ (<span className="font-mono">/*</span>)
      </p>
      {canEdit ? (
        <form
          className="flex flex-col gap-2 sm:flex-row sm:items-center"
          onSubmit={(e) => {
            e.preventDefault()
            if (selected) purge.mutate()
          }}
        >
          <label htmlFor="purge-host" className="sr-only">โดเมน</label>
          <select id="purge-host" value={selected} onChange={(e) => setHost(e.target.value)} className={`${fieldClass} sm:w-56`}>
            {domains.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
          <label htmlFor="purge-path" className="sr-only">Path</label>
          <input id="purge-path" value={path} onChange={(e) => setPath(e.target.value)} placeholder="/*" className={`${fieldClass} flex-1 min-w-0`} />
          <Button variant="brand" size="sm" type="submit" isLoading={purge.isPending} icon={<Trash2 size={13} />}>
            Purge
          </Button>
        </form>
      ) : (
        <p className="m-0 text-[12px] text-[var(--text-muted)]">ต้องเป็น Owner หรือ Editor ของเว็บนี้จึงจะล้าง cache ได้</p>
      )}
      {jobId !== null && (
        <ul className="m-0 p-0 list-none flex flex-wrap gap-x-4 gap-y-1 font-mono text-[12px]" aria-live="polite">
          {Object.entries(status?.edges || {}).map(([name, e]) => (
            <li key={name} className="flex items-center gap-1.5">
              {e.applied ? (
                <CheckCircle2 size={13} className="text-emerald-500" aria-hidden="true" />
              ) : (
                <Loader2 size={13} className={e.polling ? 'animate-spin text-[var(--text-muted)]' : 'text-red-500'} aria-hidden="true" />
              )}
              <span className="text-[var(--text-secondary)]">
                {name} ({EDGE_LABEL[name] || name}):{' '}
                {e.applied ? 'ล้างแล้ว' : e.polling ? 'กำลังล้าง…' : 'edge ไม่ตอบ (จะล้างเมื่อกลับมา)'}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export default PurgeCache
