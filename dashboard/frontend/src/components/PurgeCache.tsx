import React, { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2, CheckCircle2, Loader2 } from 'lucide-react'
import { Button } from './ui/Button'
import { ConfirmDialog } from './ui/ConfirmDialog'
import { cdnApi, PurgeEdgeStatus } from '../api/cdn'
import { useT } from '../i18n'

// Edge cache purge for one site. The dashboard queues the job; every edge
// pulls it from control-api within a few seconds and deletes its own cached
// copies (services/cdn_purge.py, cdn/edge/entrypoint.d/99-rulesync.sh). The
// per-edge ticks below come from the edges' own acknowledgements.

const fieldClass = 'dash-input h-9 font-mono text-[12.5px]'
const EDGE_LABEL: Record<string, { en: string; th: string }> = {
  'edge-th': { en: 'Thailand', th: 'ไทย' },
  'edge-asia': { en: 'Hong Kong', th: 'ฮ่องกง' },
}

interface Props {
  domains: string[]
  canEdit: boolean
}

export const PurgeCache: React.FC<Props> = ({ domains, canEdit }) => {
  const [host, setHost] = useState(domains[0] || '')
  const [path, setPath] = useState('/*')
  const [jobId, setJobId] = useState<number | null>(null)
  const [confirmAll, setConfirmAll] = useState(false)
  const { t, lang } = useT()
  const selected = domains.includes(host) ? host : domains[0] || ''
  const targetPath = path.trim() || '/*'
  const wholeSite = targetPath === '/*' || targetPath === '/'

  const purge = useMutation({
    mutationFn: () => cdnApi.purgeCache(selected, targetPath),
    onSuccess: (res) => {
      setJobId(res.job_id)
      toast.success(t(`Purge of ${res.host}${res.path} sent to every edge`, `ส่งคำสั่งล้าง cache ${res.host}${res.path} ไปทุก edge แล้ว`))
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Could not purge the cache. Nothing was removed.', 'ล้าง cache ไม่สำเร็จ ยังไม่มีอะไรถูกลบ')),
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
        <h3 className="text-[14px] font-semibold text-[var(--text-primary)] m-0">{t('Purge cache', 'ล้าง cache')}</h3>
      </div>
      <p className="m-0 text-[13px] leading-relaxed text-[var(--text-muted)]">
        {t(
          'Removes the copies the edges keep, so the next visitor gets a fresh page from your server. Enter one path',
          'ลบสำเนาที่ edge เก็บไว้ ผู้เข้าชมคนถัดไปจะได้หน้าใหม่จากเซิร์ฟเวอร์ของคุณ ใส่ path เดียว',
        )}{' '}
        (<span className="font-mono">/pricing</span>), {t('a prefix', 'prefix')} (<span className="font-mono">/static/*</span>){' '}
        {t('or the whole site', 'หรือทั้งเว็บ')} (<span className="font-mono">/*</span>).
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
          <label htmlFor="purge-host" className="sr-only">{t('Domain', 'โดเมน')}</label>
          <select id="purge-host" value={selected} onChange={(e) => setHost(e.target.value)} className={`${fieldClass} sm:w-56`}>
            {domains.map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
          <label htmlFor="purge-path" className="sr-only">Path</label>
          <input id="purge-path" value={path} onChange={(e) => setPath(e.target.value)} placeholder="/*" className={`${fieldClass} flex-1 min-w-0`} />
          <Button variant="brand" size="md" type="submit" isLoading={purge.isPending} icon={<Trash2 size={13} />}>
            {t('Purge', 'ล้าง cache')}
          </Button>
        </form>
      ) : (
        <p className="m-0 text-[13px] text-[var(--text-muted)]">{t('Only an Owner or Editor of this site can purge its cache.', 'เฉพาะ Owner หรือ Editor ของเว็บนี้ที่ล้าง cache ได้')}</p>
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
                {EDGE_LABEL[name]?.[lang] || name}:{' '}
                {e.applied
                  ? t('purged', 'ล้างแล้ว')
                  : e.polling
                    ? t('purging…', 'กำลังล้าง…')
                    : t('not answering (it will purge when it is back)', 'ไม่ตอบสนอง (จะล้างเมื่อกลับมาออนไลน์)')}
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
        title={t(`Purge all of ${selected}?`, `ล้าง cache ทั้งหมดของ ${selected}?`)}
        message={t(
          'Every cached page of this site is removed from every edge. Until the cache fills again, all requests go to your server, which can slow it down.',
          'ทุกหน้าที่ cache ไว้ของเว็บนี้จะถูกลบจากทุก edge ระหว่างที่ cache ยังไม่เต็ม ทุก request จะวิ่งไปที่เซิร์ฟเวอร์ของคุณ ซึ่งอาจทำให้ช้าลง',
        )}
        confirmText={purge.isPending ? t('Purging…', 'กำลังล้าง…') : t('Purge whole site', 'ล้างทั้งเว็บ')}
        isDanger
      />
    </div>
  )
}

export default PurgeCache
