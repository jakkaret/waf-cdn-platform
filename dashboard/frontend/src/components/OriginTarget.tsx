import React, { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Pencil } from 'lucide-react'
import { Button } from './ui/Button'
import { updateOrigin } from '../api/origins'
import { Origin } from '../types'
import { formatBkkDateTime } from '../lib/time'
import { describeOriginAdjusted } from '../lib/connectProgress'
import { useT } from '../i18n'

// "Upstream Target Info" on the origin page. A direct connection can change
// the server it proxies to (protocol, IP, port) here; before this the only way
// to fix a wrong protocol was to delete the site and connect it again. The
// backend refuses non-public addresses and moves a server that forces HTTPS
// from http:80 to https:443 (see site_connect.direct_target).

const fieldClass = 'w-full dash-input h-9 font-mono text-[13px] tabular-nums'
const labelClass = 'block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1'

interface Props {
  originId: string
  origin: Origin
  canEdit: boolean
}

export const OriginTarget: React.FC<Props> = ({ originId, origin, canEdit }) => {
  const queryClient = useQueryClient()
  const { t, lang } = useT()
  const isDirect = origin.connection_mode === 'direct'
  const scheme = origin.origin_scheme || 'http'
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState({ scheme, ip: origin.ip, port: origin.port })

  const startEdit = () => {
    setForm({ scheme, ip: origin.ip, port: origin.port })
    setEditing(true)
  }

  const save = useMutation({
    mutationFn: () => updateOrigin(originId, { origin_scheme: form.scheme, ip: form.ip.trim(), port: form.port }),
    onSuccess: (res) => {
      const note = describeOriginAdjusted(res.data.origin_adjusted, lang)
      if (note) toast.success(note, { duration: 8000 })
      else toast.success(t('Upstream server saved — the WAF uses it within a few seconds', 'บันทึกเซิร์ฟเวอร์ปลายทางแล้ว — WAF จะใช้ค่าใหม่ภายในไม่กี่วินาที'))
      queryClient.invalidateQueries({ queryKey: ['origin', originId] })
      queryClient.invalidateQueries({ queryKey: ['origin-progress', originId] })
      setEditing(false)
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Could not save', 'บันทึกไม่สำเร็จ')),
  })

  const row = (label: string, value: React.ReactNode, last = false) => (
    <div className={`flex justify-between gap-3 py-1.5 ${last ? '' : 'border-b border-[var(--bg-border-subtle)]'}`}>
      <span className="text-[var(--text-muted)]">{label}</span>
      <span className="min-w-0 truncate text-right">{value}</span>
    </div>
  )

  const valid = form.ip.trim().length > 0 && form.port >= 1 && form.port <= 65535

  return (
    <div className="dash-card p-5 space-y-4">
      <div className="flex items-center justify-between gap-3 pb-3 border-b border-[var(--bg-border-subtle)]">
        <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">{t('Upstream target', 'เซิร์ฟเวอร์ปลายทาง')}</h3>
        {isDirect && canEdit && !editing && (
          <Button variant="secondary" size="sm" type="button" onClick={startEdit} icon={<Pencil size={13} />}>
            {t('Edit', 'แก้ไข')}
          </Button>
        )}
      </div>

      {editing ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault()
            if (valid) save.mutate()
          }}
        >
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-[6.5rem_1fr_5.5rem]">
            <div>
              <label htmlFor="target-scheme" className={labelClass}>Protocol</label>
              <select
                id="target-scheme"
                value={form.scheme}
                onChange={(e) => {
                  const next = e.target.value as 'http' | 'https'
                  // Follow the standard port when it was the other one.
                  const port = next === 'https' && form.port === 80 ? 443 : next === 'http' && form.port === 443 ? 80 : form.port
                  setForm({ ...form, scheme: next, port })
                }}
                className={fieldClass}
              >
                <option value="https">https</option>
                <option value="http">http</option>
              </select>
            </div>
            <div className="col-span-2 row-start-2 sm:col-span-1 sm:row-start-auto">
              <label htmlFor="target-ip" className={labelClass}>{t('Server IP', 'IP ของเซิร์ฟเวอร์')}</label>
              <input id="target-ip" value={form.ip} onChange={(e) => setForm({ ...form, ip: e.target.value })} className={fieldClass} />
            </div>
            <div>
              <label htmlFor="target-port" className={labelClass}>Port</label>
              <input
                id="target-port"
                type="number"
                min={1}
                max={65535}
                value={form.port}
                onChange={(e) => setForm({ ...form, port: parseInt(e.target.value, 10) || 0 })}
                className={fieldClass}
              />
            </div>
          </div>
          <p className="m-0 text-[12px] leading-relaxed text-[var(--text-muted)]">
            {t('The WAF sends traffic to', 'WAF จะส่ง traffic ไปที่')}{' '}
            <span className="font-mono">{form.scheme}://{form.ip || '…'}:{form.port}</span>{' '}
            {t(
              'If the server forces HTTPS (e.g. Vercel, Netlify), use https:443, otherwise the site redirects in a loop.',
              'ถ้าเซิร์ฟเวอร์บังคับ HTTPS (เช่น Vercel, Netlify) ให้ใช้ https:443 ไม่งั้นเว็บจะ redirect วนไม่จบ',
            )}
          </p>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" size="sm" type="button" onClick={() => setEditing(false)}>
              {t('Cancel', 'ยกเลิก')}
            </Button>
            <Button variant="brand" size="sm" type="submit" disabled={!valid} isLoading={save.isPending}>
              {t('Save', 'บันทึก')}
            </Button>
          </div>
        </form>
      ) : (
        <div className="space-y-3 font-mono text-[12px]">
          {row(t('Server label', 'ชื่อเซิร์ฟเวอร์'), <span className="font-bold text-[var(--text-primary)]">{origin.label}</span>)}
          {isDirect && row('Protocol', <span className="text-[var(--text-primary)]">{scheme}</span>)}
          {row(t('Upstream IP', 'IP ปลายทาง'), <span className="text-orange-500 font-bold">{origin.ip}</span>)}
          {row(t('Proxy port', 'Port ปลายทาง'), <span className="text-[var(--text-primary)]">{origin.port}</span>)}
          {row(t('Registered', 'วันที่เพิ่ม'), <span className="text-[var(--text-secondary)]">{formatBkkDateTime(origin.created_at)}</span>, true)}
        </div>
      )}
    </div>
  )
}

export default OriginTarget
