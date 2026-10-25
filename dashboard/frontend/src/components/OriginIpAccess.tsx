import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2 } from 'lucide-react'
import { addSiteIpRule, deleteSiteIpRule, getSiteIpRules, SiteIpRuleInput } from '../api/siteAccess'
import { DURATIONS, looksLikeIp } from '../lib/siteAccess'
import { BKK_LABEL, formatBkkDateTime } from '../lib/time'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { LoadingSpinner } from './ui/LoadingSpinner'

interface Props {
  originId: string
  /** Owner or Editor. Viewers get a read-only view. */
  canEdit: boolean
}

const EMPTY: SiteIpRuleInput = { ip: '', action: 'block', note: '', hours: null }

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export const OriginIpAccess: React.FC<Props> = ({ originId, canEdit }) => {
  const queryClient = useQueryClient()
  const [form, setForm] = useState<SiteIpRuleInput>(EMPTY)
  const key = ['site-ip-rules', originId]

  const { data: rules, isLoading } = useQuery({ queryKey: key, queryFn: () => getSiteIpRules(originId) })

  const addMutation = useMutation({
    mutationFn: () => addSiteIpRule(originId, { ...form, ip: form.ip.trim(), note: form.note?.trim() }),
    onSuccess: (rule) => {
      queryClient.invalidateQueries({ queryKey: key })
      setForm(EMPTY)
      toast.success(`${rule.ip} ${rule.action === 'block' ? 'blocked' : 'allowed'} on this origin`)
    },
    onError: (e) => toast.error(errText(e, 'Failed to add the IP')),
  })

  const deleteMutation = useMutation({
    mutationFn: (ruleId: number) => deleteSiteIpRule(originId, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: key })
      toast.success('Removed')
    },
    onError: (e) => toast.error(errText(e, 'Failed to remove the IP')),
  })

  const ipOk = looksLikeIp(form.ip)
  const inputClass = 'w-full dash-input font-mono'
  const labelClass = 'text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block uppercase'

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">IP Access</h2>
        <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
          Block or always allow an IP address or range on this origin's domains only. Blocked visitors get 403 at
          the edge. Allowed visitors skip the WAF checks for this origin, so allow only addresses you trust. The
          platform's own block list still applies on top.
        </p>
      </div>

      {canEdit && (
        <form
          className="dash-card p-5 grid grid-cols-1 md:grid-cols-[2fr_1fr_1fr_2fr_auto] gap-3 items-end text-[12px]"
          onSubmit={(e) => {
            e.preventDefault()
            if (ipOk) addMutation.mutate()
          }}
        >
          <div>
            <label className={labelClass}>IP or CIDR</label>
            <input
              className={inputClass}
              placeholder="198.51.100.7 or 192.0.2.0/24"
              value={form.ip}
              onChange={(e) => setForm((f) => ({ ...f, ip: e.target.value }))}
            />
          </div>
          <div>
            <label className={labelClass}>Action</label>
            <select
              className={inputClass}
              value={form.action}
              onChange={(e) => setForm((f) => ({ ...f, action: e.target.value as SiteIpRuleInput['action'] }))}
            >
              <option value="block">Block</option>
              <option value="allow">Allow</option>
            </select>
          </div>
          <div>
            <label className={labelClass}>Duration</label>
            <select
              className={inputClass}
              value={form.hours ?? ''}
              onChange={(e) => setForm((f) => ({ ...f, hours: e.target.value ? Number(e.target.value) : null }))}
            >
              {DURATIONS.map((d) => (
                <option key={d.label} value={d.hours ?? ''}>
                  {d.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className={labelClass}>Note</label>
            <input
              className={inputClass}
              maxLength={200}
              placeholder="optional"
              value={form.note}
              onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))}
            />
          </div>
          <Button type="submit" disabled={!ipOk} isLoading={addMutation.isPending}>
            Add
          </Button>
        </form>
      )}

      {isLoading ? (
        <LoadingSpinner />
      ) : (
        <div className="dash-card overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>IP / Range</th>
                <th>Action</th>
                <th>Note</th>
                <th>Expires ({BKK_LABEL})</th>
                <th>Added by</th>
                {canEdit && <th></th>}
              </tr>
            </thead>
            <tbody>
              {!rules || rules.length === 0 ? (
                <tr>
                  <td colSpan={canEdit ? 6 : 5} className="py-6 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    No IPs listed for this origin.
                  </td>
                </tr>
              ) : (
                rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="font-mono font-bold">{rule.ip}</td>
                    <td>
                      <Badge color={rule.action === 'block' ? 'danger' : 'success'}>
                        {rule.action === 'block' ? 'Block' : 'Allow'}
                      </Badge>
                    </td>
                    <td className="text-[12px] text-[var(--text-secondary)]">{rule.note || '—'}</td>
                    <td className="font-mono text-[11.5px]">
                      {rule.expires_at ? formatBkkDateTime(rule.expires_at) : 'Never'}
                    </td>
                    <td className="font-mono text-[11.5px] text-[var(--text-muted)]">{rule.created_by || '—'}</td>
                    {canEdit && (
                      <td className="text-right">
                        <button
                          onClick={() => deleteMutation.mutate(rule.id)}
                          disabled={deleteMutation.isPending}
                          className="text-red-500 hover:text-red-400 cursor-pointer"
                          aria-label={`Remove ${rule.ip}`}
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
