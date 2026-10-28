import React, { useEffect, useId, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2 } from 'lucide-react'
import { addSiteIpRule, deleteSiteIpRule, getSiteIpRules, SiteIpRuleInput } from '../api/siteAccess'
import { DURATIONS, looksLikeIp } from '../lib/siteAccess'
import { BKK_LABEL, formatBkkDateTime } from '../lib/time'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { ConfirmDialog } from './ui/ConfirmDialog'
import { LoadingSpinner } from './ui/LoadingSpinner'

interface Props {
  originId: string
  /** Owner or Editor. Viewers get a read-only view. */
  canEdit: boolean
  /** From a "Block IP" link (Alerts, dashboard, logs): fills the form, nothing is saved until confirmed. */
  prefillIp?: string | null
  prefillNote?: string | null
}

const EMPTY: SiteIpRuleInput = { ip: '', action: 'block', note: '', hours: null }

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export const OriginIpAccess: React.FC<Props> = ({ originId, canEdit, prefillIp, prefillNote }) => {
  const queryClient = useQueryClient()
  const fid = useId()
  const [form, setForm] = useState<SiteIpRuleInput>(EMPTY)
  const [confirming, setConfirming] = useState(false)
  const key = ['site-ip-rules', originId]

  // A prefill only fills the form; the person still reviews and confirms.
  useEffect(() => {
    if (prefillIp) setForm({ ...EMPTY, ip: prefillIp, note: prefillNote ?? '' })
  }, [prefillIp, prefillNote])

  const { data: rules, isLoading, isError } = useQuery({ queryKey: key, queryFn: () => getSiteIpRules(originId) })

  const addMutation = useMutation({
    mutationFn: () => addSiteIpRule(originId, { ...form, ip: form.ip.trim(), note: form.note?.trim() }),
    onSuccess: (rule) => {
      queryClient.invalidateQueries({ queryKey: key })
      setForm(EMPTY)
      toast.success(`${rule.ip} ${rule.action === 'block' ? 'blocked' : 'allowed'} on this origin`)
    },
    onError: (e) => toast.error(errText(e, 'Could not add the IP. Nothing was changed.')),
    onSettled: () => setConfirming(false),
  })

  const deleteMutation = useMutation({
    mutationFn: (ruleId: number) => deleteSiteIpRule(originId, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: key })
      toast.success('Removed')
    },
    onError: (e) => toast.error(errText(e, 'Could not remove the IP')),
  })

  const ipOk = looksLikeIp(form.ip)
  const existing = (rules ?? []).find((r) => r.ip === form.ip.trim())
  const duration = DURATIONS.find((d) => (d.hours ?? null) === (form.hours ?? null))?.label ?? 'Permanent'
  const inputClass = 'w-full dash-input font-mono'
  const labelClass = 'text-[12px] font-medium text-[var(--text-secondary)] mb-1 block'

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-[16px] font-semibold text-[var(--text-primary)] m-0">IP access</h2>
        <p className="text-[13px] text-[var(--text-muted)] m-0 mt-0.5 max-w-[80ch]">
          Block or always allow an IP address or range on this origin's domains only. Blocked visitors get 403 at
          the edge. Allowed visitors skip the WAF checks for this origin, so allow only addresses you trust. The
          platform's own block list still applies on top.
        </p>
      </div>

      {prefillIp && !canEdit && (
        <p role="note" className="m-0 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-4 py-3 text-[13px] text-[var(--text-secondary)]">
          You can view this list but not change it. Ask an Owner or Editor of this origin to block <span className="font-mono">{prefillIp}</span>.
        </p>
      )}

      {canEdit && (
        <form
          className="dash-card p-5 space-y-3 text-[12.5px]"
          onSubmit={(e) => {
            e.preventDefault()
            if (!ipOk) return
            // Blocking affects real visitors at once: review first.
            if (form.action === 'block') setConfirming(true)
            else addMutation.mutate()
          }}
        >
          {prefillIp && (
            <p className="m-0 text-[13px] text-[var(--text-secondary)]">
              Filled in from the event you were looking at. Check the details, then add the rule.
            </p>
          )}
          <div className="grid grid-cols-1 md:grid-cols-[2fr_1fr_1fr_2fr_auto] gap-3 items-end">
            <div>
              <label htmlFor={`${fid}-ip`} className={labelClass}>IP or CIDR</label>
              <input
                id={`${fid}-ip`}
                className={inputClass}
                placeholder="198.51.100.7 or 192.0.2.0/24"
                value={form.ip}
                aria-invalid={form.ip.trim() !== '' && !ipOk}
                aria-describedby={`${fid}-ip-help`}
                onChange={(e) => setForm((f) => ({ ...f, ip: e.target.value }))}
              />
            </div>
            <div>
              <label htmlFor={`${fid}-action`} className={labelClass}>Action</label>
              <select
                id={`${fid}-action`}
                className={inputClass}
                value={form.action}
                onChange={(e) => setForm((f) => ({ ...f, action: e.target.value as SiteIpRuleInput['action'] }))}
              >
                <option value="block">Block</option>
                <option value="allow">Allow</option>
              </select>
            </div>
            <div>
              <label htmlFor={`${fid}-hours`} className={labelClass}>Duration</label>
              <select
                id={`${fid}-hours`}
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
              <label htmlFor={`${fid}-note`} className={labelClass}>Note</label>
              <input
                id={`${fid}-note`}
                className={inputClass}
                maxLength={200}
                placeholder="optional"
                value={form.note}
                onChange={(e) => setForm((f) => ({ ...f, note: e.target.value }))}
              />
            </div>
            <Button type="submit" variant={form.action === 'block' ? 'brand' : 'primary'} disabled={!ipOk} isLoading={addMutation.isPending}>
              {form.action === 'block' ? 'Review block' : 'Add'}
            </Button>
          </div>
          <p id={`${fid}-ip-help`} className="m-0 text-[12px]">
            {form.ip.trim() !== '' && !ipOk ? (
              <span className="text-red-600 dark:text-red-400">Enter an IPv4 or IPv6 address, or a CIDR range.</span>
            ) : existing ? (
              <span className="text-amber-700 dark:text-amber-400">
                {existing.ip} is already on this list ({existing.action === 'block' ? 'blocked' : 'allowed'}).
              </span>
            ) : (
              <span className="text-[var(--text-muted)]">&nbsp;</span>
            )}
          </p>
        </form>
      )}

      {isLoading ? (
        <LoadingSpinner />
      ) : isError ? (
        <p className="m-0 text-[13px] text-red-600 dark:text-red-400">Could not load this origin's IP list. Reload to try again.</p>
      ) : (
        <div className="dash-card overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>IP / range</th>
                <th>Action</th>
                <th>Note</th>
                <th>Expires ({BKK_LABEL})</th>
                <th>Added by</th>
                {canEdit && <th><span className="sr-only">Remove</span></th>}
              </tr>
            </thead>
            <tbody>
              {!rules || rules.length === 0 ? (
                <tr>
                  <td colSpan={canEdit ? 6 : 5} className="py-6 text-center text-[var(--text-muted)] text-[13px]">
                    No IPs listed for this origin.
                  </td>
                </tr>
              ) : (
                rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="font-mono font-semibold">{rule.ip}</td>
                    <td>
                      <Badge color={rule.action === 'block' ? 'danger' : 'success'}>
                        {rule.action === 'block' ? 'Block' : 'Allow'}
                      </Badge>
                    </td>
                    <td className="text-[12.5px] text-[var(--text-secondary)]">{rule.note || '—'}</td>
                    <td className="font-mono text-[11.5px]">
                      {rule.expires_at ? formatBkkDateTime(rule.expires_at) : 'Never'}
                    </td>
                    <td className="text-[12px] text-[var(--text-muted)]">{rule.created_by || '—'}</td>
                    {canEdit && (
                      <td className="text-right">
                        <button
                          onClick={() => deleteMutation.mutate(rule.id)}
                          disabled={deleteMutation.isPending}
                          className="p-1 rounded text-red-600 dark:text-red-400 hover:bg-red-500/10 cursor-pointer"
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

      <ConfirmDialog
        open={confirming}
        onCancel={() => setConfirming(false)}
        onConfirm={() => {
          if (!addMutation.isPending) addMutation.mutate()
        }}
        title={`Block ${form.ip.trim()}?`}
        message={`Every request from ${form.ip.trim()} to this origin's domains will get 403 at the edge (${duration.toLowerCase()}). This applies as soon as you confirm. Check that the address is not your own, a monitoring service or a shared proxy.`}
        confirmText={addMutation.isPending ? 'Blocking…' : 'Block IP'}
        isDanger
      />
    </section>
  )
}
