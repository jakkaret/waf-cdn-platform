import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { toast } from 'react-hot-toast'
import { Trash2, RefreshCw } from 'lucide-react'
import {
  getManagedStatus,
  setManagedMode,
  updateManagedToLatest,
  getTenantRules,
  getTenantRuleOptions,
  createTenantRule,
  updateTenantRule,
  deleteTenantRule,
  TenantRule,
  TenantRuleInput,
} from '../api/wafRules'
import { Badge } from './ui/Badge'
import { Button } from './ui/Button'
import { LoadingSpinner } from './ui/LoadingSpinner'

interface Props {
  originId: string
  /** Origin Admin (creator or granted Admin). Viewers get a read-only view. */
  canEdit: boolean
}

const EMPTY_RULE: TenantRuleInput = {
  variable: 'REQUEST_URI',
  operator: '@contains ',
  message: '',
  action: 'BLOCK',
  severity: 'HIGH',
  deception_template: 'auto',
  enabled: true,
}

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export const OriginWafRules: React.FC<Props> = ({ originId, canEdit }) => {
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<number | null>(null)
  const [form, setForm] = useState<TenantRuleInput>(EMPTY_RULE)

  const managedKey = ['managed-rules', originId]
  const rulesKey = ['tenant-rules', originId]

  const { data: managed, isLoading: managedLoading } = useQuery({
    queryKey: managedKey,
    queryFn: async () => (await getManagedStatus(originId)).data,
  })
  const { data: options } = useQuery({
    queryKey: ['tenant-rule-options', originId],
    queryFn: async () => (await getTenantRuleOptions(originId)).data,
  })
  const { data: rules, isLoading: rulesLoading } = useQuery({
    queryKey: rulesKey,
    queryFn: async () => (await getTenantRules(originId)).data.rules,
  })

  const modeMutation = useMutation({
    mutationFn: (mode: 'auto' | 'manual') => setManagedMode(originId, mode, managed?.current_version),
    onSuccess: (res) => {
      queryClient.setQueryData(managedKey, res.data)
      toast.success(`Managed rules set to ${res.data.mode}`)
    },
    onError: (e) => toast.error(errText(e, 'Failed to change mode')),
  })

  const updateMutation = useMutation({
    mutationFn: () => updateManagedToLatest(originId),
    onSuccess: (res) => {
      queryClient.setQueryData(managedKey, res.data)
      toast.success(`Updated to managed ruleset v${res.data.current_version}`)
    },
    onError: (e) => toast.error(errText(e, 'Update failed')),
  })

  const closeForm = () => {
    setShowForm(false)
    setEditingId(null)
    setForm(EMPTY_RULE)
  }

  const saveMutation = useMutation({
    mutationFn: () =>
      editingId === null ? createTenantRule(originId, form) : updateTenantRule(originId, editingId, form),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: rulesKey })
      toast.success(editingId === null ? 'Rule created' : 'Rule updated')
      closeForm()
    },
    onError: (e) => toast.error(errText(e, 'Failed to save rule')),
  })

  const deleteMutation = useMutation({
    mutationFn: (ruleId: number) => deleteTenantRule(originId, ruleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: rulesKey })
      toast.success('Rule deleted')
    },
    onError: (e) => toast.error(errText(e, 'Failed to delete rule')),
  })

  const toggleMutation = useMutation({
    mutationFn: (rule: TenantRule) =>
      updateTenantRule(originId, rule.id, {
        variable: rule.variable,
        operator: rule.operator,
        message: rule.message,
        action: rule.action,
        severity: rule.severity,
        deception_template: rule.deception_template,
        enabled: !rule.enabled,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: rulesKey }),
    onError: (e) => toast.error(errText(e, 'Failed to update rule')),
  })

  const startEdit = (rule: TenantRule) => {
    setEditingId(rule.id)
    setForm({
      variable: rule.variable,
      operator: rule.operator,
      message: rule.message,
      action: rule.action,
      severity: rule.severity,
      deception_template: rule.deception_template,
      enabled: rule.enabled,
    })
    setShowForm(true)
  }

  const [operatorName, ...operatorValue] = form.operator.split(' ')
  const setOperatorName = (name: string) => setForm((f) => ({ ...f, operator: `${name} ${operatorValue.join(' ')}` }))
  const setOperatorValue = (value: string) => setForm((f) => ({ ...f, operator: `${operatorName} ${value}` }))

  const inputClass = 'w-full dash-input font-mono'
  const labelClass = 'text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block uppercase'

  return (
    <div className="space-y-6">
      {/* ── Managed ruleset ─────────────────────────────────────────── */}
      <section className="space-y-3">
        <div>
          <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">Managed Rules</h2>
          <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
            Rules maintained centrally for every origin (known CVEs and exploit patterns). Nobody can edit them;
            the platform publishes new versions over time.
          </p>
        </div>

        {managedLoading || !managed ? (
          <LoadingSpinner />
        ) : (
          <div className="dash-card p-5 space-y-4">
            <div className="flex flex-wrap items-center gap-3 font-mono text-[12px]">
              <span className="text-[var(--text-muted)]">Running</span>
              <Badge color="brand">v{managed.current_version}</Badge>
              <span className="text-[var(--text-muted)]">Latest</span>
              <Badge color={managed.update_available ? 'warning' : 'success'}>v{managed.latest_version}</Badge>
              <Badge color="gray">{managed.mode === 'auto' ? 'Auto-update' : 'Manual updates'}</Badge>
              {canEdit && managed.update_available && (
                <Button
                  size="sm"
                  icon={<RefreshCw size={13} />}
                  onClick={() => updateMutation.mutate()}
                  isLoading={updateMutation.isPending}
                >
                  Update to v{managed.latest_version}
                </Button>
              )}
            </div>

            {canEdit && (
              <label className="flex items-center gap-2 text-[12px] font-mono text-[var(--text-primary)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={managed.mode === 'auto'}
                  disabled={modeMutation.isPending}
                  onChange={(e) => modeMutation.mutate(e.target.checked ? 'auto' : 'manual')}
                />
                Apply new versions automatically
                <span className="text-[var(--text-muted)]">
                  (turn off to stay on v{managed.current_version} until you press Update)
                </span>
              </label>
            )}

            <div className="overflow-x-auto">
              <table className="dash-table">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Added</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {managed.rules.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-[var(--text-muted)] font-mono text-[12px]">
                        No managed rules published yet.
                      </td>
                    </tr>
                  ) : (
                    managed.rules.map((r) => (
                      <tr key={r.id}>
                        <td className="font-mono font-bold text-orange-500">{r.id}</td>
                        <td className="text-[12px] text-[var(--text-secondary)]">{r.message}</td>
                        <td>
                          <Badge color={r.severity === 'CRITICAL' ? 'danger' : 'warning'}>{r.severity}</Badge>
                        </td>
                        <td className="font-mono text-[11.5px]">v{r.introduced_in}</td>
                        <td>
                          {r.retired_in !== null ? (
                            <Badge color="gray">Retired in v{r.retired_in}</Badge>
                          ) : r.active ? (
                            <Badge color="success">Active</Badge>
                          ) : (
                            <Badge color="warning">Pending update</Badge>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {managed.versions.length > 0 && (
              <details className="text-[12px] font-mono">
                <summary className="cursor-pointer text-[var(--text-muted)]">Version history</summary>
                <ul className="mt-2 space-y-1 list-none p-0">
                  {[...managed.versions].reverse().map((v) => (
                    <li key={v.version} className="text-[var(--text-secondary)]">
                      <strong>v{v.version}</strong> · {v.published_at} · +{v.added.length} / -{v.retired.length}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}
      </section>

      {/* ── This origin's own rules ─────────────────────────────────── */}
      <section className="space-y-3">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">Custom Rules</h2>
            <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
              Rules for this origin only. They apply to requests for this origin's DNS-verified domains and can
              never affect another origin's traffic.
            </p>
          </div>
          {canEdit && (
            <Button
              variant={showForm ? 'secondary' : 'brand'}
              onClick={() => (showForm ? closeForm() : setShowForm(true))}
            >
              {showForm ? 'Cancel' : '+ Add Rule'}
            </Button>
          )}
        </div>

        {canEdit && showForm && options && (
          <div className="dash-card p-5 border-l-2 border-l-orange-500 bg-orange-500/[0.02]">
            <h3 className="text-[13.5px] font-bold text-orange-500 font-mono mb-4">
              {editingId === null ? 'New rule' : `Edit rule ${editingId}`}
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px]">
              <div>
                <label className={labelClass}>Look at</label>
                <select
                  className={inputClass}
                  value={form.variable}
                  onChange={(e) => setForm((f) => ({ ...f, variable: e.target.value }))}
                >
                  {Object.entries(options.variables).map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelClass}>Match type</label>
                <select className={inputClass} value={operatorName} onChange={(e) => setOperatorName(e.target.value)}>
                  {options.operators.map((op) => (
                    <option key={op} value={op}>
                      {op}
                    </option>
                  ))}
                </select>
              </div>
              <div className="md:col-span-2">
                <label className={labelClass}>Value</label>
                <input
                  className={inputClass}
                  placeholder="e.g. /wp-admin"
                  value={operatorValue.join(' ')}
                  onChange={(e) => setOperatorValue(e.target.value)}
                />
              </div>
              <div>
                <label className={labelClass}>Action</label>
                <select
                  className={inputClass}
                  value={form.action}
                  onChange={(e) => setForm((f) => ({ ...f, action: e.target.value as TenantRuleInput['action'] }))}
                >
                  {options.actions.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelClass}>Severity</label>
                <select
                  className={inputClass}
                  value={form.severity}
                  onChange={(e) => setForm((f) => ({ ...f, severity: e.target.value as TenantRuleInput['severity'] }))}
                >
                  {options.severities.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <div className="md:col-span-2">
                <label className={labelClass}>Message (shown in logs)</label>
                <input
                  className={inputClass}
                  placeholder="e.g. Block wp-admin probes"
                  value={form.message}
                  onChange={(e) => setForm((f) => ({ ...f, message: e.target.value }))}
                />
              </div>
            </div>
            <div className="flex justify-end mt-4">
              <Button
                variant="brand"
                onClick={() => saveMutation.mutate()}
                disabled={!operatorValue.join(' ').trim() || !form.message.trim() || saveMutation.isPending}
                isLoading={saveMutation.isPending}
              >
                Save Rule
              </Button>
            </div>
          </div>
        )}

        <div className="dash-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="dash-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Condition</th>
                  <th>Action</th>
                  <th>Message</th>
                  <th>On</th>
                  {canEdit && <th className="text-right">Manage</th>}
                </tr>
              </thead>
              <tbody>
                {rulesLoading ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-[var(--text-muted)] font-mono text-[12px]">
                      Loading rules...
                    </td>
                  </tr>
                ) : !rules || rules.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-[var(--text-muted)] font-mono text-[12px]">
                      No custom rules for this origin.
                    </td>
                  </tr>
                ) : (
                  rules.map((rule) => (
                    <tr key={rule.id}>
                      <td className="font-mono font-bold text-orange-500">{rule.id}</td>
                      <td className="font-mono text-[11.5px] max-w-[260px] truncate">
                        {rule.variable} {rule.operator}
                      </td>
                      <td>
                        <Badge color={rule.action === 'BLOCK' ? 'danger' : 'warning'}>{rule.action}</Badge>
                      </td>
                      <td className="text-[12px] text-[var(--text-secondary)]">{rule.message}</td>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Rule ${rule.id} enabled`}
                          checked={rule.enabled}
                          disabled={!canEdit || toggleMutation.isPending}
                          onChange={() => toggleMutation.mutate(rule)}
                        />
                      </td>
                      {canEdit && (
                        <td className="text-right whitespace-nowrap">
                          <button
                            onClick={() => startEdit(rule)}
                            className="text-orange-500 hover:text-orange-400 font-mono text-[11px] font-semibold cursor-pointer mr-3"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => deleteMutation.mutate(rule.id)}
                            disabled={deleteMutation.isPending}
                            className="text-red-500 hover:text-red-400 cursor-pointer"
                            aria-label={`Delete rule ${rule.id}`}
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
        </div>
      </section>
    </div>
  )
}
