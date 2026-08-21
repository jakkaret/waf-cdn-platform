import React, { useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../api/rules'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { useAuthStore } from '../store/authStore'
import {
  Edit2,
  Trash2,
  Plus,
  RefreshCw,
  Shield,
  ShieldAlert,
  Code,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Search,
} from 'lucide-react'
import { WafRule } from '../types'
import toast from 'react-hot-toast'

export const Rules: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<Partial<WafRule> | null>(null)
  const [search, setSearch] = useState('')

  const { data: rules = [], isLoading, isFetching, refetch } = useQuery({
    queryKey: ['waf-rules'],
    queryFn: () => rulesApi.getRules(),
  })

  const createMutation = useMutation({
    mutationFn: (rule: Omit<WafRule, 'id'> & { id?: string }) => rulesApi.createRule(rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
      setIsModalOpen(false)
      setEditingRule(null)
      toast.success('Custom WAF rule deployed successfully')
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Failed to create rule'),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: Partial<WafRule> }) => rulesApi.updateRule(id, rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
      setIsModalOpen(false)
      setEditingRule(null)
      toast.success('WAF rule updated successfully')
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Failed to update rule'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => rulesApi.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
      toast.success('Rule removed from ModSecurity policy')
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Failed to delete rule'),
  })

  const syncMutation = useMutation({
    mutationFn: () => rulesApi.syncRules(),
    onSuccess: (data: any) => toast.success(`Edge Sync Complete: ${data.synced_nodes || 3} POP nodes synced`),
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Edge rule synchronization failed'),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingRule) return
    let op = (editingRule.operator || '').trim()
    if (op && !op.startsWith('@')) op = `@contains ${op}`
    const rule = {
      ...editingRule,
      id: String(editingRule.id || '').replace('custom-', ''),
      operator: op,
      severity: (editingRule.severity || 'CRITICAL').toUpperCase() as any,
    }
    const exists = rules.find((r) => r.id === editingRule.id || r.id === `custom-${editingRule.id}`)
    if (exists && editingRule !== exists) updateMutation.mutate({ id: String(editingRule.id), rule })
    else createMutation.mutate(rule as any)
  }

  const handleDelete = (id: string) => {
    if (window.confirm(`Are you sure you want to delete rule #${id}?`)) {
      deleteMutation.mutate(id)
    }
  }

  const filteredRules = rules.filter(
    (r) =>
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      (r.message || '').toLowerCase().includes(search.toLowerCase()) ||
      (r.operator || '').toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="WAF Custom Rule Policies"
        subtitle="Manage ModSecurity SecRule definitions and edge inspection logic"
        badge={
          <Badge color="brand" dot>
            {rules.length} ACTIVE POLICIES
          </Badge>
        }
        action={
          <div className="flex items-center gap-2">
            {isAdmin && (
              <>
                <Button
                  variant="secondary"
                  onClick={() => syncMutation.mutate()}
                  isLoading={syncMutation.isPending}
                  icon={<RefreshCw size={13} />}
                >
                  Sync to Edge Nodes
                </Button>
                <Button
                  variant="brand"
                  onClick={() => {
                    setEditingRule({ severity: 'CRITICAL', variable: 'REQUEST_URI' })
                    setIsModalOpen(true)
                  }}
                  icon={<Plus size={14} />}
                >
                  Create Rule
                </Button>
              </>
            )}
          </div>
        }
      />

      {/* Overview Stats Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="dash-card p-4 flex items-center justify-between border-l-2 border-l-orange-500">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] block font-mono">
              Custom Rules
            </span>
            <span className="text-[22px] font-bold font-mono text-[var(--text-primary)]">
              {rules.length}
            </span>
          </div>
          <Code size={20} className="text-orange-500 opacity-80" />
        </div>

        <div className="dash-card p-4 flex items-center justify-between border-l-2 border-l-emerald-500">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] block font-mono">
              OWASP Core Rule Set
            </span>
            <span className="text-[22px] font-bold font-mono text-emerald-500">CRS v3.3.5</span>
          </div>
          <Shield size={20} className="text-emerald-500 opacity-80" />
        </div>

        <div className="dash-card p-4 flex items-center justify-between border-l-2 border-l-sky-500">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] block font-mono">
              Default Action
            </span>
            <span className="text-[22px] font-bold font-mono text-sky-500">403 Forbidden</span>
          </div>
          <ShieldAlert size={20} className="text-sky-500 opacity-80" />
        </div>
      </div>

      {/* Rules Table */}
      <div className="dash-card overflow-hidden">
        <div className="p-3.5 border-b border-[var(--bg-border)] bg-[var(--bg-surface)] flex items-center justify-between gap-3">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
            <input
              type="text"
              placeholder="Search by ID, Operator pattern, or Message..."
              className="w-full dash-input pl-8 py-1.5 text-[12px] font-mono"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <span className="text-[11px] font-mono text-[var(--text-muted)]">
            {filteredRules.length} of {rules.length} rules
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Target Variable</th>
                <th>Operator & Pattern</th>
                <th>Action & Severity</th>
                <th>Policy Description</th>
                {isAdmin && <th className="text-right">Manage</th>}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    <RefreshCw size={16} className="animate-spin inline mr-2 text-orange-500" />
                    Loading ModSecurity policies...
                  </td>
                </tr>
              ) : filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    No custom rules found. Click &quot;Create Rule&quot; to define a new policy.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-[var(--bg-hover)]">
                    <td>
                      <span className="font-mono font-bold text-[12px] text-orange-500">
                        {rule.id}
                      </span>
                    </td>
                    <td>
                      <Badge color="gray">{rule.variable}</Badge>
                    </td>
                    <td>
                      <span className="font-mono text-[12px] text-[var(--text-primary)] max-w-[260px] truncate block bg-[var(--bg-primary)] px-2 py-0.5 rounded border border-[var(--bg-border-subtle)]">
                        {rule.operator}
                      </span>
                    </td>
                    <td>
                      <Badge
                        color={
                          rule.severity === 'CRITICAL'
                            ? 'danger'
                            : rule.severity === 'HIGH'
                            ? 'warning'
                            : 'info'
                        }
                      >
                        {rule.severity} (DENY)
                      </Badge>
                    </td>
                    <td>
                      <span className="text-[12px] text-[var(--text-secondary)]">
                        {rule.message}
                      </span>
                    </td>
                    {isAdmin && (
                      <td className="text-right">
                        <div className="flex items-center gap-1.5 justify-end">
                          <button
                            onClick={() => {
                              setEditingRule(rule)
                              setIsModalOpen(true)
                            }}
                            className="p-1.5 text-[var(--text-muted)] hover:text-sky-500 rounded bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] border border-[var(--bg-border)] transition-colors cursor-pointer"
                            title="Edit Rule"
                          >
                            <Edit2 size={13} />
                          </button>
                          <button
                            onClick={() => handleDelete(rule.id)}
                            className="p-1.5 text-[var(--text-muted)] hover:text-red-500 rounded bg-[var(--bg-surface-elevated)] hover:bg-red-500/10 border border-[var(--bg-border)] transition-colors cursor-pointer"
                            title="Delete Rule"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create / Edit Rule Modal */}
      {isModalOpen && typeof document !== 'undefined' && createPortal(
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setIsModalOpen(false)
          }}
        >
          <div
            className="dash-modal w-full max-w-lg shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="dash-card-header bg-[var(--bg-surface-elevated)]">
              <div className="flex items-center gap-2">
                <Code size={16} className="text-orange-500" />
                <h3 className="font-mono">
                  {editingRule?.id && rules.find((r) => r.id === editingRule.id)
                    ? `Edit Rule #${editingRule.id}`
                    : 'Create Custom SecRule'}
                </h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] font-mono text-base cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-5 space-y-4 text-[12.5px]">
              <div>
                <label className="block mb-1 font-bold text-[11px] uppercase font-mono text-[var(--text-secondary)]">
                  Rule ID (Numeric e.g. 100007)
                </label>
                <input
                  required
                  type="text"
                  placeholder="e.g. 100007"
                  className="w-full dash-input font-mono"
                  value={editingRule?.id || ''}
                  onChange={(e) => setEditingRule({ ...editingRule, id: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block mb-1 font-bold text-[11px] uppercase font-mono text-[var(--text-secondary)]">
                    Target Variable
                  </label>
                  <select
                    className="w-full dash-input font-mono cursor-pointer"
                    value={editingRule?.variable || 'REQUEST_URI'}
                    onChange={(e) => setEditingRule({ ...editingRule, variable: e.target.value as any })}
                  >
                    <option value="REQUEST_URI">REQUEST_URI</option>
                    <option value="ARGS">ARGS</option>
                    <option value="REQUEST_HEADERS">REQUEST_HEADERS</option>
                    <option value="REQUEST_BODY">REQUEST_BODY</option>
                    <option value="REMOTE_ADDR">REMOTE_ADDR</option>
                  </select>
                </div>

                <div>
                  <label className="block mb-1 font-bold text-[11px] uppercase font-mono text-[var(--text-secondary)]">
                    Action Severity
                  </label>
                  <select
                    className="w-full dash-input font-mono cursor-pointer"
                    value={editingRule?.severity || 'CRITICAL'}
                    onChange={(e) => setEditingRule({ ...editingRule, severity: e.target.value as any })}
                  >
                    <option value="CRITICAL">CRITICAL (403 Deny)</option>
                    <option value="HIGH">HIGH (403 Deny)</option>
                    <option value="MEDIUM">MEDIUM (Warning)</option>
                    <option value="LOW">LOW (Notice)</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block mb-1 font-bold text-[11px] uppercase font-mono text-[var(--text-secondary)]">
                  Operator & Pattern
                </label>
                <input
                  required
                  type="text"
                  placeholder="@rx (union.*select) or @contains badkeyword"
                  className="w-full dash-input font-mono"
                  value={editingRule?.operator || ''}
                  onChange={(e) => setEditingRule({ ...editingRule, operator: e.target.value })}
                />
                <p className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
                  Supported: <code className="text-orange-500">@rx &lt;regex&gt;</code>,{' '}
                  <code className="text-orange-500">@contains &lt;string&gt;</code>,{' '}
                  <code className="text-orange-500">@streq &lt;string&gt;</code>
                </p>
              </div>

              <div>
                <label className="block mb-1 font-bold text-[11px] uppercase font-mono text-[var(--text-secondary)]">
                  Policy Description / Alert Message
                </label>
                <input
                  required
                  type="text"
                  placeholder="Block unauthorized payload pattern"
                  className="w-full dash-input"
                  value={editingRule?.message || ''}
                  onChange={(e) => setEditingRule({ ...editingRule, message: e.target.value })}
                />
              </div>

              <div className="flex justify-end gap-2.5 pt-4 border-t border-[var(--bg-border)]">
                <Button variant="ghost" type="button" onClick={() => setIsModalOpen(false)}>
                  Cancel
                </Button>
                <Button variant="brand" type="submit" isLoading={createMutation.isPending || updateMutation.isPending}>
                  Save Policy
                </Button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}

export default Rules
