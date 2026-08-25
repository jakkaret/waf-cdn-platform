import React, { useState, useMemo } from 'react'
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
  Search,
  X,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react'
import { WafRule } from '../types'
import toast from 'react-hot-toast'

const PAGE_SIZE = 10

export const Rules: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()

  // State
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<Partial<WafRule> | null>(null)
  const [search, setSearch] = useState('')
  const [variableFilter, setVariableFilter] = useState('ALL')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [page, setPage] = useState(1)
  const [pageInput, setPageInput] = useState('')
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Fetch Rules
  const { data: rules = [], isLoading, isFetching, refetch } = useQuery({
    queryKey: ['waf-rules'],
    queryFn: () => rulesApi.getRules(),
    refetchInterval: 10000,
  })

  // Mutations
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
    onSuccess: (data: any) => toast.success(`Edge Sync Complete: ${data?.synced_nodes || 3} POP nodes synchronized`),
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

  const handleCopySecRule = (rule: WafRule) => {
    const rawId = String(rule.id).replace('custom-', '')
    const actionSeverity = rule.severity || 'CRITICAL'
    const status = actionSeverity === 'CRITICAL' || actionSeverity === 'HIGH' ? 403 : 200
    const secruleStr = `SecRule ${rule.variable || 'REQUEST_URI'} "${rule.operator}" "id:${rawId},phase:2,deny,status:${status},msg:'${rule.message}'"`
    navigator.clipboard.writeText(secruleStr)
    setCopiedId(rule.id)
    toast.success('Copied SecRule to clipboard')
    setTimeout(() => setCopiedId(null), 2000)
  }

  // Extract unique variables for filter dropdown
  const uniqueVariables = useMemo(() => {
    const set = new Set<string>()
    rules.forEach((r) => {
      if (r.variable) set.add(r.variable)
    })
    return Array.from(set).sort()
  }, [rules])

  // Filtered dataset
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      if (variableFilter !== 'ALL' && rule.variable !== variableFilter) {
        return false
      }
      if (severityFilter !== 'ALL' && rule.severity?.toUpperCase() !== severityFilter) {
        return false
      }
      if (search.trim()) {
        const q = search.toLowerCase().trim()
        const matchId = String(rule.id).toLowerCase().includes(q)
        const matchMsg = (rule.message || '').toLowerCase().includes(q)
        const matchOp = (rule.operator || '').toLowerCase().includes(q)
        const matchVar = (rule.variable || '').toLowerCase().includes(q)
        if (!matchId && !matchMsg && !matchOp && !matchVar) return false
      }
      return true
    })
  }, [rules, variableFilter, severityFilter, search])

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredRules.length / PAGE_SIZE))
  const paginatedRules = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE
    return filteredRules.slice(start, start + PAGE_SIZE)
  }, [filteredRules, page])

  const handlePageJump = (e: React.FormEvent) => {
    e.preventDefault()
    const target = parseInt(pageInput, 10)
    if (!isNaN(target) && target >= 1 && target <= totalPages) {
      setPage(target)
      setPageInput('')
    }
  }

  const handleClearFilters = () => {
    setSearch('')
    setVariableFilter('ALL')
    setSeverityFilter('ALL')
    setPage(1)
  }

  const isAnyFilterActive = Boolean(search.trim() || variableFilter !== 'ALL' || severityFilter !== 'ALL')

  // Helper preview for modal
  const modalSecRulePreview = useMemo(() => {
    const rawId = editingRule?.id ? String(editingRule.id).replace('custom-', '') : '10000X'
    const variable = editingRule?.variable || 'REQUEST_URI'
    let op = (editingRule?.operator || '').trim()
    if (op && !op.startsWith('@')) op = `@contains ${op}`
    if (!op) op = '@contains <pattern>'
    const sev = editingRule?.severity || 'CRITICAL'
    const status = sev === 'CRITICAL' || sev === 'HIGH' ? 403 : 200
    const msg = editingRule?.message || 'Custom rule mitigation'
    return `SecRule ${variable} "${op}" "id:${rawId},phase:2,deny,status:${status},msg:'${msg}'"`
  }, [editingRule])

  return (
    <div className="animate-fade-in pb-10">
      {/* Top Header Bar */}
      <TopBar
        title="WAF Custom Rule Policies"
        subtitle="Manage ModSecurity SecRule definitions, edge inspection logic, and custom attack signatures"
        badge={
          <Badge color="brand" dot>
            {rules.length} ACTIVE POLICIES
          </Badge>
        }
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--bg-surface)] border border-[var(--bg-border)] hover:border-[var(--bg-border-hover)] text-[12px] font-mono font-medium text-[var(--text-primary)] rounded-md hover:bg-[var(--bg-hover)] shadow-sm transition-all cursor-pointer"
              title="Refresh policies"
            >
              <RefreshCw size={13} className={isFetching ? 'animate-spin text-orange-500' : 'text-[var(--text-muted)]'} />
              <span className="hidden sm:inline">Refresh</span>
            </button>

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
                    setEditingRule({ severity: 'CRITICAL', variable: 'REQUEST_URI', id: '', operator: '', message: '' })
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

      {/* ═══ Section 1: Overview Stats Strip ═══ */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
        <div className="dash-card p-4 sm:p-5 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] block font-mono mb-1">
              Custom Edge Rules
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-[26px] font-bold font-mono text-orange-600 dark:text-orange-400 leading-none">
                {rules.length}
              </span>
              <span className="text-[11px] font-mono text-[var(--text-muted)]">Active definitions</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-orange-500/10">
            <Code size={18} className="text-orange-600 dark:text-orange-400" />
          </div>
        </div>

        <div className="dash-card p-4 sm:p-5 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] block font-mono mb-1">
              OWASP Core Rule Set
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-[26px] font-bold font-mono text-emerald-600 dark:text-emerald-400 leading-none">
                CRS v3.3.5
              </span>
              <span className="text-[11px] font-mono text-[var(--text-muted)]">Active baseline</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-emerald-500/10">
            <Shield size={18} className="text-emerald-600 dark:text-emerald-400" />
          </div>
        </div>

        <div className="dash-card p-4 sm:p-5 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] block font-mono mb-1">
              Default Mitigation Action
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-[26px] font-bold font-mono text-sky-600 dark:text-sky-400 leading-none">
                403 Forbidden
              </span>
              <span className="text-[11px] font-mono text-[var(--text-muted)]">Hot drop</span>
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg flex items-center justify-center bg-sky-500/10">
            <ShieldAlert size={18} className="text-sky-600 dark:text-sky-400" />
          </div>
        </div>
      </div>

      {/* ═══ Section 2: Rule Management Table & Filters ═══ */}
      <div className="dash-card overflow-hidden mt-7">
        {/* Filter Toolbar */}
        <div className="p-3.5 border-b border-[var(--bg-border)] bg-[var(--bg-surface)] flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5 flex-1">
            {/* Search Input */}
            <div className="relative flex-1 min-w-[220px] max-w-sm">
              <Search className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={14} />
              <input
                type="text"
                placeholder="Search by ID, variable, operator, or description..."
                className="w-full dash-input pl-8 pr-7 py-1.5 text-[12px] font-mono"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value)
                  setPage(1)
                }}
              />
              {search && (
                <button
                  onClick={() => {
                    setSearch('')
                    setPage(1)
                  }}
                  className="absolute right-2.5 top-2 text-[var(--text-muted)] hover:text-[var(--text-primary)] p-0.5 cursor-pointer"
                >
                  <X size={13} />
                </button>
              )}
            </div>

            {/* Variable Filter */}
            <select
              className="dash-input py-1.5 text-[11.5px] font-mono cursor-pointer"
              value={variableFilter}
              onChange={(e) => {
                setVariableFilter(e.target.value)
                setPage(1)
              }}
            >
              <option value="ALL">All Target Variables</option>
              <option value="REQUEST_URI">REQUEST_URI</option>
              <option value="ARGS">ARGS</option>
              <option value="REQUEST_HEADERS">REQUEST_HEADERS</option>
              <option value="REQUEST_BODY">REQUEST_BODY</option>
              <option value="REMOTE_ADDR">REMOTE_ADDR</option>
              {uniqueVariables
                .filter((v) => !['REQUEST_URI', 'ARGS', 'REQUEST_HEADERS', 'REQUEST_BODY', 'REMOTE_ADDR'].includes(v))
                .map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
            </select>

            {/* Severity Filter */}
            <select
              className="dash-input py-1.5 text-[11.5px] font-mono cursor-pointer"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value)
                setPage(1)
              }}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical (403)</option>
              <option value="HIGH">High (403)</option>
              <option value="MEDIUM">Medium (Warning)</option>
              <option value="LOW">Low (Notice)</option>
            </select>

            {/* Reset Filters */}
            {isAnyFilterActive && (
              <button
                type="button"
                onClick={handleClearFilters}
                className="px-2.5 py-1 text-[11px] font-mono text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 bg-red-50 hover:bg-red-100 dark:bg-red-500/10 rounded border border-red-200 dark:border-red-500/20 transition-colors cursor-pointer flex items-center gap-1"
              >
                <X size={11} />
                <span>Reset</span>
              </button>
            )}
          </div>

          <div className="text-[11.5px] font-mono text-[var(--text-muted)]">
            Showing{' '}
            <span className="text-[var(--text-primary)] font-semibold">
              {filteredRules.length === 0 ? 0 : (page - 1) * PAGE_SIZE + 1}
            </span>{' '}
            to{' '}
            <span className="text-[var(--text-primary)] font-semibold">
              {Math.min(page * PAGE_SIZE, filteredRules.length)}
            </span>{' '}
            of{' '}
            <span className="text-[var(--text-primary)] font-semibold">{filteredRules.length}</span> matching rules
          </div>
        </div>

        {/* Enterprise Rules Table with Vertical Column Dividers */}
        <div className="overflow-x-auto">
          <table className="dash-table border-collapse w-full">
            <thead>
              <tr className="border-b border-[var(--bg-border)]">
                <th className="w-28 border-r border-[var(--bg-border)]">Rule ID</th>
                <th className="w-36 border-r border-[var(--bg-border)]">Target Variable</th>
                <th className="border-r border-[var(--bg-border)]">Operator & Pattern</th>
                <th className="w-40 border-r border-[var(--bg-border)]">Action & Severity</th>
                <th className="border-r border-[var(--bg-border)]">Policy Description</th>
                <th className="text-right w-24">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                    Loading ModSecurity custom rule policies...
                  </td>
                </tr>
              ) : filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-14 text-center">
                    <div className="space-y-3">
                      <Code size={32} className="mx-auto text-orange-500 opacity-40" />
                      <p className="text-[13.5px] font-bold font-mono text-[var(--text-primary)] m-0">
                        No custom rules match the specified criteria
                      </p>
                      <p className="text-[12px] text-[var(--text-muted)] font-mono m-0 max-w-sm mx-auto">
                        {isAnyFilterActive
                          ? 'Try clearing the search query or changing filter parameters.'
                          : 'No custom rules have been defined yet. Click "Create Rule" above to create one.'}
                      </p>
                      {isAnyFilterActive && (
                        <button
                          onClick={handleClearFilters}
                          className="mt-2 px-3 py-1.5 bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] rounded-md text-[11.5px] font-mono cursor-pointer transition-colors"
                        >
                          Clear Filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                paginatedRules.map((rule) => {
                  const rawId = String(rule.id).replace('custom-', '')
                  const isCritical = rule.severity === 'CRITICAL'
                  const isHigh = rule.severity === 'HIGH'

                  return (
                    <tr key={rule.id} className="hover:bg-[var(--bg-hover)] transition-colors border-b border-[var(--bg-border-subtle)]">
                      {/* Rule ID Column */}
                      <td className="border-r border-[var(--bg-border-subtle)]">
                        <span className="font-mono font-bold text-[12px] text-orange-600 dark:text-orange-400">
                          #{rawId}
                        </span>
                      </td>

                      {/* Variable Column */}
                      <td className="border-r border-[var(--bg-border-subtle)]">
                        <Badge color="gray">{rule.variable || 'REQUEST_URI'}</Badge>
                      </td>

                      {/* Operator & Pattern Column */}
                      <td className="border-r border-[var(--bg-border-subtle)]">
                        <div className="flex items-center gap-2 max-w-md">
                          <span
                            className="font-mono text-[11.5px] text-[var(--text-primary)] bg-[var(--bg-primary)] px-2 py-1 rounded border border-[var(--bg-border-subtle)] truncate block flex-1"
                            title={rule.operator}
                          >
                            {rule.operator}
                          </span>
                          <button
                            onClick={() => handleCopySecRule(rule)}
                            className="p-1 text-[var(--text-muted)] hover:text-orange-500 rounded transition-colors cursor-pointer shrink-0"
                            title="Copy full SecRule syntax"
                          >
                            {copiedId === rule.id ? (
                              <Check size={13} className="text-emerald-500" />
                            ) : (
                              <Copy size={13} />
                            )}
                          </button>
                        </div>
                      </td>

                      {/* Action & Severity Column */}
                      <td className="border-r border-[var(--bg-border-subtle)]">
                        <Badge color={isCritical ? 'danger' : isHigh ? 'warning' : 'info'}>
                          {rule.severity || 'CRITICAL'} (DENY)
                        </Badge>
                      </td>

                      {/* Policy Description Column */}
                      <td className="border-r border-[var(--bg-border-subtle)]">
                        <span className="text-[12.5px] text-[var(--text-secondary)]">
                          {rule.message || '—'}
                        </span>
                      </td>

                      {/* Manage Actions Column */}
                      <td className="text-right">
                        <div className="flex items-center gap-1.5 justify-end">
                          {isAdmin ? (
                            <>
                              <button
                                onClick={() => {
                                  setEditingRule(rule)
                                  setIsModalOpen(true)
                                }}
                                className="p-1.5 text-[var(--text-muted)] hover:text-sky-600 dark:hover:text-sky-400 rounded bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] border border-[var(--bg-border)] transition-colors cursor-pointer"
                                title="Edit Rule"
                              >
                                <Edit2 size={13} />
                              </button>
                              <button
                                onClick={() => handleDelete(rule.id)}
                                className="p-1.5 text-[var(--text-muted)] hover:text-red-600 dark:hover:text-red-400 rounded bg-[var(--bg-surface-elevated)] hover:bg-red-50 dark:hover:bg-red-500/10 border border-[var(--bg-border)] transition-colors cursor-pointer"
                                title="Delete Rule"
                              >
                                <Trash2 size={13} />
                              </button>
                            </>
                          ) : (
                            <span className="text-[11px] font-mono text-[var(--text-dim)]">Read only</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="p-3.5 border-t border-[var(--bg-border)] bg-[var(--bg-surface)] flex flex-col sm:flex-row items-center justify-between gap-3 text-[12px] font-mono">
            <form onSubmit={handlePageJump} className="flex items-center gap-2 text-[var(--text-muted)]">
              <span>Page {page} of {totalPages}</span>
              <span className="text-[var(--text-dim)]">•</span>
              <span>Jump to:</span>
              <input
                type="number"
                min={1}
                max={totalPages}
                placeholder="#"
                value={pageInput}
                onChange={(e) => setPageInput(e.target.value)}
                className="w-14 dash-input py-0.5 px-2 text-center text-[12px] font-mono"
              />
              <button
                type="submit"
                disabled={!pageInput}
                className="bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] px-2 py-0.5 text-[11px] font-semibold rounded disabled:opacity-40 hover:bg-[var(--bg-hover)] text-[var(--text-primary)] cursor-pointer transition-colors"
              >
                Go
              </button>
            </form>

            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setPage(1)}
                disabled={page <= 1}
                title="First Page"
                className="p-1.5 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] disabled:opacity-30 cursor-pointer transition-colors"
              >
                <ChevronsLeft size={14} />
              </button>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="flex items-center gap-1 px-2.5 py-1 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] disabled:opacity-30 cursor-pointer transition-colors"
              >
                <ChevronLeft size={13} /> Prev
              </button>

              {Array.from({ length: totalPages }, (_, i) => i + 1)
                .filter((num) => num === 1 || num === totalPages || Math.abs(num - page) <= 1)
                .map((num, idx, arr) => {
                  const prev = arr[idx - 1]
                  return (
                    <React.Fragment key={`page-${num}`}>
                      {prev && num - prev > 1 && <span className="px-1 text-[var(--text-muted)]">…</span>}
                      <button
                        onClick={() => setPage(num)}
                        className={`min-w-[28px] h-7 text-[12px] font-mono font-semibold rounded border cursor-pointer transition-colors ${
                          page === num
                            ? 'bg-orange-500 text-white border-orange-500 shadow-sm'
                            : 'bg-[var(--bg-surface)] border-[var(--bg-border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
                        }`}
                      >
                        {num}
                      </button>
                    </React.Fragment>
                  )
                })}

              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="flex items-center gap-1 px-2.5 py-1 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] disabled:opacity-30 cursor-pointer transition-colors"
              >
                Next <ChevronRight size={13} />
              </button>
              <button
                onClick={() => setPage(totalPages)}
                disabled={page >= totalPages}
                title="Last Page"
                className="p-1.5 rounded border border-[var(--bg-border)] bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] disabled:opacity-30 cursor-pointer transition-colors"
              >
                <ChevronsRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ═══ Create / Edit Rule Modal ═══ */}
      {isModalOpen && typeof document !== 'undefined' && createPortal(
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setIsModalOpen(false)
          }}
        >
          <div
            className="dash-modal w-full max-w-xl shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="dash-card-header bg-[var(--bg-surface-elevated)]">
              <div className="flex items-center gap-2">
                <Code size={16} className="text-orange-600 dark:text-orange-400" />
                <h3 className="font-mono">
                  {editingRule?.id && rules.find((r) => r.id === editingRule.id)
                    ? `Edit Custom Rule #${String(editingRule.id).replace('custom-', '')}`
                    : 'Create Custom SecRule Policy'}
                </h3>
              </div>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] font-mono text-base cursor-pointer px-1"
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

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
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
                  Supported: <code className="text-orange-600 dark:text-orange-400">@rx &lt;regex&gt;</code>,{' '}
                  <code className="text-orange-600 dark:text-orange-400">@contains &lt;string&gt;</code>,{' '}
                  <code className="text-orange-600 dark:text-orange-400">@streq &lt;string&gt;</code>
                </p>
              </div>

              <div>
                <label className="block mb-1 font-bold text-[11px] uppercase font-mono text-[var(--text-secondary)]">
                  Policy Description / Alert Message
                </label>
                <input
                  required
                  type="text"
                  placeholder="e.g. Block SQL injection payload attempt"
                  className="w-full dash-input"
                  value={editingRule?.message || ''}
                  onChange={(e) => setEditingRule({ ...editingRule, message: e.target.value })}
                />
              </div>

              {/* Live SecRule Syntax Preview */}
              <div className="rounded-lg bg-slate-950 border border-slate-800 text-slate-200 overflow-hidden font-mono text-[11px] mt-3">
                <div className="px-3 py-1.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-slate-400 text-[10px] uppercase font-bold">
                  <span>ModSecurity SecRule Generated Preview</span>
                  <Code size={12} className="text-orange-400" />
                </div>
                <div className="p-3 overflow-x-auto text-amber-300 bg-slate-950 leading-relaxed">
                  <code>{modalSecRulePreview}</code>
                </div>
              </div>

              <div className="flex justify-end gap-2.5 pt-4 border-t border-[var(--bg-border)]">
                <Button variant="ghost" type="button" onClick={() => setIsModalOpen(false)}>
                  Cancel
                </Button>
                <Button variant="brand" type="submit" isLoading={createMutation.isPending || updateMutation.isPending}>
                  Save & Deploy Policy
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
