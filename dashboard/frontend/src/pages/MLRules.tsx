import React, { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { mlRulesApi } from '../api/mlRules'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import { MLPendingRule } from '../types'
import {
  Sparkles,
  Check,
  X,
  Clock,
  AlertTriangle,
  Code,
  ShieldCheck,
  RefreshCw,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Copy,
  Layers,
  CheckSquare,
  Square,
  MinusSquare,
  ChevronDown,
  ChevronUp,
  Maximize2,
  Minimize2,
  Shield,
  Zap,
} from 'lucide-react'

const PAGE_SIZE = 10

export const MLRules: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()

  // Tab & Filters state
  const [activeTab, setActiveTab] = useState<'all' | 'pending' | 'approved' | 'rejected'>('all')
  const [search, setSearch] = useState('')
  const [attackTypeFilter, setAttackTypeFilter] = useState('ALL')
  const [variableFilter, setVariableFilter] = useState('ALL')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [page, setPage] = useState(1)
  const [pageInput, setPageInput] = useState('')

  // Expand / Collapse state for rule details
  const [expandedRuleIds, setExpandedRuleIds] = useState<string[]>([])

  // Single Rejection & action states
  const [rejectReason, setRejectReason] = useState('')
  const [rejectingId, setRejectingId] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  // Bulk Selection & Rejection state
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>([])
  const [isBulkRejectModalOpen, setIsBulkRejectModalOpen] = useState(false)
  const [bulkRejectReason, setBulkRejectReason] = useState('')
  const [isBulkProcessing, setIsBulkProcessing] = useState(false)

  // Fetch all rules
  const { data: allRules = [], isLoading, isFetching, refetch } = useQuery({
    queryKey: ['ml-rules'],
    queryFn: () => mlRulesApi.listRules(),
    refetchInterval: 10000,
  })

  // Single rule mutations
  const approveMutation = useMutation({
    mutationFn: (id: string) => mlRulesApi.approveRule(id),
    onSuccess: () => {
      toast.success('ML Rule approved and deployed to ModSecurity!')
      queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to approve rule'),
  })

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => mlRulesApi.rejectRule(id, reason),
    onSuccess: () => {
      toast.success('Rule marked as rejected')
      setRejectingId(null)
      setRejectReason('')
      queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to reject rule'),
  })

  const handleApprove = (id: string) => {
    if (!isAdmin) {
      toast.error('Administrator privileges required to approve and deploy rules')
      return
    }
    approveMutation.mutate(id)
  }

  const handleReject = (id: string) => {
    if (!isAdmin) {
      toast.error('Administrator privileges required to reject rules')
      return
    }
    rejectMutation.mutate({ id, reason: rejectReason })
  }

  const handleCopySecRule = (rule: MLPendingRule) => {
    const text = rule.secrule_template.replace(
      '{RULE_ID}',
      rule.deployed_rule_id ? String(rule.deployed_rule_id) : 'PENDING_ID'
    )
    navigator.clipboard.writeText(text)
    setCopiedId(rule.rule_id)
    toast.success('Copied SecRule to clipboard')
    setTimeout(() => setCopiedId(null), 2000)
  }

  // Compute summary stats
  const stats = useMemo(() => {
    const total = allRules.length
    const pending = allRules.filter((r) => r.status === 'pending').length
    const approved = allRules.filter((r) => r.status === 'approved').length
    const rejected = allRules.filter((r) => r.status === 'rejected').length
    return { total, pending, approved, rejected }
  }, [allRules])

  // Extract unique filter options from dataset
  const attackTypes = useMemo(() => {
    const set = new Set<string>()
    allRules.forEach((r) => {
      if (r.attack_type) set.add(r.attack_type)
    })
    return Array.from(set).sort()
  }, [allRules])

  const variables = useMemo(() => {
    const set = new Set<string>()
    allRules.forEach((r) => {
      if (r.variable) set.add(r.variable)
    })
    return Array.from(set).sort()
  }, [allRules])

  const methods = useMemo(() => {
    const set = new Set<string>()
    allRules.forEach((r) => {
      if (r.source_method) set.add(r.source_method.toUpperCase())
    })
    return Array.from(set).sort()
  }, [allRules])

  // Filtered dataset
  const filteredRules = useMemo(() => {
    return allRules.filter((rule) => {
      if (activeTab !== 'all' && rule.status !== activeTab) {
        return false
      }
      if (attackTypeFilter !== 'ALL' && rule.attack_type !== attackTypeFilter) {
        return false
      }
      if (variableFilter !== 'ALL' && rule.variable !== variableFilter) {
        return false
      }
      if (methodFilter !== 'ALL' && rule.source_method?.toUpperCase() !== methodFilter) {
        return false
      }
      if (search.trim()) {
        const query = search.toLowerCase().trim()
        const matchId = rule.rule_id?.toLowerCase().includes(query)
        const matchAttack = rule.attack_type?.toLowerCase().includes(query)
        const matchPattern = rule.pattern?.toLowerCase().includes(query)
        const matchVariable = rule.variable?.toLowerCase().includes(query)
        const matchUrl = rule.source_url?.toLowerCase().includes(query)
        const matchMethod = rule.source_method?.toLowerCase().includes(query)
        const matchDeployed = rule.deployed_rule_id ? String(rule.deployed_rule_id).includes(query) : false
        const matchReason = rule.reject_reason?.toLowerCase().includes(query)

        if (!matchId && !matchAttack && !matchPattern && !matchVariable && !matchUrl && !matchMethod && !matchDeployed && !matchReason) {
          return false
        }
      }
      return true
    })
  }, [allRules, activeTab, attackTypeFilter, variableFilter, methodFilter, search])

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(filteredRules.length / PAGE_SIZE))
  const paginatedRules = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE
    return filteredRules.slice(start, start + PAGE_SIZE)
  }, [filteredRules, page])

  // Pending rules in current view
  const pendingOnCurrentPage = useMemo(
    () => paginatedRules.filter((r) => r.status === 'pending'),
    [paginatedRules]
  )
  const allPendingFiltered = useMemo(
    () => filteredRules.filter((r) => r.status === 'pending'),
    [filteredRules]
  )

  const isAllCurrentPagePendingSelected =
    pendingOnCurrentPage.length > 0 &&
    pendingOnCurrentPage.every((r) => selectedRuleIds.includes(r.rule_id))

  const isSomeCurrentPagePendingSelected =
    pendingOnCurrentPage.some((r) => selectedRuleIds.includes(r.rule_id)) &&
    !isAllCurrentPagePendingSelected

  // Toggle card expansion
  const toggleRuleExpansion = (ruleId: string) => {
    setExpandedRuleIds((prev) =>
      prev.includes(ruleId) ? prev.filter((id) => id !== ruleId) : [...prev, ruleId]
    )
  }

  const handleExpandAllOnPage = () => {
    const pageIds = paginatedRules.map((r) => r.rule_id)
    setExpandedRuleIds((prev) => Array.from(new Set([...prev, ...pageIds])))
  }

  const handleCollapseAllOnPage = () => {
    const pageIds = new Set(paginatedRules.map((r) => r.rule_id))
    setExpandedRuleIds((prev) => prev.filter((id) => !pageIds.has(id)))
  }

  const isAllCurrentPageExpanded =
    paginatedRules.length > 0 && paginatedRules.every((r) => expandedRuleIds.includes(r.rule_id))

  // Bulk Selection Handlers
  const handleToggleSelectAllCurrentPage = () => {
    if (isAllCurrentPagePendingSelected) {
      const pagePendingIds = new Set(pendingOnCurrentPage.map((r) => r.rule_id))
      setSelectedRuleIds((prev) => prev.filter((id) => !pagePendingIds.has(id)))
    } else {
      const pagePendingIds = pendingOnCurrentPage.map((r) => r.rule_id)
      setSelectedRuleIds((prev) => Array.from(new Set([...prev, ...pagePendingIds])))
    }
  }

  const handleSelectAllFilteredPending = () => {
    setSelectedRuleIds(allPendingFiltered.map((r) => r.rule_id))
    toast.success(`Selected all ${allPendingFiltered.length} matching pending rules`)
  }

  const handleDeselectAll = () => {
    setSelectedRuleIds([])
  }

  const handleToggleRuleSelection = (ruleId: string) => {
    setSelectedRuleIds((prev) =>
      prev.includes(ruleId) ? prev.filter((id) => id !== ruleId) : [...prev, ruleId]
    )
  }

  // Bulk Reject Execution
  const handleExecuteBulkReject = async () => {
    if (!isAdmin) {
      toast.error('Administrator privileges required to reject rules')
      return
    }
    if (selectedRuleIds.length === 0) return

    setIsBulkProcessing(true)
    try {
      const results = await Promise.allSettled(
        selectedRuleIds.map((id) => mlRulesApi.rejectRule(id, bulkRejectReason.trim()))
      )
      const successCount = results.filter((r) => r.status === 'fulfilled').length
      const failCount = results.filter((r) => r.status === 'rejected').length

      if (successCount > 0) {
        toast.success(`Successfully rejected ${successCount} rule(s)`)
      }
      if (failCount > 0) {
        toast.error(`Failed to reject ${failCount} rule(s)`)
      }

      setSelectedRuleIds([])
      setIsBulkRejectModalOpen(false)
      setBulkRejectReason('')
      queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
    } catch (err: any) {
      toast.error('Bulk reject action encountered an error')
    } finally {
      setIsBulkProcessing(false)
    }
  }

  // Bulk Approve Execution
  const handleExecuteBulkApprove = async () => {
    if (!isAdmin) {
      toast.error('Administrator privileges required to approve rules')
      return
    }
    if (selectedRuleIds.length === 0) return

    if (!window.confirm(`Are you sure you want to approve and hot-deploy ${selectedRuleIds.length} rule(s) to ModSecurity?`)) {
      return
    }

    setIsBulkProcessing(true)
    try {
      const results = await Promise.allSettled(
        selectedRuleIds.map((id) => mlRulesApi.approveRule(id))
      )
      const successCount = results.filter((r) => r.status === 'fulfilled').length
      const failCount = results.filter((r) => r.status === 'rejected').length

      if (successCount > 0) {
        toast.success(`Successfully approved and deployed ${successCount} rule(s) to ModSecurity!`)
      }
      if (failCount > 0) {
        toast.error(`Failed to approve ${failCount} rule(s)`)
      }

      setSelectedRuleIds([])
      queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
    } catch (err: any) {
      toast.error('Bulk approve action encountered an error')
    } finally {
      setIsBulkProcessing(false)
    }
  }

  // Reset page when filters change
  const handleTabChange = (tab: 'all' | 'pending' | 'approved' | 'rejected') => {
    setActiveTab(tab)
    setPage(1)
  }

  const handleClearFilters = () => {
    setSearch('')
    setAttackTypeFilter('ALL')
    setVariableFilter('ALL')
    setMethodFilter('ALL')
    setActiveTab('all')
    setPage(1)
  }

  const handlePageJump = (e: React.FormEvent) => {
    e.preventDefault()
    const targetPage = parseInt(pageInput, 10)
    if (!isNaN(targetPage) && targetPage >= 1 && targetPage <= totalPages) {
      setPage(targetPage)
      setPageInput('')
    }
  }

  // Generate page numbers for pagination
  const getPageNumbers = () => {
    const pages: (number | string)[] = []
    if (totalPages <= 7) {
      for (let i = 1; i <= totalPages; i++) pages.push(i)
    } else {
      pages.push(1)
      if (page > 3) pages.push('...')
      const start = Math.max(2, page - 1)
      const end = Math.min(totalPages - 1, page + 1)
      for (let i = start; i <= end; i++) pages.push(i)
      if (page < totalPages - 2) pages.push('...')
      pages.push(totalPages)
    }
    return pages
  }

  const hasSearchOrDropdownFilter = Boolean(
    search.trim() || attackTypeFilter !== 'ALL' || variableFilter !== 'ALL' || methodFilter !== 'ALL'
  )
  const isAnyFilterActive = hasSearchOrDropdownFilter || activeTab !== 'all'

  return (
    <div className="animate-fade-in pb-12">
      {/* Top Header Bar */}
      <TopBar
        title="ML Anomaly Rule Approvals"
        subtitle="Review, filter, approve, reject, and hot-deploy SecRule definitions generated by AI classifier models"
        badge={
          <Badge color="purple" dot>
            AI COPILOT
          </Badge>
        }
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="px-3 py-1.5 rounded-md bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] border border-[var(--bg-border)] text-[12px] font-mono font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
              title="Refresh anomaly queue"
            >
              <RefreshCw size={13} className={isFetching ? 'animate-spin text-violet-600 dark:text-violet-400' : ''} />
              <span>Refresh</span>
            </button>
          </div>
        }
      />

      {/* ═══ Section 1: Overview Stat Cards ═══ */}
      <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] font-mono">
              Total AI Pool
            </span>
            <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-violet-500/10">
              <Layers size={15} className="text-violet-600 dark:text-violet-400" />
            </div>
          </div>
          <span className="text-[26px] font-bold font-mono text-[var(--text-primary)] leading-none">
            {stats.total}
          </span>
          <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] text-[11px] text-[var(--text-muted)] font-mono truncate">
            Anomaly templates captured
          </div>
        </div>

        <div className="dash-card p-4 sm:p-5 flex flex-col justify-between bg-amber-50/40 dark:bg-amber-950/[0.08] border-amber-200/60 dark:border-amber-500/15">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-amber-700/80 dark:text-amber-400/80 font-mono">
              Pending Review
            </span>
            <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-amber-500/15">
              <Clock size={15} className="text-amber-600 dark:text-amber-400" />
            </div>
          </div>
          <span className="text-[26px] font-bold font-mono text-amber-600 dark:text-amber-400 leading-none">
            {stats.pending}
          </span>
          <div className="mt-3 pt-2.5 border-t border-amber-200/40 dark:border-amber-500/10 text-[11px] text-amber-700/70 dark:text-amber-400/70 font-mono truncate">
            Awaiting admin action
          </div>
        </div>

        <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] font-mono">
              Deployed to ModSec
            </span>
            <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-emerald-500/10">
              <ShieldCheck size={15} className="text-emerald-600 dark:text-emerald-400" />
            </div>
          </div>
          <span className="text-[26px] font-bold font-mono text-emerald-600 dark:text-emerald-400 leading-none">
            {stats.approved}
          </span>
          <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] text-[11px] text-[var(--text-muted)] font-mono truncate">
            Hot-deployed at edge nodes
          </div>
        </div>

        <div className="dash-card p-4 sm:p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between gap-2 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-[var(--text-muted)] font-mono">
              Rejected Rules
            </span>
            <div className="w-7 h-7 rounded-lg flex items-center justify-center bg-red-500/10">
              <X size={15} className="text-red-600 dark:text-red-400" />
            </div>
          </div>
          <span className="text-[26px] font-bold font-mono text-red-600 dark:text-red-400 leading-none">
            {stats.rejected}
          </span>
          <div className="mt-3 pt-2.5 border-t border-[var(--bg-border-subtle)] text-[11px] text-[var(--text-muted)] font-mono truncate">
            False positives dismissed
          </div>
        </div>
      </div>

      {/* ═══ Section 2: Filter Toolbar & Control Container ═══ */}
      <div className="dash-card overflow-hidden mt-7">
        <div className="p-3.5 border-b border-[var(--bg-border)] bg-[var(--bg-surface)] space-y-3">
          {/* Top Row: Status Tabs + Search Box */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            {/* Status Tabs */}
            <div className="flex flex-wrap items-center gap-1 bg-[var(--bg-primary)] p-1 rounded-lg border border-[var(--bg-border-subtle)] text-[12px] font-mono">
              <button
                onClick={() => handleTabChange('all')}
                className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                  activeTab === 'all'
                    ? 'bg-[var(--bg-surface)] text-[var(--text-primary)] shadow-sm font-semibold border border-[var(--bg-border)]'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                All ({stats.total})
              </button>
              <button
                onClick={() => handleTabChange('pending')}
                className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                  activeTab === 'pending'
                    ? 'bg-[var(--bg-surface)] text-amber-600 dark:text-amber-400 shadow-sm font-semibold border border-[var(--bg-border)]'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                Pending ({stats.pending})
              </button>
              <button
                onClick={() => handleTabChange('approved')}
                className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                  activeTab === 'approved'
                    ? 'bg-[var(--bg-surface)] text-emerald-600 dark:text-emerald-400 shadow-sm font-semibold border border-[var(--bg-border)]'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                Deployed ({stats.approved})
              </button>
              <button
                onClick={() => handleTabChange('rejected')}
                className={`px-3 py-1 rounded-md font-medium transition-colors cursor-pointer ${
                  activeTab === 'rejected'
                    ? 'bg-[var(--bg-surface)] text-red-600 dark:text-red-400 shadow-sm font-semibold border border-[var(--bg-border)]'
                    : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
              >
                Rejected ({stats.rejected})
              </button>
            </div>

            {/* Search Input */}
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-2.5 text-[var(--text-muted)] pointer-events-none" size={14} />
              <input
                type="text"
                placeholder="Search attack type, pattern, URI, variable, ID..."
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
          </div>

          {/* Bottom Row: Dropdown Filters & View Controls */}
          <div className="flex flex-wrap items-center justify-between gap-2.5 pt-1">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-[var(--text-muted)]">
                <Filter size={12} />
                <span>Filters:</span>
              </div>

              {/* Attack Type Filter */}
              <select
                className="dash-input py-1 text-[11px] font-mono cursor-pointer"
                value={attackTypeFilter}
                onChange={(e) => {
                  setAttackTypeFilter(e.target.value)
                  setPage(1)
                }}
              >
                <option value="ALL">All Attack Types</option>
                {attackTypes.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>

              {/* Variable Filter */}
              <select
                className="dash-input py-1 text-[11px] font-mono cursor-pointer"
                value={variableFilter}
                onChange={(e) => {
                  setVariableFilter(e.target.value)
                  setPage(1)
                }}
              >
                <option value="ALL">All Variables</option>
                {variables.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>

              {/* HTTP Method Filter */}
              <select
                className="dash-input py-1 text-[11px] font-mono cursor-pointer"
                value={methodFilter}
                onChange={(e) => {
                  setMethodFilter(e.target.value)
                  setPage(1)
                }}
              >
                <option value="ALL">All Methods</option>
                {methods.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>

              {/* Clear Filters Button */}
              {isAnyFilterActive && (
                <button
                  type="button"
                  onClick={handleClearFilters}
                  className="px-2 py-0.5 text-[11px] font-mono text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 bg-red-50 hover:bg-red-100 dark:bg-red-500/10 rounded border border-red-200 dark:border-red-500/20 transition-colors cursor-pointer flex items-center gap-1"
                >
                  <X size={11} />
                  <span>Reset</span>
                </button>
              )}
            </div>

            {/* Expand / Collapse All Toggle */}
            <div className="flex items-center gap-1.5 ml-auto">
              <button
                type="button"
                onClick={isAllCurrentPageExpanded ? handleCollapseAllOnPage : handleExpandAllOnPage}
                className="px-2.5 py-1 rounded bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] border border-[var(--bg-border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-[11px] font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                title={isAllCurrentPageExpanded ? 'Collapse all rule previews' : 'Expand all rule previews'}
              >
                {isAllCurrentPageExpanded ? (
                  <>
                    <Minimize2 size={12} />
                    <span>Collapse All</span>
                  </>
                ) : (
                  <>
                    <Maximize2 size={12} />
                    <span>Expand All Previews</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Results Counter & Select All Toolbar */}
        <div className="px-4 py-2.5 bg-[var(--bg-primary)] border-b border-[var(--bg-border-subtle)] flex flex-wrap items-center justify-between gap-3 text-[11.5px] font-mono text-[var(--text-muted)]">
          <div className="flex items-center gap-3 flex-wrap">
            {/* Select All Checkbox for Pending Rules */}
            {isAdmin && allPendingFiltered.length > 0 && (
              <button
                type="button"
                onClick={handleToggleSelectAllCurrentPage}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] border border-[var(--bg-border)] text-[var(--text-primary)] transition-colors cursor-pointer font-medium"
                title="Select/Deselect all pending rules on this page"
              >
                {isAllCurrentPagePendingSelected ? (
                  <CheckSquare size={14} className="text-violet-600 dark:text-violet-400" />
                ) : isSomeCurrentPagePendingSelected ? (
                  <MinusSquare size={14} className="text-violet-600 dark:text-violet-400" />
                ) : (
                  <Square size={14} className="text-[var(--text-muted)]" />
                )}
                <span>Select Page Pending ({pendingOnCurrentPage.length})</span>
              </button>
            )}

            <div>
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
              {filteredRules.length !== allRules.length && (
                <span className="ml-1 text-[var(--text-dim)]">({allRules.length} total in pool)</span>
              )}
            </div>
          </div>

          <div className="text-[11px]">
            10 rules / page • Page {page} of {totalPages}
          </div>
        </div>

        {/* Bulk Action Sticky Bar (Appears when items are selected) */}
        {selectedRuleIds.length > 0 && isAdmin && (
          <div className="p-3 bg-violet-50 dark:bg-violet-950/40 border-b border-violet-200 dark:border-violet-500/30 flex flex-wrap items-center justify-between gap-3 animate-fade-in">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-violet-100 dark:bg-violet-600/20 text-violet-700 dark:text-violet-300 font-mono text-[12px] font-bold border border-violet-200 dark:border-violet-500/30">
                <CheckSquare size={14} />
                <span>{selectedRuleIds.length} pending rule(s) selected</span>
              </span>

              {allPendingFiltered.length > selectedRuleIds.length && (
                <button
                  type="button"
                  onClick={handleSelectAllFilteredPending}
                  className="px-2.5 py-1 rounded bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-violet-700 dark:text-violet-300 border border-violet-200 dark:border-violet-500/30 text-[11.5px] font-mono underline-offset-2 hover:underline cursor-pointer"
                >
                  Select all {allPendingFiltered.length} matching pending rules
                </button>
              )}

              <button
                type="button"
                onClick={handleDeselectAll}
                className="px-2 py-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] text-[11.5px] font-mono cursor-pointer"
              >
                Deselect all
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setIsBulkRejectModalOpen(true)}
                disabled={isBulkProcessing}
                className="px-3 py-1.5 bg-red-50 hover:bg-red-100 dark:bg-red-500/15 dark:hover:bg-red-500/25 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-500/30 rounded-md text-[12px] font-mono font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
              >
                <X size={14} />
                <span>Reject Selected ({selectedRuleIds.length})</span>
              </button>

              <button
                type="button"
                onClick={handleExecuteBulkApprove}
                disabled={isBulkProcessing}
                className="px-3 py-1.5 bg-emerald-50 hover:bg-emerald-100 dark:bg-emerald-500/15 dark:hover:bg-emerald-500/25 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-500/30 rounded-md text-[12px] font-mono font-semibold flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
              >
                <Check size={14} />
                <span>Approve Selected ({selectedRuleIds.length})</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ═══ Section 3: Rules Queue List ═══ */}
      <div className="space-y-3 mt-4">
        {isLoading && (
          <div className="text-center py-16 text-[var(--text-muted)] font-mono text-[12.5px] dash-card">
            <RefreshCw size={20} className="animate-spin inline mr-2.5 text-violet-600 dark:text-violet-500" />
            Loading AI anomaly rule pool...
          </div>
        )}

        {!isLoading && filteredRules.length === 0 && (
          <div className="dash-card p-12 text-center space-y-3">
            <Sparkles size={36} className="mx-auto text-violet-500 dark:text-violet-400 opacity-40" />
            <h3 className="text-[14.5px] font-bold text-[var(--text-primary)] font-mono m-0">
              No matching ML rules found
            </h3>
            <p className="text-[12px] text-[var(--text-muted)] m-0 font-mono max-w-md mx-auto">
              {hasSearchOrDropdownFilter
                ? 'No rules match the currently applied search criteria and filter selections.'
                : activeTab === 'pending'
                ? 'All AI-suggested rules have been reviewed and approved or rejected.'
                : activeTab === 'all'
                ? 'No AI-suggested rules have been recorded yet.'
                : `There are currently no rules under the "${activeTab}" category.`}
            </p>
            {isAnyFilterActive && (
              <button
                onClick={handleClearFilters}
                className="mt-2 px-3 py-1.5 bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)] rounded-md text-[12px] font-mono cursor-pointer transition-colors"
              >
                Clear all filters
              </button>
            )}
          </div>
        )}

        {paginatedRules.map((rule) => {
          const isSelected = selectedRuleIds.includes(rule.rule_id)
          const isPending = rule.status === 'pending'
          const isExpanded = expandedRuleIds.includes(rule.rule_id)

          return (
            <div
              key={rule.rule_id}
              className={`dash-card overflow-hidden transition-all ${
                isSelected
                  ? 'border-violet-500 ring-1 ring-violet-500/50 bg-violet-50/40 dark:bg-violet-950/[0.08]'
                  : 'hover:border-[var(--bg-border-hover)]'
              }`}
            >
              {/* Status Header Bar */}
              <div
                className={`h-0.5 w-full ${
                  rule.status === 'pending'
                    ? 'bg-amber-500'
                    : rule.status === 'approved'
                    ? 'bg-emerald-500'
                    : 'bg-red-500'
                }`}
              />

              <div className="p-4 sm:p-4.5 space-y-3">
                {/* Top Row: Selection Checkbox, Attack Type, Status & Quick Actions */}
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="flex items-center gap-2.5 min-w-0">
                    {/* Checkbox for Pending Rules */}
                    {isPending && isAdmin && (
                      <button
                        type="button"
                        onClick={() => handleToggleRuleSelection(rule.rule_id)}
                        className="p-1 text-[var(--text-muted)] hover:text-violet-600 dark:hover:text-violet-400 transition-colors cursor-pointer shrink-0"
                        title={isSelected ? 'Deselect rule' : 'Select rule for bulk actions'}
                      >
                        {isSelected ? (
                          <CheckSquare size={17} className="text-violet-600 dark:text-violet-500" />
                        ) : (
                          <Square size={17} className="text-[var(--text-muted)]" />
                        )}
                      </button>
                    )}

                    <div
                      className={`w-8 h-8 rounded-md flex items-center justify-center shrink-0 ${
                        rule.status === 'pending'
                          ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400'
                          : rule.status === 'approved'
                          ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400'
                          : 'bg-red-500/10 text-red-600 dark:text-red-400'
                      }`}
                    >
                      {rule.status === 'pending' ? (
                        <Clock size={15} />
                      ) : rule.status === 'approved' ? (
                        <Check size={15} />
                      ) : (
                        <X size={15} />
                      )}
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[13.5px] font-bold text-[var(--text-primary)] font-mono flex items-center gap-1.5">
                        <Sparkles size={13} className="text-violet-600 dark:text-violet-400 shrink-0" />
                        {rule.attack_type}
                      </span>
                      <span className="text-[10.5px] font-mono px-1.5 py-0.2 rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] text-[var(--text-muted)]">
                        ID: {rule.rule_id}
                      </span>
                      <span className="text-[10.5px] text-[var(--text-dim)] font-mono hidden md:inline">
                        • {new Date(rule.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  </div>

                  {/* Badges & Expand Button */}
                  <div className="flex items-center gap-2 ml-auto">
                    {rule.status === 'pending' && <Badge color="warning" dot>PENDING</Badge>}
                    {rule.status === 'approved' && (
                      <Badge color="success" dot>
                        DEPLOYED #{rule.deployed_rule_id}
                      </Badge>
                    )}
                    {rule.status === 'rejected' && <Badge color="danger" dot>REJECTED</Badge>}

                    <button
                      type="button"
                      onClick={() => toggleRuleExpansion(rule.rule_id)}
                      className="px-2 py-1 text-[11px] font-mono text-[var(--text-secondary)] hover:text-[var(--text-primary)] bg-[var(--bg-primary)] hover:bg-[var(--bg-hover)] rounded border border-[var(--bg-border)] flex items-center gap-1 transition-colors cursor-pointer"
                      title={isExpanded ? 'Collapse SecRule code' : 'View full SecRule definition'}
                    >
                      <span>{isExpanded ? 'Hide Code' : 'SecRule'}</span>
                      {isExpanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                    </button>
                  </div>
                </div>

                {/* Middle Row: Quick Pattern & Source Summary Strip */}
                <div className="grid grid-cols-1 md:grid-cols-12 gap-2 bg-[var(--bg-primary)] p-2.5 rounded-lg border border-[var(--bg-border-subtle)] text-[11.5px] font-mono items-center">
                  <div className="md:col-span-6 flex items-center gap-2 min-w-0">
                    <span className="text-[10px] uppercase font-bold text-[var(--text-muted)] shrink-0">Pattern:</span>
                    <span className="font-bold text-violet-700 dark:text-violet-400 truncate bg-[var(--bg-surface)] px-1.5 py-0.5 rounded border border-[var(--bg-border)]" title={rule.pattern}>
                      {rule.pattern}
                    </span>
                    <span className="text-[10px] text-[var(--text-dim)] shrink-0">in {rule.variable}</span>
                  </div>

                  <div className="md:col-span-6 flex items-center gap-2 min-w-0 md:justify-end">
                    <span className="text-[10px] uppercase font-bold text-[var(--text-muted)] shrink-0">Target:</span>
                    <Badge color="gray" size="sm">{rule.source_method || 'ANY'}</Badge>
                    <span className="text-[var(--text-primary)] truncate" title={rule.source_url}>
                      {rule.source_url || '/'}
                    </span>
                  </div>
                </div>

                {/* Expandable Section: Full SecRule Preview & Rejection Info */}
                {isExpanded && (
                  <div className="space-y-3 pt-2 animate-fade-in">
                    {/* SecRule Preview (High contrast Dark Terminal Style) */}
                    <div className="rounded-lg bg-slate-950 border border-slate-800 text-slate-200 overflow-hidden flex flex-col font-mono text-[11.5px]">
                      <div className="px-3 py-1.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Code size={13} className="text-violet-400" />
                          <span className="font-bold uppercase text-[10px] text-slate-400">
                            Generated ModSecurity SecRule Syntax
                          </span>
                        </div>
                        <button
                          onClick={() => handleCopySecRule(rule)}
                          className="p-1 text-slate-400 hover:text-white transition-colors cursor-pointer flex items-center gap-1 text-[10.5px]"
                          title="Copy SecRule definition"
                        >
                          {copiedId === rule.rule_id ? (
                            <>
                              <Check size={12} className="text-emerald-400" />
                              <span className="text-emerald-400">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy size={12} />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                      <div className="p-3 overflow-x-auto text-violet-300 leading-relaxed bg-slate-950">
                        <pre className="m-0">
                          {rule.secrule_template.replace(
                            '{RULE_ID}',
                            rule.deployed_rule_id ? String(rule.deployed_rule_id) : 'PENDING_ID'
                          )}
                        </pre>
                      </div>
                    </div>
                  </div>
                )}

                {/* Rejection Reason display if rejected */}
                {rule.status === 'rejected' && rule.reject_reason && (
                  <div className="p-2.5 rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-[11.5px] text-red-700 dark:text-red-300 font-mono flex items-start gap-2">
                    <AlertTriangle size={14} className="text-red-600 dark:text-red-400 mt-0.5 shrink-0" />
                    <div>
                      <span className="font-semibold text-red-700 dark:text-red-400 block text-[10px] uppercase">Rejection Reason:</span>
                      <span>{rule.reject_reason}</span>
                    </div>
                  </div>
                )}

                {/* Action Buttons for Pending Rules */}
                {rule.status === 'pending' && isAdmin && (
                  <div className="flex items-center gap-2 pt-2 border-t border-[var(--bg-border)]">
                    {rejectingId === rule.rule_id ? (
                      <div className="flex-1 flex gap-2 animate-fade-in flex-wrap sm:flex-nowrap">
                        <input
                          type="text"
                          placeholder="Specify reason for rejection (optional)..."
                          value={rejectReason}
                          onChange={(e) => setRejectReason(e.target.value)}
                          className="flex-1 dash-input text-[12px] font-mono py-1"
                          autoFocus
                        />
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => handleReject(rule.rule_id)}
                          isLoading={rejectMutation.isPending}
                        >
                          Confirm Reject
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setRejectingId(null)
                            setRejectReason('')
                          }}
                        >
                          Cancel
                        </Button>
                      </div>
                    ) : (
                      <div className="flex-1 flex gap-2 justify-end">
                        <Button
                          variant="danger"
                          size="sm"
                          onClick={() => setRejectingId(rule.rule_id)}
                          icon={<X size={13} />}
                        >
                          Reject
                        </Button>
                        <Button
                          variant="success"
                          size="sm"
                          onClick={() => handleApprove(rule.rule_id)}
                          isLoading={approveMutation.isPending}
                          icon={<Check size={13} />}
                        >
                          Approve & Deploy to ModSec
                        </Button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* ═══ Section 4: Pagination Footer ═══ */}
      {totalPages > 1 && (
        <div className="dash-card p-3.5 mt-4 flex flex-col sm:flex-row items-center justify-between gap-3 text-[12px] font-mono">
          {/* Jump Form */}
          <form onSubmit={handlePageJump} className="flex items-center gap-2 text-[var(--text-muted)]">
            <span>Jump to:</span>
            <input
              type="number"
              min={1}
              max={totalPages}
              placeholder="#"
              value={pageInput}
              onChange={(e) => setPageInput(e.target.value)}
              className="w-14 dash-input py-1 px-2 text-center text-[12px] font-mono"
            />
            <button
              type="submit"
              disabled={!pageInput}
              className="bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] px-2.5 py-1 text-[11.5px] font-semibold rounded disabled:opacity-40 hover:bg-[var(--bg-hover)] text-[var(--text-primary)] cursor-pointer transition-colors"
            >
              Go
            </button>
          </form>

          {/* Page Buttons */}
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

            {getPageNumbers().map((num, idx) =>
              num === '...' ? (
                <span key={`ellipsis-${idx}`} className="px-1 text-[var(--text-muted)]">
                  …
                </span>
              ) : (
                <button
                  key={`page-${num}`}
                  onClick={() => setPage(num as number)}
                  className={`min-w-[28px] h-7 text-[12px] font-mono font-semibold rounded border cursor-pointer transition-colors ${
                    page === num
                      ? 'bg-violet-600 text-white border-violet-600 shadow-sm'
                      : 'bg-[var(--bg-surface)] border-[var(--bg-border)] text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {num}
                </button>
              )
            )}

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

      {/* ═══ Bulk Reject Modal Dialog ═══ */}
      {isBulkRejectModalOpen && (
        <div className="modal-backdrop">
          <div className="dash-modal w-full max-w-md p-6 space-y-4 animate-fade-in bg-[var(--bg-surface)]">
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-2.5 text-red-600 dark:text-red-400">
                <div className="p-2 rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20">
                  <AlertTriangle size={20} />
                </div>
                <div>
                  <h3 className="text-[16px] font-bold text-[var(--text-primary)] font-mono m-0">
                    Bulk Reject Rules
                  </h3>
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0 mt-0.5">
                    Dismiss {selectedRuleIds.length} selected pending rule(s)
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setIsBulkRejectModalOpen(false)}
                className="p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={18} />
              </button>
            </div>

            <p className="text-[12.5px] text-[var(--text-secondary)] leading-relaxed m-0">
              The selected AI-suggested rules will be categorized as rejected and will not be hot-deployed to ModSecurity edge nodes.
            </p>

            <div className="space-y-1.5">
              <label className="block text-[11.5px] font-semibold text-[var(--text-secondary)] font-mono">
                Rejection Reason (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. False positive, legitimate developer pattern..."
                value={bulkRejectReason}
                onChange={(e) => setBulkRejectReason(e.target.value)}
                className="w-full dash-input text-[12.5px] font-mono py-2"
                autoFocus
              />
            </div>

            <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[var(--bg-border)]">
              <Button
                variant="ghost"
                onClick={() => setIsBulkRejectModalOpen(false)}
                disabled={isBulkProcessing}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={handleExecuteBulkReject}
                isLoading={isBulkProcessing}
                icon={<X size={14} />}
              >
                Reject {selectedRuleIds.length} Rules
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default MLRules
