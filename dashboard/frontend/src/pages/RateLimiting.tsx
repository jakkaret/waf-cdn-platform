import React, { useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rateLimitsApi, RateRule } from '../api/rateLimits'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'
import {
  Gauge,
  Plus,
  Trash2,
  RefreshCw,
  Zap,
  Activity,
  AlertCircle,
  X,
  RotateCcw,
  CheckCircle2,
  Layers,
} from 'lucide-react'

export const RateLimiting: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()

  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<RateRule | null>(null)

  // Form State
  const [formData, setFormData] = useState({
    name: '',
    path_pattern: '',
    method: 'ALL',
    limit_count: 60,
    window_seconds: 60,
    burst: 10,
    action: '429',
  })

  // Fetch Rules
  const { data: rules = [], isLoading: isLoadingRules, refetch: refetchRules } = useQuery({
    queryKey: ['rate-limit-rules'],
    queryFn: rateLimitsApi.getRules,
  })

  // Fetch Live Throttled Clients
  const { data: throttledClients = [], isLoading: isLoadingThrottled, refetch: refetchThrottled, isFetching: isFetchingThrottled } = useQuery({
    queryKey: ['throttled-clients'],
    queryFn: rateLimitsApi.getThrottledClients,
    refetchInterval: 5000, // Poll every 5s for live sliding window updates
  })

  // Create Rule Mutation
  const createMutation = useMutation({
    mutationFn: rateLimitsApi.createRule,
    onSuccess: () => {
      toast.success('Rate limit policy enforced')
      queryClient.invalidateQueries({ queryKey: ['rate-limit-rules'] })
      setIsAddModalOpen(false)
      resetForm()
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Failed to create rate limit policy')
    },
  })

  // Update Rule Mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<RateRule> }) =>
      rateLimitsApi.updateRule(id, data),
    onSuccess: () => {
      toast.success('Rate limit policy updated')
      queryClient.invalidateQueries({ queryKey: ['rate-limit-rules'] })
      setEditingRule(null)
      setIsAddModalOpen(false)
      resetForm()
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Failed to update rate limit policy')
    },
  })

  // Delete Rule Mutation
  const deleteMutation = useMutation({
    mutationFn: rateLimitsApi.deleteRule,
    onSuccess: () => {
      toast.success('Rate limit policy removed')
      queryClient.invalidateQueries({ queryKey: ['rate-limit-rules'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Failed to remove rate limit policy')
    },
  })

  // Reset Client Mutation
  const resetClientMutation = useMutation({
    mutationFn: rateLimitsApi.resetClient,
    onSuccess: (res) => {
      toast.success(res.message || 'Client rate limit bucket cleared')
      queryClient.invalidateQueries({ queryKey: ['throttled-clients'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.detail || 'Failed to reset client limit')
    },
  })

  const resetForm = () => {
    setFormData({
      name: '',
      path_pattern: '',
      method: 'ALL',
      limit_count: 60,
      window_seconds: 60,
      burst: 10,
      action: '429',
    })
  }

  const handleOpenEdit = (rule: RateRule) => {
    setEditingRule(rule)
    setFormData({
      name: rule.name,
      path_pattern: rule.path_pattern,
      method: rule.method,
      limit_count: rule.limit_count,
      window_seconds: rule.window_seconds,
      burst: rule.burst,
      action: rule.action,
    })
    setIsAddModalOpen(true)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (editingRule) {
      updateMutation.mutate({
        id: editingRule.id,
        data: formData,
      })
    } else {
      createMutation.mutate(formData)
    }
  }

  const handleToggleEnable = (rule: RateRule) => {
    updateMutation.mutate({
      id: rule.id,
      data: { enabled: rule.enabled ? 0 : 1 },
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-[20px] font-bold tracking-tight text-[var(--text-primary)] font-mono">
            Rate Limiting Engine
          </h1>
          <p className="text-[12.5px] text-[var(--text-muted)] mt-0.5">
            Protect endpoints against L7 volumetric flooding, brute-force attacks, and abusive crawlers.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={() => {
              refetchRules()
              refetchThrottled()
            }}
            className="px-3 py-1.5 rounded-md bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] border border-[var(--bg-border)] text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer"
          >
            <RefreshCw size={13} className={isFetchingThrottled ? 'animate-spin' : ''} />
            <span>Refresh</span>
          </button>
          {isAdmin && (
            <button
              onClick={() => {
                setEditingRule(null)
                resetForm()
                setIsAddModalOpen(true)
              }}
              className="px-3 py-1.5 rounded-md bg-orange-500 hover:bg-orange-600 text-white text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
            >
              <Plus size={14} />
              <span>New Rate Rule</span>
            </button>
          )}
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium uppercase">Active Policies</span>
            <Gauge size={16} className="text-orange-500" />
          </div>
          <div className="text-[22px] font-bold font-mono text-[var(--text-primary)]">
            {rules.length}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            {rules.filter((r) => r.enabled).length} Enabled • {rules.filter((r) => !r.enabled).length} Disabled
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium uppercase">Throttled Clients</span>
            <Zap size={16} className="text-amber-500" />
          </div>
          <div className="text-[22px] font-bold font-mono text-amber-500">
            {throttledClients.length}
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            Active in Redis sliding window
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium uppercase">Engine Mechanism</span>
            <Layers size={16} className="text-blue-400" />
          </div>
          <div className="text-[16px] font-bold font-mono text-[var(--text-primary)] mt-1">
            Redis Sliding Window
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            Millisecond precision TTL
          </div>
        </div>

        <div className="dash-card p-4">
          <div className="flex items-center justify-between text-[var(--text-muted)] mb-1">
            <span className="text-[11.5px] font-mono font-medium uppercase">Edge Enforcement</span>
            <Activity size={16} className="text-emerald-500 animate-pulse" />
          </div>
          <div className="text-[22px] font-bold font-mono text-emerald-500">
            Active
          </div>
          <div className="text-[11px] text-[var(--text-muted)] mt-1 font-mono">
            Nginx limit_req_zone & Redis
          </div>
        </div>
      </div>

      {/* Configured Rate Rules Table */}
      <div className="dash-card overflow-hidden">
        <div className="dash-card-header">
          <h3 className="font-mono text-[13.5px]">
            <Gauge size={16} className="text-orange-500" />
            <span>Configured Rate Limiting Policies</span>
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>Policy Name</th>
                <th>Target Path Pattern</th>
                <th>HTTP Method</th>
                <th>Threshold Limit</th>
                <th>Burst Buffer</th>
                <th>Action</th>
                <th>Status</th>
                {isAdmin && <th className="text-right">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {isLoadingRules ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-[var(--text-muted)]">
                    Loading rate limit rules...
                  </td>
                </tr>
              ) : rules.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-[var(--text-muted)]">
                    No rate limit rules defined yet.
                  </td>
                </tr>
              ) : (
                rules.map((rule) => (
                  <tr key={rule.id}>
                    <td className="font-medium text-[13px] text-[var(--text-primary)]">
                      {rule.name}
                    </td>
                    <td className="font-mono text-[12px] text-orange-400">
                      {rule.path_pattern}
                    </td>
                    <td>
                      <span className="mono-chip font-bold">
                        {rule.method}
                      </span>
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-secondary)]">
                      <span className="font-bold text-[var(--text-primary)]">{rule.limit_count}</span> reqs / {rule.window_seconds}s
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-muted)]">
                      +{rule.burst} reqs
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        {rule.action === '429' ? '429 Too Many Requests' : 'Temporary Ban'}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        onClick={() => handleToggleEnable(rule)}
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium cursor-pointer transition-colors ${
                          rule.enabled
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-[var(--bg-hover)] text-[var(--text-muted)] border border-[var(--bg-border)]'
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${rule.enabled ? 'bg-emerald-500' : 'bg-[var(--text-muted)]'}`} />
                        <span>{rule.enabled ? 'ACTIVE' : 'PAUSED'}</span>
                      </button>
                    </td>
                    {isAdmin && (
                      <td className="text-right">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => handleOpenEdit(rule)}
                            className="px-2 py-1 text-[11.5px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] rounded transition-colors cursor-pointer"
                          >
                            Edit
                          </button>
                          <button
                            onClick={() => {
                              if (confirm(`Delete rate limit rule "${rule.name}"?`)) {
                                deleteMutation.mutate(rule.id)
                              }
                            }}
                            className="p-1 text-[var(--text-muted)] hover:text-red-400 hover:bg-red-500/10 rounded transition-colors cursor-pointer"
                            title="Delete rule"
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

      {/* Live Throttled Stream Table */}
      <div className="dash-card overflow-hidden">
        <div className="dash-card-header">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
            <h3 className="font-mono text-[13.5px] m-0">Live Throttled Clients (Redis Sliding Window Stream)</h3>
          </div>
          <span className="text-[11.5px] font-mono text-[var(--text-muted)]">
            Auto-refreshing every 5s
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>Client IP Address</th>
                <th>Current Bucket Count</th>
                <th>Remaining Lock TTL</th>
                <th>Status</th>
                {isAdmin && <th className="text-right">Action</th>}
              </tr>
            </thead>
            <tbody>
              {isLoadingThrottled ? (
                <tr>
                  <td colSpan={5} className="text-center py-6 text-[var(--text-muted)]">
                    Scanning active Redis buckets...
                  </td>
                </tr>
              ) : throttledClients.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-[var(--text-muted)]">
                    <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-500/60" />
                    <span className="text-[12.5px]">No throttled clients at this moment. Traffic is healthy.</span>
                  </td>
                </tr>
              ) : (
                throttledClients.map((client) => (
                  <tr key={client.ip}>
                    <td className="font-mono font-bold text-[12.5px] text-[var(--text-primary)]">
                      {client.ip}
                    </td>
                    <td className="font-mono text-[12.5px] text-amber-400 font-bold">
                      {client.request_count} requests
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-muted)]">
                      {client.ttl_seconds > 0 ? `${client.ttl_seconds} seconds` : 'Expiring'}
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        THROTTLED
                      </span>
                    </td>
                    {isAdmin && (
                      <td className="text-right">
                        <button
                          onClick={() => resetClientMutation.mutate(client.ip)}
                          disabled={resetClientMutation.isPending}
                          className="px-2.5 py-1 rounded bg-[var(--bg-surface-elevated)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--bg-border)] text-[11.5px] font-medium inline-flex items-center gap-1 transition-colors cursor-pointer"
                        >
                          <RotateCcw size={11} />
                          <span>Release Bucket</span>
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

      {/* Add / Edit Policy Modal */}
      {isAddModalOpen && typeof document !== 'undefined' && createPortal(
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setIsAddModalOpen(false)
          }}
        >
          <div
            className="dash-modal w-full max-w-md p-6 shadow-2xl animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between pb-4 border-b border-[var(--bg-border)] mb-4">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded bg-orange-500/10 text-orange-500 flex items-center justify-center">
                  <Gauge size={16} />
                </div>
                <h3 className="text-[15px] font-bold font-mono text-[var(--text-primary)] m-0">
                  {editingRule ? 'Edit Rate Policy' : 'Create Rate Limit Policy'}
                </h3>
              </div>
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] cursor-pointer"
              >
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4 text-[13px]">
              <div>
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                  Policy Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Login Brute Force Protection"
                  className="w-full dash-input text-[12.5px]"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    Path Pattern
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. /api/auth/* or *"
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.path_pattern}
                    onChange={(e) => setFormData({ ...formData, path_pattern: e.target.value })}
                  />
                </div>
                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    Method
                  </label>
                  <select
                    className="w-full dash-input text-[12.5px]"
                    value={formData.method}
                    onChange={(e) => setFormData({ ...formData, method: e.target.value })}
                  >
                    <option value="ALL">ALL</option>
                    <option value="POST">POST</option>
                    <option value="GET">GET</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    Max Requests
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.limit_count}
                    onChange={(e) => setFormData({ ...formData, limit_count: parseInt(e.target.value, 10) || 1 })}
                  />
                </div>

                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    Window (sec)
                  </label>
                  <input
                    type="number"
                    min="1"
                    required
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.window_seconds}
                    onChange={(e) => setFormData({ ...formData, window_seconds: parseInt(e.target.value, 10) || 1 })}
                  />
                </div>

                <div>
                  <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                    Burst Buffer
                  </label>
                  <input
                    type="number"
                    min="0"
                    className="w-full dash-input font-mono text-[12.5px]"
                    value={formData.burst}
                    onChange={(e) => setFormData({ ...formData, burst: parseInt(e.target.value, 10) || 0 })}
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11.5px] font-medium text-[var(--text-secondary)] mb-1">
                  Action When Limit Exceeded
                </label>
                <select
                  className="w-full dash-input text-[12.5px]"
                  value={formData.action}
                  onChange={(e) => setFormData({ ...formData, action: e.target.value })}
                >
                  <option value="429">HTTP 429 Too Many Requests (Standard)</option>
                  <option value="temp_ban">Temporary IP Jail / Drop</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2.5 pt-3 border-t border-[var(--bg-border)]">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-3.5 py-1.5 rounded-md bg-[var(--bg-primary)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] text-[12px] font-medium transition-colors cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending || updateMutation.isPending}
                  className="px-4 py-1.5 rounded-md bg-orange-500 hover:bg-orange-600 text-white text-[12px] font-medium flex items-center gap-1.5 transition-colors cursor-pointer shadow-sm"
                >
                  {createMutation.isPending || updateMutation.isPending ? 'Saving...' : editingRule ? 'Save Changes' : 'Enforce Policy'}
                </button>
              </div>
            </form>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}

export default RateLimiting
