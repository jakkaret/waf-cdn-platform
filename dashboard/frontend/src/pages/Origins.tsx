import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getOrigins, deleteOrigin, restoreOrigin } from '../api/origins'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { AddOriginModal } from '../components/AddOriginModal'
import { ConfirmDialog } from '../components/ui/ConfirmDialog'
import { toast } from 'react-hot-toast'
import { Origin } from '../types'
import {
  Server,
  Plus,
  Search,
  RotateCcw,
  Trash2,
  ExternalLink,
  ShieldCheck,
  Activity,
  Globe,
  HardDrive,
  Clock,
  ArrowRight,
  AlertTriangle,
} from 'lucide-react'

export const Origins: React.FC = () => {
  const navigate = useNavigate()
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'pending' | 'error' | 'archived'>('all')
  const [originToDelete, setOriginToDelete] = useState<Origin | null>(null)
  const [originToRestore, setOriginToRestore] = useState<Origin | null>(null)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['origins'],
    queryFn: getOrigins,
    refetchInterval: 15000,
  })

  const { data: quotaData } = useQuery({
    queryKey: ['origins-quota'],
    queryFn: () => api.get('/origins/quota').then((r) => r.data),
    refetchInterval: 30000,
  })

  const origins = data?.data?.origins || []

  const filteredOrigins = origins.filter((origin: Origin) => {
    const matchesSearch =
      origin.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
      origin.ip.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesStatus =
      statusFilter === 'all' ? origin.status !== 'archived' : origin.status === statusFilter
    return matchesSearch && matchesStatus
  })

  const handleDeleteConfirm = async () => {
    if (!originToDelete) return
    try {
      await deleteOrigin(originToDelete.origin_id)
      toast.success('Origin archived successfully')
      refetch()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to archive origin')
    } finally {
      setOriginToDelete(null)
    }
  }

  const handleRestoreConfirm = async () => {
    if (!originToRestore) return
    try {
      await restoreOrigin(originToRestore.origin_id)
      toast.success('Origin restored successfully')
      refetch()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to restore origin')
    } finally {
      setOriginToRestore(null)
    }
  }

  const quotaUsed: number =
    quotaData?.origins?.used ?? origins.filter((o: Origin) => o.status !== 'archived').length
  const quotaMax: number = quotaData?.origins?.max ?? 5
  const quotaFull: boolean = quotaData?.origins?.at_limit ?? false
  const quotaPct = Math.min(100, Math.round((quotaUsed / quotaMax) * 100))

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="Origin Server Infrastructure"
        subtitle="Upstream web server pools protected behind the CloudWAF reverse proxy"
        badge={
          <Badge color="blue" dot>
            {origins.length} POOLS CONFIGURED
          </Badge>
        }
        action={
          <Button
            variant="brand"
            onClick={() => setIsAddModalOpen(true)}
            disabled={quotaFull}
            icon={<Plus size={14} />}
          >
            Add Origin Server
          </Button>
        }
      />

      {/* Quota & Capacity Banner */}
      <div className="dash-card p-4 sm:p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-bold text-[var(--text-primary)] font-mono">
              Origin Pool Quota Allocation
            </span>
            <span
              className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded ${
                quotaFull
                  ? 'bg-red-500/15 text-red-400'
                  : quotaPct >= 80
                  ? 'bg-amber-500/15 text-amber-400'
                  : 'bg-emerald-500/15 text-emerald-400'
              }`}
            >
              {quotaUsed} / {quotaMax} slots used ({quotaPct}%)
            </span>
          </div>
          <p className="text-[12px] text-[var(--text-muted)] m-0">
            Each origin server receives dedicated SSL cert provisioning and ModSec reverse proxy routes.
          </p>
        </div>

        <div className="w-full sm:w-56 space-y-1.5">
          <div className="w-full bg-[var(--bg-primary)] rounded-full h-2 overflow-hidden border border-[var(--bg-border-subtle)]">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                quotaFull ? 'bg-red-500' : quotaPct >= 80 ? 'bg-amber-500' : 'bg-emerald-500'
              }`}
              style={{ width: `${quotaPct}%` }}
            />
          </div>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="dash-card p-3.5 flex flex-col md:flex-row gap-3 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="absolute left-3 top-2.5 text-[var(--text-muted)]" size={14} />
          <input
            type="text"
            placeholder="Search by label or IP address..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full dash-input pl-8 py-1.5 text-[12px] font-mono"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto font-mono text-[12px]">
          <span className="text-[var(--text-muted)] text-[11px]">Filter:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
            className="dash-input py-1 text-[12px] font-mono cursor-pointer"
          >
            <option value="all">Active Only (Excl. Archived)</option>
            <option value="active">Active</option>
            <option value="pending">Pending Setup</option>
            <option value="error">Unreachable / Error</option>
            <option value="archived">Archived</option>
          </select>
        </div>
      </div>

      {/* Origins Cards Grid */}
      {isLoading ? (
        <div className="text-center py-16 text-[var(--text-muted)] font-mono text-[12px]">
          Loading origin servers...
        </div>
      ) : filteredOrigins.length === 0 ? (
        <div className="dash-card p-12 text-center space-y-3">
          <Server size={36} className="mx-auto text-[var(--text-muted)] opacity-40" />
          <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
            No Origin Servers Found
          </h3>
          <p className="text-[12px] text-[var(--text-muted)] m-0 font-mono">
            {origins.length === 0
              ? 'Click "Add Origin Server" to attach your backend hosts behind the WAF.'
              : 'No origins match the current search or status filter criteria.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filteredOrigins.map((origin: Origin) => {
            const isArchived = origin.status === 'archived'
            const isPending = origin.status === 'pending'
            const isActive = origin.status === 'active'

            return (
              <div
                key={origin.origin_id}
                onClick={() => navigate(`/origins/${origin.origin_id}`)}
                className="dash-card p-5 flex flex-col justify-between hover:border-orange-500/40 hover:shadow-card-hover transition-all cursor-pointer group"
              >
                <div>
                  <div className="flex justify-between items-start mb-3">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-orange-500/10 text-orange-500 flex items-center justify-center">
                        <Server size={16} />
                      </div>
                      <div>
                        <h3 className="font-bold text-[14px] text-[var(--text-primary)] font-mono m-0 group-hover:text-orange-500 transition-colors">
                          {origin.label}
                        </h3>
                        <p className="text-[11px] font-mono text-[var(--text-muted)] m-0">
                          {origin.ip}:{origin.port}
                        </p>
                      </div>
                    </div>

                    <Badge
                      color={isActive ? 'success' : isPending ? 'warning' : isArchived ? 'gray' : 'danger'}
                      dot
                    >
                      {origin.status.toUpperCase()}
                    </Badge>
                  </div>

                  <div className="mt-4 pt-3 border-t border-[var(--bg-border-subtle)] space-y-2 text-[12px] font-mono">
                    <div className="flex justify-between text-[var(--text-secondary)]">
                      <span className="text-[var(--text-muted)]">Proxy Target:</span>
                      <span className="text-[var(--text-primary)] font-semibold">
                        http://{origin.ip}:{origin.port}
                      </span>
                    </div>
                    <div className="flex justify-between text-[var(--text-secondary)]">
                      <span className="text-[var(--text-muted)]">Added on:</span>
                      <span>{new Date(origin.created_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                </div>

                <div className="mt-5 pt-3 border-t border-[var(--bg-border)] flex justify-between items-center text-[12px]">
                  <span className="font-semibold text-orange-500 flex items-center gap-1 group-hover:gap-1.5 transition-all font-mono">
                    <span>Manage Pool</span>
                    <ArrowRight size={13} />
                  </span>

                  {isArchived ? (
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setOriginToRestore(origin)
                      }}
                      className="p-1.5 text-emerald-500 hover:bg-emerald-500/10 rounded transition-colors"
                      title="Restore origin"
                    >
                      <RotateCcw size={14} />
                    </button>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setOriginToDelete(origin)
                      }}
                      className="p-1.5 text-[var(--text-muted)] hover:text-red-500 hover:bg-red-500/10 rounded transition-colors"
                      title={isPending ? 'Cancel setup' : 'Archive origin'}
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}

      <AddOriginModal
        open={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSuccess={() => {
          setIsAddModalOpen(false)
          refetch()
        }}
      />

      <ConfirmDialog
        open={!!originToDelete}
        onCancel={() => setOriginToDelete(null)}
        onConfirm={handleDeleteConfirm}
        title={originToDelete?.status === 'pending' ? 'Cancel Setup' : 'Archive Origin'}
        message={
          originToDelete
            ? originToDelete.status === 'pending'
              ? `Are you sure you want to cancel the setup of the origin "${originToDelete.label}"?`
              : `Are you sure you want to archive the origin "${originToDelete.label}"? This will hide it from the active dashboard.`
            : ''
        }
        confirmText={originToDelete?.status === 'pending' ? 'Cancel Setup' : 'Archive Origin'}
        isDanger={true}
      />

      <ConfirmDialog
        open={!!originToRestore}
        onCancel={() => setOriginToRestore(null)}
        onConfirm={handleRestoreConfirm}
        title="Restore Origin"
        message={
          originToRestore
            ? `Are you sure you want to restore origin "${originToRestore.label}" back to active service?`
            : ''
        }
        confirmText="Restore Origin"
        isDanger={false}
      />
    </div>
  )
}

export default Origins
