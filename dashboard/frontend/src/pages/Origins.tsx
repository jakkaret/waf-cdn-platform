import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getOrigins, deleteOrigin, restoreOrigin } from '../api/origins';
import { api } from '../api/axios';
import { Card } from '../components/ui/Card';
import { HealthDot } from '../components/ui/HealthDot';
import { EmptyState } from '../components/ui/EmptyState';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { Button } from '../components/ui/Button';
import { AddOriginModal } from '../components/AddOriginModal';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { toast } from 'react-hot-toast';
import { Origin } from '../types';

const Origins: React.FC = () => {
  const navigate = useNavigate();
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'pending' | 'error' | 'archived'>('all');
  const [originToDelete, setOriginToDelete] = useState<Origin | null>(null);
  const [originToRestore, setOriginToRestore] = useState<Origin | null>(null);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['origins'],
    queryFn: getOrigins,
    refetchInterval: 30000,
  });

  const { data: quotaData } = useQuery({
    queryKey: ['origins-quota'],
    queryFn: () => api.get('/origins/quota').then(r => r.data),
    refetchInterval: 30000,
  });

  const origins = data?.data?.origins || [];

  const filteredOrigins = origins.filter((origin: Origin) => {
    const matchesSearch = origin.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
      origin.ip.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all'
      ? origin.status !== 'archived'
      : origin.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleDeleteConfirm = async () => {
    if (!originToDelete) return;
    try {
      await deleteOrigin(originToDelete.origin_id);
      toast.success('Origin archived successfully');
      refetch();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to archive origin');
    } finally {
      setOriginToDelete(null);
    }
  };

  const handleRestoreConfirm = async () => {
    if (!originToRestore) return;
    try {
      await restoreOrigin(originToRestore.origin_id);
      toast.success('Origin restored successfully');
      refetch();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to restore origin');
    } finally {
      setOriginToRestore(null);
    }
  };
  const quotaUsed: number = quotaData?.origins?.used ?? origins.filter((o: Origin) => o.status !== 'archived').length;
  const quotaMax: number = quotaData?.origins?.max ?? 5;
  const quotaFull: boolean = quotaData?.origins?.at_limit ?? false;
  const quotaPct = Math.min(100, Math.round((quotaUsed / quotaMax) * 100));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-text-primary">My Origins</h1>
        <Button
          variant="primary"
          onClick={() => setIsAddModalOpen(true)}
          disabled={quotaFull}
          title={quotaFull ? `Quota reached (${quotaMax}/${quotaMax})` : 'Add a new origin server'}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-2">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Add Origin
        </Button>
      </div>

      {/* Quota Bar */}
      <Card className="p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-sm font-medium text-text-primary">Origin Quota</span>
          <span className={`text-sm font-bold ${quotaFull ? 'text-danger' : quotaPct >= 80 ? 'text-yellow-400' : 'text-success'
            }`}>
            {quotaUsed} / {quotaMax} used
          </span>
        </div>
        <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden">
          <div
            className={`h-2 rounded-full transition-all duration-500 ${quotaFull ? 'bg-danger' : quotaPct >= 80 ? 'bg-yellow-400' : 'bg-success'
              }`}
            style={{ width: `${quotaPct}%` }}
          />
        </div>
        {quotaFull && (
          <p className="text-xs text-danger mt-2">
            ⚠️ Quota reached. Delete an existing origin to add a new one.
          </p>
        )}
      </Card>

      {/* Search and Filters */}
      <div className="flex flex-col md:flex-row gap-4 items-center justify-between bg-bg-surface p-4 rounded-xl border border-bg-border shadow-sm">
        <div className="relative w-full md:w-80">
          <input
            type="text"
            placeholder="Search origins by name or IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-bg-surface2 border border-bg-border rounded-lg pl-10 pr-4 py-2 text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-colors"
          />
          <div className="absolute left-3 top-2.5 text-text-muted">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
          </div>
        </div>
        <div className="flex items-center gap-2 w-full md:w-auto">
          <span className="text-xs text-text-muted whitespace-nowrap">Status:</span>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
            className="bg-bg-surface2 border border-bg-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-accent"
          >
            <option value="all">All</option>
            <option value="active">Active</option>
            <option value="pending">Pending</option>
            <option value="error">Error</option>
            <option value="archived">Archived</option>
          </select>
        </div>
      </div>

      {isLoading ? (
        <div className="py-20">
          <LoadingSpinner size="lg" />
        </div>
      ) : origins.filter((o: Origin) => o.status !== 'archived').length === 0 && statusFilter === 'all' ? (
        <Card className="p-12 border border-bg-border bg-bg-surface2/30">
          <EmptyState
            title="No Origins Yet"
            subtitle="Click the 'Add Origin' button to start managing your web servers behind our WAF."
          />
        </Card>
      ) : filteredOrigins.length === 0 ? (
        <Card className="p-12 border border-bg-border bg-bg-surface2/30">
          <EmptyState
            title="No Matching Origins"
            subtitle="No origin servers match your current search query or status filter."
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredOrigins.map((origin: Origin) => (
            <Card key={origin.origin_id} className="flex flex-col h-full cursor-pointer hover:brightness-110 transition-all" onClick={() => navigate(`/origins/${origin.origin_id}`)}>
              <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-2">
                  <HealthDot status={origin.status === 'archived' ? 'degraded' : origin.health === 'up' ? 'online' : origin.health === 'down' ? 'offline' : 'degraded'} />
                  <h3 className="font-semibold text-lg text-text-primary">{origin.label}</h3>
                </div>
                <span className={`px-2 py-1 text-xs font-semibold rounded-full ${origin.status === 'active' ? 'bg-[#e6f9f0]/10 text-[#68d391]' :
                    origin.status === 'pending' ? 'bg-[#fff4e5]/10 text-[#f6ad55]' :
                      origin.status === 'archived' ? 'bg-white/10 text-text-muted' :
                        'bg-[#fff5f5]/10 text-[#fc8181]'
                  }`}>
                  {origin.status.toUpperCase()}
                </span>
              </div>

              <div className="flex-1 space-y-3 mb-6">
                <div className="text-sm text-text-muted">
                  <div className="flex items-center gap-2">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <path d="M2 12h20" />
                      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                    </svg>
                    {origin.ip}:{origin.port}
                  </div>
                </div>
                <div className="text-sm text-text-muted">
                  <div className="flex items-center gap-2">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                      <line x1="16" y1="2" x2="16" y2="6" />
                      <line x1="8" y1="2" x2="8" y2="6" />
                      <line x1="3" y1="10" x2="21" y2="10" />
                    </svg>
                    Added {new Date(origin.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>

              <div className="mt-auto pt-4 border-t border-bg-border flex justify-between items-center">
                <span className="text-sm font-medium text-accent hover:text-accent-light transition-colors">
                  View Details &rarr;
                </span>
                {origin.status === 'archived' ? (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setOriginToRestore(origin);
                    }}
                    className="text-success/60 hover:text-success p-1 rounded hover:bg-success/10 transition-all"
                    title="Restore origin server"
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
                      <polyline points="3 3 3 8 8 8" />
                    </svg>
                  </button>
                ) : (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setOriginToDelete(origin);
                    }}
                    className="text-danger/60 hover:text-danger p-1 rounded hover:bg-danger/10 transition-all"
                    title={origin.status === 'pending' ? 'Cancel setup' : 'Archive origin server'}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      {origin.status === 'pending' ? (
                        <>
                          <line x1="18" y1="6" x2="6" y2="18" />
                          <line x1="6" y1="6" x2="18" y2="18" />
                        </>
                      ) : (
                        <>
                          <polyline points="21 8 21 21 3 21 3 8" />
                          <rect x="1" y="3" width="22" height="5" />
                          <line x1="10" y1="12" x2="14" y2="12" />
                        </>
                      )}
                    </svg>
                  </button>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      <AddOriginModal
        open={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        onSuccess={() => {
          setIsAddModalOpen(false);
          refetch();
        }}
      />

      <ConfirmDialog
        open={!!originToDelete}
        onCancel={() => setOriginToDelete(null)}
        onConfirm={handleDeleteConfirm}
        title={originToDelete?.status === 'pending' ? "Cancel Setup" : "Archive Origin"}
        message={originToDelete ? (originToDelete.status === 'pending' ? `Are you sure you want to cancel the setup of the origin "${originToDelete.label}"?` : `Are you sure you want to archive the origin "${originToDelete.label}"? This will hide it from the active dashboard and put it into cold storage.`) : ''}
        confirmText={originToDelete?.status === 'pending' ? "Cancel Setup" : "Archive Origin"}
        isDanger={true}
      />

      <ConfirmDialog
        open={!!originToRestore}
        onCancel={() => setOriginToRestore(null)}
        onConfirm={handleRestoreConfirm}
        title="Restore Origin"
        message={originToRestore ? `Are you sure you want to restore the origin "${originToRestore.label}"? This will return it to active service.` : ''}
        confirmText="Restore Origin"
        isDanger={false}
      />
    </div>
  );
};

export default Origins;
