import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getOrigin, deleteOrigin, restoreOrigin } from '../api/origins';
import { getDomains, deleteDomain, verifyDomain } from '../api/domains';
import { rulesApi } from '../api/rules';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { HealthDot } from '../components/ui/HealthDot';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { EmptyState } from '../components/ui/EmptyState';
import { DomainSetupWizard } from '../components/DomainSetupWizard';
import { toast } from 'react-hot-toast';
import { WafRule, Domain } from '../types';

const OriginDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'overview' | 'domains' | 'waf' | 'ssl'>('overview');
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isRestoreModalOpen, setIsRestoreModalOpen] = useState(false);
  const [isDomainWizardOpen, setIsDomainWizardOpen] = useState(false);
  const [domainToDelete, setDomainToDelete] = useState<string | null>(null);
  const [verifyingDomainId, setVerifyingDomainId] = useState<string | null>(null);
  const [showAddRule, setShowAddRule] = useState(false);
  const [newRule, setNewRule] = useState<{ id: string; variable: WafRule['variable']; operator: string; severity: WafRule['severity']; message: string }>({ id: '', variable: 'REQUEST_URI', operator: '', severity: 'HIGH', message: '' });
  const queryClient = useQueryClient();

  const { data, isLoading, isError } = useQuery({
    queryKey: ['origin', id],
    queryFn: () => getOrigin(id!),
    enabled: !!id,
  });

  const { data: domainsData, refetch: refetchDomains } = useQuery({
    queryKey: ['domains', id],
    queryFn: () => getDomains(id!),
    enabled: !!id,
  });

  const { data: rulesData, isLoading: rulesLoading } = useQuery({
    queryKey: ['waf-rules'],
    queryFn: () => rulesApi.getRules(),
  });

  const deleteRuleMutation = useMutation({
    mutationFn: (ruleId: string) => rulesApi.deleteRule(ruleId),
    onSuccess: () => {
      toast.success('Rule deleted');
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] });
    },
    onError: () => toast.error('Failed to delete rule'),
  });

  const createRuleMutation = useMutation({
    mutationFn: (rule: typeof newRule) => rulesApi.createRule(rule),
    onSuccess: () => {
      toast.success('Rule created successfully');
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] });
      setShowAddRule(false);
      setNewRule({ id: '', variable: 'REQUEST_URI', operator: '', severity: 'HIGH', message: '' });
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to create rule'),
  });

  const origin = data?.data || null;
  const domains = domainsData?.data?.domains || [];

  const handleDelete = async () => {
    const isPending = origin?.status === 'pending';
    try {
      await deleteOrigin(id!);
      toast.success(isPending ? 'Origin setup cancelled successfully' : 'Origin archived successfully');
      navigate('/origins');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || (isPending ? 'Failed to cancel setup' : 'Failed to archive origin'));
    }
  };

  const handleRestore = async () => {
    try {
      await restoreOrigin(id!);
      toast.success('Origin restored successfully');
      queryClient.invalidateQueries({ queryKey: ['origin', id] });
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to restore origin');
    } finally {
      setIsRestoreModalOpen(false);
    }
  };

  const handleDeleteDomain = async () => {
    if (!domainToDelete) return;
    try {
      await deleteDomain(id!, domainToDelete);
      toast.success('Domain deleted successfully');
      refetchDomains();
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to delete domain');
    } finally {
      setDomainToDelete(null);
    }
  };

  const handleVerifyDomain = async (domainId: string) => {
    setVerifyingDomainId(domainId);
    try {
      const res = await verifyDomain(id!, domainId);
      if (res.data?.status === 'success') {
        toast.success('✅ Domain verified successfully!');
        refetchDomains();
      } else {
        toast.error(res.data?.message || '❌ DNS records not found yet. Please try again.');
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || '❌ Verification failed. Check DNS settings.');
    } finally {
      setVerifyingDomainId(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center py-20">
        <LoadingSpinner size="lg" />
      </div>
    );
  }

  if (isError || !origin) {
    return (
      <div className="p-6">
        <Card className="p-12 text-center text-text-muted">
          <p>Failed to load origin details.</p>
          <Button variant="secondary" className="mt-4" onClick={() => navigate('/origins')}>
            Back to Origins
          </Button>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex justify-between items-center bg-bg-surface p-6 rounded-xl border border-bg-border shadow-sm">
        <div className="flex items-center gap-4">
          <button 
            onClick={() => navigate('/origins')}
            className="p-2 bg-bg-surface2 rounded-lg text-text-muted hover:text-text-primary hover:bg-bg-border transition-colors"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M19 12H5M12 19l-7-7 7-7"/>
            </svg>
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold text-text-primary">{origin.label}</h1>
              <HealthDot status={origin.health === 'up' ? 'online' : origin.health === 'down' ? 'offline' : 'degraded'} />
              <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                  origin.status === 'active' ? 'bg-[#e6f9f0]/10 text-[#68d391]' :
                  origin.status === 'pending' ? 'bg-[#fff4e5]/10 text-[#f6ad55]' :
                  'bg-[#fff5f5]/10 text-[#fc8181]'
                }`}>
                  {origin.status.toUpperCase()}
                </span>
            </div>
            <p className="text-sm text-text-muted mt-1">{origin.ip}:{origin.port}</p>
          </div>
        </div>
        
        <div className="flex gap-3">
          {origin.status === 'archived' ? (
            <Button variant="primary" className="!bg-success hover:!bg-success-dark border-none" onClick={() => setIsRestoreModalOpen(true)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-2">
                <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
                <polyline points="3 3 3 8 8 8" />
              </svg>
              Restore Origin
            </Button>
          ) : origin.status === 'pending' ? (
            <Button variant="outline" className="text-danger hover:bg-danger/10 border-danger hover:border-danger transition-colors" onClick={() => setIsDeleteModalOpen(true)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-2">
                <line x1="18" y1="6" x2="6" y2="18" />
                <line x1="6" y1="6" x2="18" y2="18" />
              </svg>
              Cancel Setup
            </Button>
          ) : (
            <Button variant="danger" onClick={() => setIsDeleteModalOpen(true)}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-2">
                <polyline points="21 8 21 21 3 21 3 8" />
                <rect x="1" y="3" width="22" height="5" />
                <line x1="10" y1="12" x2="14" y2="12" />
              </svg>
              Archive Origin
            </Button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-bg-border overflow-x-auto">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'domains', label: 'Domains & DNS' },
          { id: 'waf', label: 'WAF Config' },
          { id: 'ssl', label: 'SSL Certs' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`px-4 py-3 text-sm font-medium border-b-2 whitespace-nowrap transition-colors ${
              activeTab === tab.id 
                ? 'border-accent text-accent' 
                : 'border-transparent text-text-muted hover:text-text-primary hover:bg-bg-surface2/50'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="py-4">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4 text-text-primary">Origin Information</h3>
              <div className="space-y-4">
                <div className="grid grid-cols-3 gap-2 py-2 border-b border-bg-border/50">
                  <span className="text-text-muted text-sm">Label</span>
                  <span className="col-span-2 text-text-primary font-medium">{origin.label}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 py-2 border-b border-bg-border/50">
                  <span className="text-text-muted text-sm">IP Address</span>
                  <span className="col-span-2 text-text-primary font-mono text-sm">{origin.ip}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 py-2 border-b border-bg-border/50">
                  <span className="text-text-muted text-sm">Port</span>
                  <span className="col-span-2 text-text-primary font-mono text-sm">{origin.port}</span>
                </div>
                <div className="grid grid-cols-3 gap-2 py-2 border-b border-bg-border/50">
                  <span className="text-text-muted text-sm">Created At</span>
                  <span className="col-span-2 text-text-primary text-sm">{new Date(origin.created_at).toLocaleString()}</span>
                </div>
              </div>
            </Card>
          </div>
        )}
        
        {activeTab === 'domains' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-semibold text-text-primary">Custom Domains</h2>
              <Button variant="primary" onClick={() => setIsDomainWizardOpen(true)}>
                + Add Domain
              </Button>
            </div>
            
            {domains.length === 0 ? (
              <Card className="p-12 text-center border-dashed">
                <EmptyState 
                  title="No domains connected"
                  subtitle="Add a custom domain to route traffic through the WAF to this origin."
                />
                <Button variant="primary" className="mt-4" onClick={() => setIsDomainWizardOpen(true)}>
                  Add Custom Domain
                </Button>
              </Card>
            ) : (
              <div className="grid grid-cols-1 gap-4">
                {domains.map((domain: Domain) => (
                  <Card key={domain.domain_id} className="p-5 flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-3">
                        <h3 className="text-lg font-bold text-text-primary font-mono">{domain.domain_name}</h3>
                        <span className={`px-2 py-1 text-[10px] font-bold uppercase rounded-full tracking-wider ${
                          domain.verification_status === 'verified' ? 'bg-success/10 text-success' : 
                          domain.verification_status === 'pending' ? 'bg-[#f6ad55]/10 text-[#f6ad55]' : 
                          'bg-danger/10 text-danger'
                        }`}>
                          {domain.verification_status}
                        </span>
                      </div>
                      <p className="text-xs text-text-muted mt-2">Added on {new Date(domain.created_at).toLocaleDateString()}</p>
                    </div>
                    
                    <div className="flex gap-2">
                      {domain.verification_status !== 'verified' && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleVerifyDomain(domain.domain_id)}
                          disabled={verifyingDomainId === domain.domain_id}
                        >
                          {verifyingDomainId === domain.domain_id ? (
                            <span className="flex items-center gap-1.5">
                              <LoadingSpinner size="sm" />
                              Checking...
                            </span>
                          ) : 'Verify DNS'}
                        </Button>
                      )}
                      <Button variant="danger" size="sm" onClick={() => setDomainToDelete(domain.domain_id)}>
                        Remove
                      </Button>
                    </div>
                  </Card>
                ))}
              </div>
            )}
            
            <DomainSetupWizard 
              open={isDomainWizardOpen} 
              onClose={() => setIsDomainWizardOpen(false)}
              onSuccess={() => {
                setIsDomainWizardOpen(false);
                refetchDomains();
              }}
              originId={id!}
            />
            
            <ConfirmDialog
              open={!!domainToDelete}
              onCancel={() => setDomainToDelete(null)}
              onConfirm={handleDeleteDomain}
              title="Remove Domain"
              message="Are you sure you want to remove this domain? Traffic routed through this domain will stop working immediately."
              confirmText="Remove Domain"
              isDanger={true}
            />
          </div>
        )}

        {activeTab === 'waf' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="text-lg font-semibold text-text-primary">WAF Custom Rules</h2>
                <p className="text-sm text-text-muted mt-0.5">ModSecurity rules applied globally across all origins</p>
              </div>
              <Button variant="primary" onClick={() => setShowAddRule(!showAddRule)}>
                {showAddRule ? 'Cancel' : '+ Add Rule'}
              </Button>
            </div>

            {/* Add Rule Form */}
            {showAddRule && (
              <Card className="p-5 border border-accent/30 bg-accent/5">
                <h3 className="text-sm font-semibold text-accent mb-4">New Rule</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs text-text-muted mb-1 block">Rule ID</label>
                    <input
                      className="w-full bg-bg-surface border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-accent focus:outline-none font-mono"
                      placeholder="e.g. CUSTOM-001"
                      value={newRule.id}
                      onChange={e => setNewRule(r => ({ ...r, id: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-text-muted mb-1 block">Variable</label>
                    <select
                      className="w-full bg-bg-surface border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-accent focus:outline-none"
                      value={newRule.variable}
                      onChange={e => setNewRule(r => ({ ...r, variable: e.target.value as WafRule['variable'] }))}
                    >
                      <option value="REQUEST_URI">REQUEST_URI</option>
                      <option value="ARGS">ARGS</option>
                      <option value="REQUEST_HEADERS">REQUEST_HEADERS</option>
                      <option value="REQUEST_BODY">REQUEST_BODY</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-text-muted mb-1 block">Operator / Pattern</label>
                    <input
                      className="w-full bg-bg-surface border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-accent focus:outline-none font-mono"
                      placeholder="e.g. @rx (select|union|drop)"
                      value={newRule.operator}
                      onChange={e => setNewRule(r => ({ ...r, operator: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-text-muted mb-1 block">Severity</label>
                    <select
                      className="w-full bg-bg-surface border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-accent focus:outline-none"
                      value={newRule.severity}
                      onChange={e => setNewRule(r => ({ ...r, severity: e.target.value as WafRule['severity'] }))}
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label className="text-xs text-text-muted mb-1 block">Message / Description</label>
                    <input
                      className="w-full bg-bg-surface border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:border-accent focus:outline-none"
                      placeholder="e.g. Block SQL injection attempt"
                      value={newRule.message}
                      onChange={e => setNewRule(r => ({ ...r, message: e.target.value }))}
                    />
                  </div>
                </div>
                <div className="flex justify-end mt-4">
                  <Button
                    variant="primary"
                    onClick={() => createRuleMutation.mutate(newRule)}
                    disabled={!newRule.id || !newRule.operator || !newRule.message || createRuleMutation.isPending}
                  >
                    {createRuleMutation.isPending ? 'Saving...' : 'Save Rule'}
                  </Button>
                </div>
              </Card>
            )}

            {/* Rules Table */}
            <Card noPadding>
              {rulesLoading ? (
                <div className="flex justify-center py-12"><LoadingSpinner size="lg" /></div>
              ) : !rulesData || rulesData.length === 0 ? (
                <div className="p-12 text-center">
                  <EmptyState title="No custom rules" subtitle='Click "+ Add Rule" to create a ModSecurity custom rule.' />
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-white/5 text-left">
                        {['Rule ID', 'Variable', 'Operator', 'Severity', 'Message', ''].map(h => (
                          <th key={h} className="px-4 py-3 text-xs font-semibold text-text-muted uppercase tracking-wider">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {rulesData.map((rule: WafRule) => (
                        <tr key={rule.id} className="border-b border-white/5 hover:bg-white/2 transition-colors">
                          <td className="px-4 py-3 font-mono text-xs text-accent">{rule.id}</td>
                          <td className="px-4 py-3 text-text-muted text-xs">{rule.variable}</td>
                          <td className="px-4 py-3 font-mono text-xs text-text-primary max-w-[180px] truncate">{rule.operator}</td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                              rule.severity === 'CRITICAL' ? 'bg-red-500/15 text-red-400' :
                              rule.severity === 'HIGH' ? 'bg-orange-500/15 text-orange-400' :
                              rule.severity === 'MEDIUM' ? 'bg-yellow-500/15 text-yellow-400' :
                              'bg-blue-500/15 text-blue-400'
                            }`}>{rule.severity}</span>
                          </td>
                          <td className="px-4 py-3 text-text-muted text-xs max-w-[200px] truncate">{rule.message}</td>
                          <td className="px-4 py-3 text-right">
                            <button
                              onClick={() => deleteRuleMutation.mutate(rule.id)}
                              disabled={deleteRuleMutation.isPending}
                              className="text-danger/60 hover:text-danger text-xs font-medium transition-colors"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>
        )}

        {activeTab === 'ssl' && (
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold text-text-primary">SSL Certificates</h2>
              <p className="text-sm text-text-muted mt-0.5">Managed automatically by Caddy via Let's Encrypt / ZeroSSL</p>
            </div>

            {domains.length === 0 ? (
              <Card className="p-12 text-center border-dashed">
                <EmptyState
                  title="No domains configured"
                  subtitle="Add and verify a custom domain first to enable SSL certificate management."
                />
              </Card>
            ) : (
              <div className="grid grid-cols-1 gap-4">
                {domains.map((domain: Domain) => (
                  <Card key={domain.domain_id} className="p-5">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-9 h-9 rounded-lg flex items-center justify-center text-lg ${
                          domain.ssl_status === 'active' ? 'bg-success/10' :
                          domain.ssl_status === 'pending' ? 'bg-yellow-500/10' :
                          domain.ssl_status === 'error' ? 'bg-danger/10' : 'bg-white/5'
                        }`}>
                          {domain.ssl_status === 'active' ? '🔒' : domain.ssl_status === 'pending' ? '⏳' : domain.ssl_status === 'error' ? '⚠️' : '🔓'}
                        </div>
                        <div>
                          <p className="font-bold text-text-primary font-mono">{domain.domain_name}</p>
                          <p className="text-xs text-text-muted mt-0.5">
                            {domain.ssl_status === 'active' && domain.ssl_expires_at
                              ? `Expires ${new Date(domain.ssl_expires_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })}`
                              : domain.ssl_status === 'pending' ? 'Certificate provisioning in progress...'
                              : domain.ssl_status === 'error' ? 'Certificate error — check DNS settings'
                              : 'Domain not verified — verify DNS first to enable SSL'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                          domain.ssl_status === 'active' ? 'bg-success/10 text-success' :
                          domain.ssl_status === 'pending' ? 'bg-yellow-500/10 text-yellow-400' :
                          domain.ssl_status === 'error' ? 'bg-danger/10 text-danger' :
                          'bg-white/5 text-text-muted'
                        }`}>
                          {domain.ssl_status || 'none'}
                        </span>
                        {!domain.dns_verification_token && (
                          <span className="text-xs text-text-muted italic">Verify DNS first</span>
                        )}
                      </div>
                    </div>
                    {domain.ssl_status === 'active' && (
                      <div className="mt-3 pt-3 border-t border-white/5 flex items-center gap-2 text-xs text-text-muted">
                        <span>🔐 Issuer: Let's Encrypt / ZeroSSL</span>
                        <span className="mx-1">·</span>
                        <span>Auto-renew: Enabled (Caddy)</span>
                      </div>
                    )}
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={isDeleteModalOpen}
        onCancel={() => setIsDeleteModalOpen(false)}
        onConfirm={handleDelete}
        title={origin?.status === 'pending' ? "Cancel Setup" : "Archive Origin"}
        message={origin ? (origin.status === 'pending' ? `Are you sure you want to cancel the setup of the origin "${origin.label}"?` : `Are you sure you want to archive the origin "${origin.label}"? This will hide it from the active dashboard and put it into cold storage.`) : ''}
        confirmText={origin?.status === 'pending' ? "Cancel Setup" : "Archive Origin"}
        isDanger={true}
      />

      <ConfirmDialog
        open={isRestoreModalOpen}
        onCancel={() => setIsRestoreModalOpen(false)}
        onConfirm={handleRestore}
        title="Restore Origin"
        message={`Are you sure you want to restore the origin "${origin.label}"? This will return it to active service.`}
        confirmText="Restore Origin"
        isDanger={false}
      />
    </div>
  );
};

export default OriginDetail;
