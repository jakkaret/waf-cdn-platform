import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getOrigin, deleteOrigin } from '../api/origins';
import { getDomains, deleteDomain } from '../api/domains';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { HealthDot } from '../components/ui/HealthDot';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { EmptyState } from '../components/ui/EmptyState';
import { DomainSetupWizard } from '../components/DomainSetupWizard';
import { toast } from 'react-hot-toast';
import { Domain } from '../types';

const OriginDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'overview' | 'domains' | 'waf' | 'ssl'>('overview');
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isDomainWizardOpen, setIsDomainWizardOpen] = useState(false);
  const [domainToDelete, setDomainToDelete] = useState<string | null>(null);

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

  const origin = data?.data || null;
  const domains = domainsData?.data?.domains || [];

  const handleDelete = async () => {
    try {
      await deleteOrigin(id!);
      toast.success('Origin deleted successfully');
      navigate('/origins');
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to delete origin');
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
          <Button variant="danger" onClick={() => setIsDeleteModalOpen(true)}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-2">
              <polyline points="3 6 5 6 21 6"></polyline>
              <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
            </svg>
            Delete Origin
          </Button>
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
                         <Button variant="outline" size="sm" onClick={() => setIsDomainWizardOpen(true)}>
                           Verify DNS
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
          <Card className="p-12 text-center border-dashed">
            <h3 className="text-lg font-medium text-text-primary mb-2">WAF Rules</h3>
            <p className="text-text-muted max-w-md mx-auto mb-6">Customize ModSecurity paranoia level and custom rules for this specific origin.</p>
            <Button variant="secondary" disabled>Available in Phase 4</Button>
          </Card>
        )}

        {activeTab === 'ssl' && (
          <Card className="p-12 text-center border-dashed">
            <h3 className="text-lg font-medium text-text-primary mb-2">SSL Certificates</h3>
            <p className="text-text-muted max-w-md mx-auto mb-6">Manage Let's Encrypt certificates and auto-renewal settings.</p>
            <Button variant="secondary" disabled>Available in Phase 3</Button>
          </Card>
        )}
      </div>

      <ConfirmDialog
        open={isDeleteModalOpen}
        onCancel={() => setIsDeleteModalOpen(false)}
        onConfirm={handleDelete}
        title="Delete Origin"
        message={`Are you sure you want to delete the origin "${origin.label}"? This action cannot be undone and will stop traffic routing to this server.`}
        confirmText="Delete Origin"
        isDanger={true}
      />
    </div>
  );
};

export default OriginDetail;
