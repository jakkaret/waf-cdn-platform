import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { getOrigins } from '../api/origins';
import { Card } from '../components/ui/Card';
import { HealthDot } from '../components/ui/HealthDot';
import { EmptyState } from '../components/ui/EmptyState';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';
import { Button } from '../components/ui/Button';
import { AddOriginModal } from '../components/AddOriginModal';
import { Origin } from '../types';

const Origins: React.FC = () => {
  const navigate = useNavigate();
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);

  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ['origins'],
    queryFn: getOrigins,
    refetchInterval: 30000,
  });

  const origins = data?.data?.origins || [];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-text-primary">My Origins</h1>
        <Button variant="primary" onClick={() => setIsAddModalOpen(true)}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mr-2">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Add Origin
        </Button>
      </div>

      {isLoading ? (
        <div className="py-20">
          <LoadingSpinner size="lg" />
        </div>
      ) : isError ? (
        <Card className="p-8">
          <EmptyState 
            title="Failed to load origins" 
            subtitle="Please try again later or contact support." 
          />
        </Card>
      ) : origins.length === 0 ? (
        <Card className="p-12 border border-bg-border bg-bg-surface2/30">
          <EmptyState 
            title="No Origins Yet" 
            subtitle="Click the 'Add Origin' button to start managing your web servers behind our WAF." 
          />
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {origins.map((origin: Origin) => (
            <Card key={origin.origin_id} className="flex flex-col h-full cursor-pointer hover:brightness-110 transition-all" onClick={() => navigate(`/origins/${origin.origin_id}`)}>
              <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-2">
                  <HealthDot status={origin.health === 'up' ? 'online' : origin.health === 'down' ? 'offline' : 'degraded'} />
                  <h3 className="font-semibold text-lg text-text-primary">{origin.label}</h3>
                </div>
                <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                  origin.status === 'active' ? 'bg-[#e6f9f0]/10 text-[#68d391]' :
                  origin.status === 'pending' ? 'bg-[#fff4e5]/10 text-[#f6ad55]' :
                  'bg-[#fff5f5]/10 text-[#fc8181]'
                }`}>
                  {origin.status.toUpperCase()}
                </span>
              </div>
              
              <div className="flex-1 space-y-3 mb-6">
                <div className="text-sm text-text-muted">
                  <div className="flex items-center gap-2">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10"/>
                      <path d="M2 12h20"/>
                      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                    </svg>
                    {origin.ip}:{origin.port}
                  </div>
                </div>
                <div className="text-sm text-text-muted">
                  <div className="flex items-center gap-2">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <rect x="3" y="4" width="18" height="18" rx="2" ry="2"/>
                      <line x1="16" y1="2" x2="16" y2="6"/>
                      <line x1="8" y1="2" x2="8" y2="6"/>
                      <line x1="3" y1="10" x2="21" y2="10"/>
                    </svg>
                    Added {new Date(origin.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
              
              <div className="mt-auto pt-4 border-t border-bg-border text-center">
                <span className="text-sm font-medium text-accent hover:text-accent-light transition-colors">
                  View Details &rarr;
                </span>
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
    </div>
  );
};

export default Origins;
