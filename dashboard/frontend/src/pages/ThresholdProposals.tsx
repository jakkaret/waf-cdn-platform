import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { thresholdProposalsApi, ThresholdProposal } from '../api/thresholdProposals'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import { RefreshCw, Check, X, ShieldAlert, Sparkles, RotateCcw } from 'lucide-react'

export const ThresholdProposals: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()
  const [isGenerating, setIsGenerating] = useState(false)

  const { data: proposals = [], isLoading } = useQuery({
    queryKey: ['threshold-proposals'],
    queryFn: () => thresholdProposalsApi.getProposals(),
  })

  const generateMutation = useMutation({
    mutationFn: () => thresholdProposalsApi.generateProposal(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['threshold-proposals'] })
      if (!data.proposal) {
         toast(data.message || 'No safe proposal generated (metrics look fine)', { icon: 'ℹ️' })
      } else {
         toast.success('Generated new tuning proposal')
      }
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Generation failed'),
    onSettled: () => setIsGenerating(false)
  })

  const approveMutation = useMutation({
    mutationFn: (id: string) => thresholdProposalsApi.approveProposal(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threshold-proposals'] })
      toast.success('Proposal Approved. Global Threshold updated.')
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Approval failed'),
  })

  const rejectMutation = useMutation({
    mutationFn: (id: string) => thresholdProposalsApi.rejectProposal(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threshold-proposals'] })
      toast.success('Proposal Rejected')
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Rejection failed'),
  })

  const rollbackMutation = useMutation({
    mutationFn: (id: string) => thresholdProposalsApi.rollbackProposal(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['threshold-proposals'] })
      toast.success('Proposal rolled back. Previous threshold restored.')
    },
    onError: (err: any) => toast.error(err?.response?.data?.detail || 'Rollback failed'),
  })

  const handleGenerate = () => {
    setIsGenerating(true)
    generateMutation.mutate()
  }

  return (
    <div className="space-y-5">
      <TopBar title="Self-Tuning Anomaly Proposals" />

      <div className="dash-card">
        <div className="dash-card-header flex justify-between items-center bg-[var(--bg-surface-elevated)]">
          <div className="flex items-center gap-2">
            <Sparkles size={16} className="text-orange-500" />
            <h3 className="font-mono">AI Tuning Proposals</h3>
          </div>
          <Button onClick={handleGenerate} disabled={isGenerating} isLoading={isGenerating}>
            <RefreshCw size={14} className={isGenerating ? 'animate-spin' : ''} />
            Generate Proposal
          </Button>
        </div>

        <div className="p-4">
          <p className="text-[12.5px] text-[var(--text-muted)] mb-4 font-mono">
            The Self-Tuning system analyzes anomaly block-rates and suggests threshold adjustments to prevent false positives or increase security.
          </p>

          <div className="space-y-3">
            {isLoading ? (
               <div className="p-6 text-center text-[var(--text-muted)]">Loading proposals...</div>
            ) : proposals.length === 0 ? (
               <div className="p-6 text-center border border-dashed border-[var(--bg-border)] rounded-xl text-[var(--text-muted)]">
                 No tuning proposals found. Generate one to see AI recommendations.
               </div>
            ) : (
               proposals.map(p => (
                 <div key={p.proposal_id} className="p-4 rounded-xl border border-[var(--bg-border)] bg-[var(--bg-surface)] flex justify-between items-center">
                   <div>
                     <div className="flex items-center gap-2 mb-1">
                       <span className="font-mono text-[11px] text-orange-500">{p.proposal_id}</span>
                       <Badge color={p.status === 'pending' ? 'warning' : p.status === 'approved' ? 'success' : p.status === 'rolled_back' ? 'gray' : 'danger'}>
                         {p.status}
                       </Badge>
                     </div>
                     <p className="text-[13px] font-bold m-0">Threshold: {p.current_threshold} &rarr; <span className="text-emerald-500">{p.proposed_threshold}</span></p>
                     <p className="text-[12px] text-[var(--text-muted)] mt-1">{p.reason}</p>
                   </div>
                   {p.status === 'pending' && isAdmin && (
                     <div className="flex gap-2">
                       <Button color="ghost" onClick={() => rejectMutation.mutate(p.proposal_id)} isLoading={rejectMutation.isPending}>
                         <X size={14} /> Reject
                       </Button>
                       <Button color="brand" onClick={() => approveMutation.mutate(p.proposal_id)} isLoading={approveMutation.isPending}>
                         <Check size={14} /> Approve
                       </Button>
                     </div>
                   )}
                   {p.status === 'approved' && isAdmin && (
                     <Button color="ghost" onClick={() => rollbackMutation.mutate(p.proposal_id)} isLoading={rollbackMutation.isPending}>
                       <RotateCcw size={14} /> Rollback
                     </Button>
                   )}
                 </div>
               ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default ThresholdProposals
