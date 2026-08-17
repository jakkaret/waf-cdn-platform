import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { mlRulesApi } from '../api/mlRules'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Card, CardHeader } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import toast from 'react-hot-toast'
import { MLPendingRule } from '../types'
import { Sparkles, Check, X, Clock, AlertTriangle, Code, Trash2 } from 'lucide-react'

export const MLRules: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'pending' | 'approved' | 'rejected'>('pending')
  const [rejectReason, setRejectReason] = useState('')
  const [rejectingId, setRejectingId] = useState<string | null>(null)

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ['ml-rules', activeTab],
    queryFn: () => mlRulesApi.listRules(activeTab),
    refetchInterval: 10000,
  })

  const approveMutation = useMutation({
    mutationFn: (id: string) => mlRulesApi.approveRule(id),
    onSuccess: () => {
      toast.success('Rule approved and deployed successfully')
      queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to approve rule')
  })

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string, reason: string }) => mlRulesApi.rejectRule(id, reason),
    onSuccess: () => {
      toast.success('Rule rejected')
      setRejectingId(null)
      setRejectReason('')
      queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to reject rule')
  })

  const handleApprove = (id: string) => {
    if (!isAdmin) {
      toast.error('Admin privileges required to approve rules')
      return
    }
    approveMutation.mutate(id)
  }

  const handleReject = (id: string) => {
    if (!isAdmin) {
      toast.error('Admin privileges required to reject rules')
      return
    }
    rejectMutation.mutate({ id, reason: rejectReason })
  }

  return (
    <div>
      <TopBar 
        title="ML Generated Rules" 
        subtitle="Review and approve rules suggested by the ML anomaly detection model" 
        action={
          <div className="flex bg-white/[0.03] p-1 rounded-[10px] border border-white/[0.05]">
            {(['pending', 'approved', 'rejected'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-4 py-1.5 text-[12px] font-semibold rounded-lg transition-all duration-200 capitalize ${
                  activeTab === tab
                    ? 'bg-accent/[0.12] text-accent-light shadow-[0_0_12px_rgba(102,126,234,0.1)]'
                    : 'text-white/25 hover:text-white/45'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        }
      />

      <div className="space-y-6">
        {isLoading && (
          <div className="text-center py-10 text-white/40">Loading rules...</div>
        )}

        {!isLoading && rules.length === 0 && (
          <div className="text-center py-16 bg-white/[0.02] border border-white/[0.04] rounded-2xl">
            <Sparkles size={40} className="mx-auto mb-4 text-white/10" />
            <h3 className="text-lg font-bold text-white/60 mb-2">No {activeTab} rules</h3>
            <p className="text-sm text-white/30">
              {activeTab === 'pending' ? 'ML model has not generated any new rules recently.' : `There are no ${activeTab} rules.`}
            </p>
          </div>
        )}

        {rules.map((rule, idx) => (
          <Card key={rule.rule_id} className={`animate-fade-in-up stagger-${(idx % 8) + 1} overflow-hidden`} noPadding>
            {/* Top accent line based on status */}
            <div className={`h-1 w-full ${
              rule.status === 'pending' ? 'bg-warning' : 
              rule.status === 'approved' ? 'bg-success' : 'bg-danger'
            }`} />
            
            <div className="p-6">
              <div className="flex justify-between items-start mb-6">
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center shadow-glow ${
                    rule.status === 'pending' ? 'bg-warning/[0.1] text-warning' : 
                    rule.status === 'approved' ? 'bg-success/[0.1] text-success' : 'bg-danger/[0.1] text-danger'
                  }`}>
                    {rule.status === 'pending' ? <Clock size={20} /> : 
                     rule.status === 'approved' ? <Check size={20} /> : <X size={20} />}
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white/90 font-heading mb-1 flex items-center gap-2">
                      <Sparkles size={16} className="text-accent-light" />
                      {rule.attack_type}
                    </h3>
                    <p className="text-[12px] text-white/40 font-medium">
                      Generated at: {new Date(rule.created_at).toLocaleString()}
                    </p>
                  </div>
                </div>
                
                {rule.status === 'pending' && (
                  <Badge color="warning" dot>PENDING APPROVAL</Badge>
                )}
                {rule.status === 'approved' && (
                  <div className="text-right">
                    <Badge color="success" dot className="mb-1">DEPLOYED: ID {rule.deployed_rule_id}</Badge>
                    <p className="text-[10px] text-white/30">by {rule.reviewed_by}</p>
                  </div>
                )}
                {rule.status === 'rejected' && (
                  <div className="text-right">
                    <Badge color="danger" dot className="mb-1">REJECTED</Badge>
                    <p className="text-[10px] text-white/30">by {rule.reviewed_by}</p>
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div className="space-y-4">
                  <div className="bg-white/[0.02] border border-white/[0.04] p-4 rounded-xl">
                    <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.08em] mb-2">Detection Details</p>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-[11px] text-white/40 mb-1">Pattern</p>
                        <p className="text-[13px] font-mono text-accent-light break-all">{rule.pattern}</p>
                      </div>
                      <div>
                        <p className="text-[11px] text-white/40 mb-1">Variable</p>
                        <p className="text-[13px] font-mono text-white/80">{rule.variable}</p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="bg-white/[0.02] border border-white/[0.04] p-4 rounded-xl">
                    <p className="text-[10px] font-bold text-white/20 uppercase tracking-[0.08em] mb-2">Source Trigger</p>
                    <div className="flex items-center gap-2 text-[13px]">
                      <Badge color="gray">{rule.source_method}</Badge>
                      <span className="text-white/60 font-mono truncate">{rule.source_url}</span>
                    </div>
                  </div>
                </div>

                <div className="bg-[#0a0d14] border border-white/[0.06] rounded-xl overflow-hidden flex flex-col">
                  <div className="bg-white/[0.02] border-b border-white/[0.04] px-4 py-2 flex items-center gap-2">
                    <Code size={14} className="text-white/40" />
                    <span className="text-[11px] font-bold text-white/40 uppercase tracking-widest">SecRule Preview</span>
                  </div>
                  <div className="p-4 overflow-x-auto flex-1 text-[12px] font-mono text-white/60 leading-relaxed">
                    <pre>{rule.secrule_template.replace('{RULE_ID}', rule.deployed_rule_id ? String(rule.deployed_rule_id) : 'PENDING_ID')}</pre>
                  </div>
                </div>
              </div>

              {rule.status === 'rejected' && rule.reject_reason && (
                <div className="mb-6 p-3 rounded-lg bg-danger/[0.05] border border-danger/[0.1] flex gap-3 items-start">
                  <AlertTriangle size={16} className="text-danger mt-0.5" />
                  <div>
                    <p className="text-[12px] font-bold text-danger/80">Reject Reason</p>
                    <p className="text-[13px] text-white/60 mt-1">{rule.reject_reason}</p>
                  </div>
                </div>
              )}

              {rule.status === 'pending' && isAdmin && (
                <div className="flex items-center gap-3 pt-4 border-t border-white/[0.04]">
                  {rejectingId === rule.rule_id ? (
                    <div className="flex-1 flex gap-3 animate-fade-in">
                      <input 
                        type="text" 
                        placeholder="Reason for rejection (optional)"
                        value={rejectReason}
                        onChange={e => setRejectReason(e.target.value)}
                        className="flex-1 bg-white/[0.02] border border-white/[0.1] rounded-lg px-4 py-2 text-[13px] text-white outline-none focus:border-accent/40 transition-colors"
                        autoFocus
                      />
                      <Button variant="danger" onClick={() => handleReject(rule.rule_id)} isLoading={rejectMutation.isPending}>
                        Confirm Reject
                      </Button>
                      <Button variant="ghost" onClick={() => { setRejectingId(null); setRejectReason(''); }}>
                        Cancel
                      </Button>
                    </div>
                  ) : (
                    <div className="flex-1 flex gap-3 justify-end">
                      <Button variant="outline" className="border-danger/30 text-danger hover:bg-danger/[0.05] hover:border-danger/50" onClick={() => setRejectingId(rule.rule_id)}>
                        <X size={16} /> Reject
                      </Button>
                      <Button onClick={() => handleApprove(rule.rule_id)} isLoading={approveMutation.isPending}>
                        <Check size={16} /> Approve & Deploy
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}

export default MLRules
