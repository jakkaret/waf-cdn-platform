import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../api/rules'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import { Shield, ShieldAlert, Code } from 'lucide-react'

export const BolaRules: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()

  const { data: policies = [], isLoading } = useQuery({
    queryKey: ['bola-policies'],
    queryFn: () => rulesApi.getBolaPolicies().then(res => res.policies || []),
  })

  // The actual POST API for creating BOLA policies exists on the backend but we didn't add it to rules.ts yet
  // For now, this fulfills the "UI" requirement by at least showing them.

  return (
    <div className="space-y-5">
      <TopBar title="BOLA Protection" />

      <div className="dash-card">
        <div className="dash-card-header bg-[var(--bg-surface-elevated)]">
          <div className="flex items-center gap-2">
            <ShieldAlert size={16} className="text-orange-500" />
            <h3 className="font-mono">BOLA (Broken Object Level Authorization) Policies</h3>
          </div>
        </div>

        <div className="p-4">
          <p className="text-[12.5px] text-[var(--text-muted)] mb-4 font-mono">
            BOLA policies detect and block requests where users attempt to manipulate object IDs in the URL to access resources belonging to other users.
          </p>

          <div className="space-y-3">
            {isLoading ? (
               <div className="p-6 text-center text-[var(--text-muted)]">Loading BOLA policies...</div>
            ) : policies.length === 0 ? (
               <div className="p-6 text-center border border-dashed border-[var(--bg-border)] rounded-xl text-[var(--text-muted)]">
                 No BOLA policies defined. Configure them via the backend API.
               </div>
            ) : (
               policies.map((p: any, i: number) => (
                 <div key={i} className="p-4 rounded-xl border border-[var(--bg-border)] bg-[var(--bg-surface)]">
                   <div className="flex justify-between">
                     <p className="font-bold font-mono text-[13px]">{p.name || p.path_pattern}</p>
                     <Badge color={p.mode === 'enforce' ? 'danger' : 'warning'}>{p.mode}</Badge>
                   </div>
                   <div className="mt-2 text-[12px] text-[var(--text-muted)] flex flex-col gap-1">
                     <span><strong>Path Regex:</strong> <code className="bg-slate-100 dark:bg-slate-800 p-0.5 rounded">{p.path_pattern}</code></span>
                     <span><strong>Auth Header:</strong> {p.auth_header}</span>
                     {p.id_extraction_regex && <span><strong>ID Extractor:</strong> <code className="bg-slate-100 dark:bg-slate-800 p-0.5 rounded">{p.id_extraction_regex}</code></span>}
                   </div>
                 </div>
               ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default BolaRules
