import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { rulesApi } from '../api/rules'
import { useAuthStore } from '../store/authStore'
import { TopBar } from '../components/layout/TopBar'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import toast from 'react-hot-toast'
import { WafRule } from '../types'
import { api } from '../api/axios'

export const Rules: React.FC = () => {
  const { user } = useAuthStore()
  const isAdmin = user?.role === 'admin'
  const queryClient = useQueryClient()
  
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<Partial<WafRule> | null>(null)

  const { data: rules = [], isLoading } = useQuery({
    queryKey: ['rules'],
    queryFn: rulesApi.getRules,
  })

  const createMutation = useMutation({
    mutationFn: rulesApi.createRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      setIsModalOpen(false)
      toast.success('Rule created successfully')
    },
    onError: () => toast.error('Failed to create rule')
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string, rule: Partial<WafRule> }) => rulesApi.updateRule(id, rule),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      setIsModalOpen(false)
      toast.success('Rule updated successfully')
    },
    onError: () => toast.error('Failed to update rule')
  })

  const deleteMutation = useMutation({
    mutationFn: rulesApi.deleteRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      toast.success('Rule deleted')
    },
    onError: () => toast.error('Failed to delete rule')
  })

  const syncMutation = useMutation({
    mutationFn: () => api.post('/rules/sync'),
    onSuccess: (res) => {
      const nodes: { region: string; status: string }[] = res.data?.node_results || []
      if (nodes.length > 0) {
        const summary = nodes.map(n => `${n.status === 'synced' ? '✅' : '❌'} ${n.region}`).join('  ')
        toast.success(`Sync complete: ${summary}`, { duration: 5000 })
      } else {
        toast.success('Rules synced to edge nodes')
      }
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Sync failed'),
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!editingRule?.id || !editingRule?.operator || !editingRule?.message) {
      return toast.error('Please fill required fields')
    }
    
    // Check if updating existing or creating new based on if rule existed
    const exists = rules.find(r => r.id === editingRule.id)
    if (exists && editingRule !== exists) { // edit mode is simplified here for demo
      updateMutation.mutate({ id: editingRule.id, rule: editingRule })
    } else {
      createMutation.mutate(editingRule as Omit<WafRule, 'id'> & { id?: string })
    }
  }

  const handleDelete = (id: string) => {
    if (window.confirm('Delete this rule?')) {
      deleteMutation.mutate(id)
    }
  }

  return (
    <div>
      <TopBar 
        title="Custom Rules" 
        subtitle="Manage WAF filtering rules"
        action={isAdmin && (
          <div className="flex gap-2">
            <Button
              variant="secondary"
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
            >
              {syncMutation.isPending ? '⏳ Syncing...' : '🔄 Sync to Edge Nodes'}
            </Button>
            <Button onClick={() => { setEditingRule({}); setIsModalOpen(true) }}>+ Add Rule</Button>
          </div>
        )}
      />

      <Card noPadding>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/5 text-text-muted text-[11px] uppercase tracking-wider">
              <tr>
                <th className="p-4 font-semibold">Rule ID</th>
                <th className="p-4 font-semibold">Variable</th>
                <th className="p-4 font-semibold">Operator</th>
                <th className="p-4 font-semibold">Severity</th>
                <th className="p-4 font-semibold">Message</th>
                {isAdmin && <th className="p-4 font-semibold">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {isLoading ? (
                <tr><td colSpan={6} className="p-8 text-center text-text-muted">Loading rules...</td></tr>
              ) : rules.length === 0 ? (
                <tr><td colSpan={6} className="p-8 text-center text-text-muted">No rules configured</td></tr>
              ) : (
                rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-white/5 transition-colors">
                    <td className="p-4 font-mono text-[13px]">{rule.id}</td>
                    <td className="p-4"><Badge color="gray">{rule.variable}</Badge></td>
                    <td className="p-4 font-mono text-[12px] text-text-muted max-w-[200px] truncate">{rule.operator}</td>
                    <td className="p-4">
                      <Badge color={rule.severity === 'CRITICAL' ? 'danger' : rule.severity === 'HIGH' ? 'warning' : 'brand'}>
                        {rule.severity}
                      </Badge>
                    </td>
                    <td className="p-4 text-text-muted">{rule.message}</td>
                    {isAdmin && (
                      <td className="p-4 space-x-2">
                        <Button variant="outline" size="sm" onClick={() => { setEditingRule(rule); setIsModalOpen(true) }}>Edit</Button>
                        <Button variant="danger" size="sm" onClick={() => handleDelete(rule.id)}>Delete</Button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Basic Modal Implementation */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-lg">
            <h3 className="text-lg font-bold mb-4">{editingRule?.id && rules.find(r=>r.id===editingRule.id) ? 'Edit Rule' : 'Add Rule'}</h3>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm mb-1 text-text-muted">Rule ID</label>
                <input required type="text" className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2 text-sm" value={editingRule?.id || ''} onChange={e => setEditingRule({...editingRule, id: e.target.value})} />
              </div>
              <div>
                <label className="block text-sm mb-1 text-text-muted">Variable</label>
                <select className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2 text-sm" value={editingRule?.variable || 'REQUEST_URI'} onChange={e => setEditingRule({...editingRule, variable: e.target.value as any})}>
                  <option value="REQUEST_URI">REQUEST_URI</option>
                  <option value="ARGS">ARGS</option>
                  <option value="REQUEST_HEADERS">REQUEST_HEADERS</option>
                  <option value="REQUEST_BODY">REQUEST_BODY</option>
                </select>
              </div>
              <div>
                <label className="block text-sm mb-1 text-text-muted">Operator</label>
                <input required type="text" className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2 text-sm" value={editingRule?.operator || ''} onChange={e => setEditingRule({...editingRule, operator: e.target.value})} />
              </div>
              <div>
                <label className="block text-sm mb-1 text-text-muted">Severity</label>
                <select className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2 text-sm" value={editingRule?.severity || 'MEDIUM'} onChange={e => setEditingRule({...editingRule, severity: e.target.value as any})}>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm mb-1 text-text-muted">Message</label>
                <input required type="text" className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2 text-sm" value={editingRule?.message || ''} onChange={e => setEditingRule({...editingRule, message: e.target.value})} />
              </div>
              <div className="flex justify-end gap-2 mt-6">
                <Button variant="ghost" type="button" onClick={() => setIsModalOpen(false)}>Cancel</Button>
                <Button type="submit">Save</Button>
              </div>
            </form>
          </Card>
        </div>
      )}
    </div>
  )
}

export default Rules
