import React, { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getOrigin, deleteOrigin, restoreOrigin } from '../api/origins'
import { getDomains, deleteDomain, verifyDomain } from '../api/domains'
import { rulesApi } from '../api/rules'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { LoadingSpinner } from '../components/ui/LoadingSpinner'
import { ConfirmDialog } from '../components/ui/ConfirmDialog'
import { EmptyState } from '../components/ui/EmptyState'
import { DomainSetupWizard } from '../components/DomainSetupWizard'
import { toast } from 'react-hot-toast'
import { WafRule, Domain } from '../types'
import {
  ArrowLeft,
  Server,
  Globe,
  Shield,
  Lock,
  Plus,
  Trash2,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Code,
} from 'lucide-react'

export const OriginDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState<'overview' | 'domains' | 'waf' | 'ssl'>('overview')
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [isRestoreModalOpen, setIsRestoreModalOpen] = useState(false)
  const [isDomainWizardOpen, setIsDomainWizardOpen] = useState(false)
  const [domainToDelete, setDomainToDelete] = useState<string | null>(null)
  const [verifyingDomainId, setVerifyingDomainId] = useState<string | null>(null)
  const [showAddRule, setShowAddRule] = useState(false)
  const [newRule, setNewRule] = useState<{
    id: string
    variable: WafRule['variable']
    operator: string
    severity: WafRule['severity']
    message: string
  }>({ id: '', variable: 'REQUEST_URI', operator: '', severity: 'HIGH', message: '' })
  const queryClient = useQueryClient()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['origin', id],
    queryFn: () => getOrigin(id!),
    enabled: !!id,
  })

  const { data: domainsData, refetch: refetchDomains } = useQuery({
    queryKey: ['domains', id],
    queryFn: () => getDomains(id!),
    enabled: !!id,
  })

  const { data: rulesData, isLoading: rulesLoading } = useQuery({
    queryKey: ['waf-rules'],
    queryFn: () => rulesApi.getRules(),
  })

  const deleteRuleMutation = useMutation({
    mutationFn: (ruleId: string) => rulesApi.deleteRule(ruleId),
    onSuccess: () => {
      toast.success('Rule deleted')
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
    },
    onError: () => toast.error('Failed to delete rule'),
  })

  const createRuleMutation = useMutation({
    mutationFn: (rule: typeof newRule) => rulesApi.createRule(rule),
    onSuccess: () => {
      toast.success('Rule created successfully')
      queryClient.invalidateQueries({ queryKey: ['waf-rules'] })
      setShowAddRule(false)
      setNewRule({ id: '', variable: 'REQUEST_URI', operator: '', severity: 'HIGH', message: '' })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to create rule'),
  })

  const origin = data?.data || null
  const domains = domainsData?.data?.domains || []

  const handleDelete = async () => {
    const isPending = origin?.status === 'pending'
    try {
      await deleteOrigin(id!)
      toast.success(isPending ? 'Origin setup cancelled' : 'Origin archived successfully')
      navigate('/origins')
    } catch (error: any) {
      toast.error(error.response?.data?.detail || (isPending ? 'Failed to cancel setup' : 'Failed to archive origin'))
    }
  }

  const handleRestore = async () => {
    try {
      await restoreOrigin(id!)
      toast.success('Origin restored successfully')
      queryClient.invalidateQueries({ queryKey: ['origin', id] })
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to restore origin')
    } finally {
      setIsRestoreModalOpen(false)
    }
  }

  const handleDeleteDomain = async () => {
    if (!domainToDelete) return
    try {
      await deleteDomain(id!, domainToDelete)
      toast.success('Domain deleted successfully')
      refetchDomains()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to delete domain')
    } finally {
      setDomainToDelete(null)
    }
  }

  const handleVerifyDomain = async (domainId: string) => {
    setVerifyingDomainId(domainId)
    try {
      const res = await verifyDomain(id!, domainId)
      if (res.data?.status === 'success') {
        toast.success('Domain DNS verified successfully!')
        refetchDomains()
      } else {
        toast.error(res.data?.message || 'DNS verification records not detected yet')
      }
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'DNS verification failed')
    } finally {
      setVerifyingDomainId(null)
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center py-24 text-[var(--text-muted)] font-mono text-[12px]">
        <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
        Loading origin configuration...
      </div>
    )
  }

  if (isError || !origin) {
    return (
      <div className="p-6">
        <div className="dash-card p-12 text-center text-[var(--text-muted)] space-y-3 font-mono">
          <p>Failed to load origin server details.</p>
          <Button variant="secondary" onClick={() => navigate('/origins')}>
            Back to Origin Pools
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-6xl mx-auto animate-fade-in">
      {/* Top Header Card */}
      <div className="dash-card p-5 sm:p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/origins')}
            className="p-2 bg-[var(--bg-primary)] rounded-lg text-[var(--text-muted)] hover:text-[var(--text-primary)] border border-[var(--bg-border)] hover:bg-[var(--bg-hover)] transition-colors cursor-pointer"
            title="Back to Origins"
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-[20px] font-bold text-[var(--text-primary)] font-mono m-0">
                {origin.label}
              </h1>
              <Badge
                color={
                  origin.status === 'active'
                    ? 'success'
                    : origin.status === 'pending'
                    ? 'warning'
                    : 'gray'
                }
                dot
              >
                {origin.status.toUpperCase()}
              </Badge>
            </div>
            <p className="text-[12px] font-mono text-[var(--text-muted)] mt-1 m-0">
              Proxy Upstream: {origin.ip}:{origin.port}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {origin.status === 'archived' ? (
            <Button
              variant="brand"
              onClick={() => setIsRestoreModalOpen(true)}
              icon={<RotateCcw size={14} />}
            >
              Restore Origin
            </Button>
          ) : origin.status === 'pending' ? (
            <Button
              variant="outline"
              onClick={() => setIsDeleteModalOpen(true)}
            >
              Cancel Setup
            </Button>
          ) : (
            <Button
              variant="danger"
              onClick={() => setIsDeleteModalOpen(true)}
              icon={<Trash2 size={14} />}
            >
              Archive Origin
            </Button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 border-b border-[var(--bg-border)] font-mono text-[12.5px] overflow-x-auto">
        {[
          { id: 'overview', label: 'Pool Overview', icon: <Server size={14} /> },
          { id: 'domains', label: 'Domains & DNS', icon: <Globe size={14} /> },
          { id: 'waf', label: 'WAF Policies', icon: <Shield size={14} /> },
          { id: 'ssl', label: 'SSL Certificates', icon: <Lock size={14} /> },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`flex items-center gap-2 px-4 py-2.5 font-semibold border-b-2 whitespace-nowrap transition-all cursor-pointer ${
              activeTab === tab.id
                ? 'border-orange-500 text-orange-500'
                : 'border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
            }`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Tab Panels */}
      <div className="py-2">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="dash-card p-5 space-y-4">
              <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)]">
                Upstream Target Info
              </h3>
              <div className="space-y-3 font-mono text-[12px]">
                <div className="flex justify-between py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">Server Label</span>
                  <span className="font-bold text-[var(--text-primary)]">{origin.label}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">Upstream IP</span>
                  <span className="text-orange-500 font-bold">{origin.ip}</span>
                </div>
                <div className="flex justify-between py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">Proxy Port</span>
                  <span className="text-[var(--text-primary)]">{origin.port}</span>
                </div>
                <div className="flex justify-between py-1.5">
                  <span className="text-[var(--text-muted)]">Registered Date</span>
                  <span className="text-[var(--text-secondary)]">
                    {new Date(origin.created_at).toLocaleString()}
                  </span>
                </div>
              </div>
            </div>

            <div className="dash-card p-5 space-y-4">
              <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)]">
                Security & Protection Status
              </h3>
              <div className="space-y-3 font-mono text-[12px]">
                <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">ModSecurity WAF</span>
                  <Badge color="success">ENABLED (CRS 3.3)</Badge>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">SSL / TLS Termination</span>
                  <Badge color="success">AUTO CADDY</Badge>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">Rate Limiting</span>
                  <Badge color="brand">100 REQ/MIN</Badge>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-[var(--text-muted)]">Attached Domains</span>
                  <span className="font-bold text-[var(--text-primary)]">{domains.length} Domain(s)</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'domains' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                  Custom Domain Bindings
                </h2>
                <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                  Point your DNS CNAME / A records to CloudWAF edge proxy IP
                </p>
              </div>
              <Button variant="brand" onClick={() => setIsDomainWizardOpen(true)} icon={<Plus size={14} />}>
                Add Domain
              </Button>
            </div>

            {domains.length === 0 ? (
              <div className="dash-card p-12 text-center space-y-3 border-dashed">
                <Globe size={36} className="mx-auto text-[var(--text-muted)] opacity-40" />
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
                  No Custom Domains Connected
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0 font-mono">
                  Attach a custom domain to route live visitors through CloudWAF.
                </p>
                <Button variant="brand" onClick={() => setIsDomainWizardOpen(true)}>
                  Add Custom Domain
                </Button>
              </div>
            ) : (
              <div className="space-y-3">
                {domains.map((domain: Domain) => (
                  <div
                    key={domain.domain_id}
                    className="dash-card p-4 sm:p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
                  >
                    <div>
                      <div className="flex items-center gap-2.5">
                        <h3 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                          {domain.domain_name}
                        </h3>
                        <Badge
                          color={
                            domain.verification_status === 'verified'
                              ? 'success'
                              : domain.verification_status === 'pending'
                              ? 'warning'
                              : 'danger'
                          }
                          size="sm"
                        >
                          {domain.verification_status.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 mt-1">
                        Bound to origin {origin.ip}:{origin.port} • Added{' '}
                        {new Date(domain.created_at).toLocaleDateString()}
                      </p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {domain.verification_status !== 'verified' && (
                        <Button
                          variant="secondary"
                          size="sm"
                          onClick={() => handleVerifyDomain(domain.domain_id)}
                          disabled={verifyingDomainId === domain.domain_id}
                          isLoading={verifyingDomainId === domain.domain_id}
                        >
                          Verify DNS
                        </Button>
                      )}
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => setDomainToDelete(domain.domain_id)}
                        icon={<Trash2 size={13} />}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <DomainSetupWizard
              open={isDomainWizardOpen}
              onClose={() => setIsDomainWizardOpen(false)}
              onSuccess={() => {
                setIsDomainWizardOpen(false)
                refetchDomains()
              }}
              originId={id!}
            />

            <ConfirmDialog
              open={!!domainToDelete}
              onCancel={() => setDomainToDelete(null)}
              onConfirm={handleDeleteDomain}
              title="Remove Domain Binding"
              message="Are you sure you want to remove this domain? Web traffic through this hostname will halt immediately."
              confirmText="Remove Domain"
              isDanger={true}
            />
          </div>
        )}

        {activeTab === 'waf' && (
          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <div>
                <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                  WAF Security Policies
                </h2>
                <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                  ModSecurity CRS & custom filtering rules
                </p>
              </div>
              <Button
                variant={showAddRule ? 'secondary' : 'brand'}
                onClick={() => setShowAddRule(!showAddRule)}
              >
                {showAddRule ? 'Cancel' : '+ Add SecRule'}
              </Button>
            </div>

            {showAddRule && (
              <div className="dash-card p-5 border-l-2 border-l-orange-500 bg-orange-500/[0.02]">
                <h3 className="text-[13.5px] font-bold text-orange-500 font-mono mb-4">
                  Define New ModSecurity Rule
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px]">
                  <div>
                    <label className="text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block uppercase">
                      Rule ID
                    </label>
                    <input
                      className="w-full dash-input font-mono"
                      placeholder="e.g. 100010"
                      value={newRule.id}
                      onChange={(e) => setNewRule((r) => ({ ...r, id: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block uppercase">
                      Variable
                    </label>
                    <select
                      className="w-full dash-input font-mono"
                      value={newRule.variable}
                      onChange={(e) =>
                        setNewRule((r) => ({ ...r, variable: e.target.value as WafRule['variable'] }))
                      }
                    >
                      <option value="REQUEST_URI">REQUEST_URI</option>
                      <option value="ARGS">ARGS</option>
                      <option value="REQUEST_HEADERS">REQUEST_HEADERS</option>
                      <option value="REQUEST_BODY">REQUEST_BODY</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block uppercase">
                      Pattern Operator
                    </label>
                    <input
                      className="w-full dash-input font-mono"
                      placeholder="e.g. @rx (select|union)"
                      value={newRule.operator}
                      onChange={(e) => setNewRule((r) => ({ ...r, operator: e.target.value }))}
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block uppercase">
                      Severity
                    </label>
                    <select
                      className="w-full dash-input font-mono"
                      value={newRule.severity}
                      onChange={(e) =>
                        setNewRule((r) => ({ ...r, severity: e.target.value as WafRule['severity'] }))
                      }
                    >
                      <option value="CRITICAL">CRITICAL (403)</option>
                      <option value="HIGH">HIGH (403)</option>
                      <option value="MEDIUM">MEDIUM (Warn)</option>
                      <option value="LOW">LOW (Notice)</option>
                    </select>
                  </div>
                  <div className="md:col-span-2">
                    <label className="text-[11px] font-bold font-mono text-[var(--text-muted)] mb-1 block uppercase">
                      Rule Message
                    </label>
                    <input
                      className="w-full dash-input font-mono"
                      placeholder="e.g. Block SQL injection payload"
                      value={newRule.message}
                      onChange={(e) => setNewRule((r) => ({ ...r, message: e.target.value }))}
                    />
                  </div>
                </div>
                <div className="flex justify-end mt-4">
                  <Button
                    variant="brand"
                    onClick={() => createRuleMutation.mutate(newRule)}
                    disabled={!newRule.id || !newRule.operator || !newRule.message || createRuleMutation.isPending}
                    isLoading={createRuleMutation.isPending}
                  >
                    Save Rule
                  </Button>
                </div>
              </div>
            )}

            <div className="dash-card overflow-hidden">
              <div className="overflow-x-auto">
                <table className="dash-table">
                  <thead>
                    <tr>
                      <th>Rule ID</th>
                      <th>Variable</th>
                      <th>Operator</th>
                      <th>Severity</th>
                      <th>Message</th>
                      <th className="text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rulesLoading ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-[var(--text-muted)] font-mono text-[12px]">
                          Loading rules...
                        </td>
                      </tr>
                    ) : !rulesData || rulesData.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-[var(--text-muted)] font-mono text-[12px]">
                          No custom rules configured.
                        </td>
                      </tr>
                    ) : (
                      rulesData.map((rule: WafRule) => (
                        <tr key={rule.id}>
                          <td className="font-mono font-bold text-orange-500">{rule.id}</td>
                          <td>
                            <Badge color="gray">{rule.variable}</Badge>
                          </td>
                          <td className="font-mono text-[11.5px] max-w-[200px] truncate">{rule.operator}</td>
                          <td>
                            <Badge color={rule.severity === 'CRITICAL' ? 'danger' : 'warning'}>
                              {rule.severity}
                            </Badge>
                          </td>
                          <td className="text-[12px] text-[var(--text-secondary)]">{rule.message}</td>
                          <td className="text-right">
                            <button
                              onClick={() => deleteRuleMutation.mutate(rule.id)}
                              className="text-red-500 hover:text-red-400 font-mono text-[11px] font-semibold cursor-pointer"
                            >
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'ssl' && (
          <div className="space-y-4">
            <div>
              <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                SSL / TLS Certificates
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                Automated ACME provisioning via Let&apos;s Encrypt and ZeroSSL
              </p>
            </div>

            {domains.length === 0 ? (
              <div className="dash-card p-12 text-center space-y-2 border-dashed">
                <Lock size={36} className="mx-auto text-[var(--text-muted)] opacity-40" />
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
                  No Domains to Secure
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0 font-mono">
                  Connect and verify a custom domain first to enable SSL certificates.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {domains.map((domain: Domain) => (
                  <div
                    key={domain.domain_id}
                    className="dash-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
                  >
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-500 flex items-center justify-center">
                        <Lock size={18} />
                      </div>
                      <div>
                        <p className="font-bold text-[14px] text-[var(--text-primary)] font-mono m-0">
                          {domain.domain_name}
                        </p>
                        <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                          TLS 1.3 • Issuer: Let&apos;s Encrypt / ZeroSSL (Auto-Renew)
                        </p>
                      </div>
                    </div>

                    <Badge color={domain.ssl_status === 'active' ? 'success' : 'warning'}>
                      {(domain.ssl_status || 'ACTIVE').toUpperCase()}
                    </Badge>
                  </div>
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
        title={origin?.status === 'pending' ? 'Cancel Setup' : 'Archive Origin'}
        message={
          origin
            ? origin.status === 'pending'
              ? `Are you sure you want to cancel the setup of origin "${origin.label}"?`
              : `Are you sure you want to archive origin "${origin.label}"?`
            : ''
        }
        confirmText={origin?.status === 'pending' ? 'Cancel Setup' : 'Archive Origin'}
        isDanger={true}
      />

      <ConfirmDialog
        open={isRestoreModalOpen}
        onCancel={() => setIsRestoreModalOpen(false)}
        onConfirm={handleRestore}
        title="Restore Origin"
        message={`Are you sure you want to restore origin "${origin.label}" back to active service?`}
        confirmText="Restore Origin"
        isDanger={false}
      />
    </div>
  )
}

export default OriginDetail
