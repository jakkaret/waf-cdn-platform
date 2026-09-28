import React, { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getOrigin, deleteOrigin, restoreOrigin, updateOrigin } from '../api/origins'
import { getDomains, deleteDomain, verifyDomain } from '../api/domains'
import { getCaptchaConfig, updateCaptchaConfig } from '../api/captcha'
import { getOtpConfig, updateOtpConfig } from '../api/otp'
import { getOriginViewers, addOriginViewer, removeOriginViewer } from '../api/origin_viewers'
import { getOriginEditors, addOriginEditor, removeOriginEditor } from '../api/origin_editors'
import { getOriginAuditLog } from '../api/origin_audit_log'
import { createPostmortem, getPostmortems, getPostmortem } from '../api/postmortems'
import { useAuthStore } from '../store/authStore'
import { tunnelConnectivityBadge } from '../lib/tunnelStatus'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { LoadingSpinner } from '../components/ui/LoadingSpinner'
import { ConfirmDialog } from '../components/ui/ConfirmDialog'
import { EmptyState } from '../components/ui/EmptyState'
import { DomainSetupWizard } from '../components/DomainSetupWizard'
import { OriginWafRules } from '../components/OriginWafRules'
import { ShieldActivity } from '../components/ShieldActivity'
import {
  ModeSelector,
  ExcludePathsField,
  OtpAccessField,
  ShieldPresets,
  ShieldPreset,
  ShieldMode,
  OtpAccessMode,
  useShieldImpactCheck,
  OTP_CODE_TTL_OPTIONS,
  OTP_CLEARANCE_OPTIONS,
  withCurrent,
} from '../components/ShieldExtras'
import { toast } from 'react-hot-toast'
import { Domain, CaptchaShieldConfig, OtpShieldConfig } from '../types'
import { parseListInput, formatListInput } from '../lib/captchaForm'
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
  Bot,
  Mail,
  Users,
  FileText,
} from 'lucide-react'

export const OriginDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const currentUser = useAuthStore((s) => s.user)
  const [viewerEmailInput, setViewerEmailInput] = useState('')
  const [editorEmailInput, setEditorEmailInput] = useState('')
  const [activeTab, setActiveTab] = useState<'overview' | 'domains' | 'waf' | 'ssl' | 'shield' | 'team' | 'postmortem'>('overview')
  const [pmStart, setPmStart] = useState('')
  const [pmEnd, setPmEnd] = useState('')
  const [selectedPostmortemId, setSelectedPostmortemId] = useState<string | null>(null)
  const [techTagInput, setTechTagInput] = useState('')
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [isRestoreModalOpen, setIsRestoreModalOpen] = useState(false)
  const [isDomainWizardOpen, setIsDomainWizardOpen] = useState(false)
  const [domainToDelete, setDomainToDelete] = useState<string | null>(null)
  const [verifyingDomainId, setVerifyingDomainId] = useState<string | null>(null)
  const queryClient = useQueryClient()
  const impactCheck = useShieldImpactCheck(id || '')

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

  const { data: captchaData, isLoading: captchaLoading } = useQuery({
    queryKey: ['captcha-shield', id],
    queryFn: () => getCaptchaConfig(id!),
    enabled: !!id,
  })

  const [shieldForm, setShieldForm] = useState<{
    enabled: boolean
    engine: 'native' | 'turnstile'
    loginPathsText: string
    bypassIpsText: string
    powDifficulty: number
    clearanceTtl: number
    mode: ShieldMode
    excludePathsText: string
  } | null>(null)
  const shieldLoadedFor = React.useRef<string | null>(null)

  const remoteShieldConfig = captchaData?.data?.captcha_shield

  // Sync once per origin, not on every refetch, so it never clobbers an
  // in-progress edit with server state (e.g. after a background refetch).
  React.useEffect(() => {
    if (!remoteShieldConfig || shieldLoadedFor.current === id) return
    shieldLoadedFor.current = id!
    setShieldForm({
      enabled: remoteShieldConfig.enabled,
      engine: remoteShieldConfig.engine,
      loginPathsText: formatListInput(remoteShieldConfig.login_paths),
      bypassIpsText: formatListInput(remoteShieldConfig.bypass_ips),
      powDifficulty: remoteShieldConfig.pow_difficulty,
      clearanceTtl: remoteShieldConfig.clearance_ttl,
      mode: remoteShieldConfig.mode ?? 'enforce',
      excludePathsText: formatListInput(remoteShieldConfig.exclude_paths ?? []),
    })
  }, [remoteShieldConfig, id])

  const saveShieldMutation = useMutation({
    mutationFn: (config: CaptchaShieldConfig) => updateCaptchaConfig(id!, config),
    onSuccess: () => {
      toast.success('Bot & Login Shield settings saved')
      queryClient.invalidateQueries({ queryKey: ['captcha-shield', id] })
    },
    onError: (e: any) =>
      toast.error(e.response?.data?.detail || 'Failed to save Bot & Login Shield settings'),
  })

  const handleSaveShield = () => {
    if (!shieldForm) return
    const login_paths = parseListInput(shieldForm.loginPathsText)
    if (login_paths.length === 0) {
      toast.error('Add at least one login path to protect')
      return
    }
    if (login_paths.some((p) => !p.startsWith('/'))) {
      toast.error('Every login path must start with /')
      return
    }
    const exclude_paths = parseListInput(shieldForm.excludePathsText)
    if (exclude_paths.some((p) => !p.startsWith('/'))) {
      toast.error('Every excluded path must start with /')
      return
    }
    const payload: CaptchaShieldConfig = {
      enabled: shieldForm.enabled,
      engine: shieldForm.engine,
      login_paths,
      bypass_ips: parseListInput(shieldForm.bypassIpsText),
      pow_difficulty: shieldForm.powDifficulty,
      clearance_ttl: shieldForm.clearanceTtl,
      mode: shieldForm.mode,
      exclude_paths,
    }
    impactCheck.guard(
      { kind: 'CAPTCHA', enabled: payload.enabled, mode: payload.mode, login_paths, exclude_paths },
      () => saveShieldMutation.mutate(payload),
    )
  }

  // OTP Shield -- sibling of the CAPTCHA state above, same shape throughout.
  const { data: otpData, isLoading: otpLoading } = useQuery({
    queryKey: ['otp-shield', id],
    queryFn: () => getOtpConfig(id!),
    enabled: !!id,
  })

  const [otpForm, setOtpForm] = useState<{
    enabled: boolean
    loginPathsText: string
    bypassIpsText: string
    codeLength: number
    codeTtl: number
    clearanceTtl: number
    mode: ShieldMode
    excludePathsText: string
    accessMode: OtpAccessMode
    allowedEmailsText: string
  } | null>(null)
  const otpLoadedFor = React.useRef<string | null>(null)

  const remoteOtpConfig = otpData?.data?.otp_shield

  React.useEffect(() => {
    if (!remoteOtpConfig || otpLoadedFor.current === id) return
    otpLoadedFor.current = id!
    setOtpForm({
      enabled: remoteOtpConfig.enabled,
      loginPathsText: formatListInput(remoteOtpConfig.login_paths),
      bypassIpsText: formatListInput(remoteOtpConfig.bypass_ips),
      codeLength: remoteOtpConfig.code_length,
      codeTtl: remoteOtpConfig.code_ttl,
      clearanceTtl: remoteOtpConfig.clearance_ttl,
      mode: remoteOtpConfig.mode ?? 'enforce',
      excludePathsText: formatListInput(remoteOtpConfig.exclude_paths ?? []),
      accessMode: remoteOtpConfig.access_mode ?? 'open',
      allowedEmailsText: formatListInput(remoteOtpConfig.allowed_emails ?? []),
    })
  }, [remoteOtpConfig, id])

  const saveOtpMutation = useMutation({
    mutationFn: (config: OtpShieldConfig) => updateOtpConfig(id!, config),
    onSuccess: () => {
      toast.success('OTP Shield settings saved')
      queryClient.invalidateQueries({ queryKey: ['otp-shield', id] })
    },
    onError: (e: any) =>
      toast.error(e.response?.data?.detail || 'Failed to save OTP Shield settings'),
  })

  const handleSaveOtp = () => {
    if (!otpForm) return
    const login_paths = parseListInput(otpForm.loginPathsText)
    if (login_paths.length === 0) {
      toast.error('Add at least one login path to protect')
      return
    }
    if (login_paths.some((p) => !p.startsWith('/'))) {
      toast.error('Every login path must start with /')
      return
    }
    const exclude_paths = parseListInput(otpForm.excludePathsText)
    if (exclude_paths.some((p) => !p.startsWith('/'))) {
      toast.error('Every excluded path must start with /')
      return
    }
    const allowed_emails = parseListInput(otpForm.allowedEmailsText)
    if (otpForm.enabled && otpForm.accessMode === 'allowlist' && allowed_emails.length === 0) {
      toast.error('Add at least one email address or @domain to the allowlist')
      return
    }
    const payload: OtpShieldConfig = {
      enabled: otpForm.enabled,
      login_paths,
      bypass_ips: parseListInput(otpForm.bypassIpsText),
      code_length: otpForm.codeLength,
      code_ttl: otpForm.codeTtl,
      clearance_ttl: otpForm.clearanceTtl,
      channel: 'email',
      mode: otpForm.mode,
      exclude_paths,
      access_mode: otpForm.accessMode,
      allowed_emails,
    }
    impactCheck.guard(
      { kind: 'OTP', enabled: payload.enabled, mode: payload.mode, login_paths, exclude_paths },
      () => saveOtpMutation.mutate(payload),
    )
  }

  // Presets only fill the two forms (always in Log only); the Admin still reviews and saves.
  const [appliedPreset, setAppliedPreset] = useState<string | null>(null)
  const applyPreset = (p: ShieldPreset) => {
    setShieldForm((f) =>
      f
        ? {
            ...f,
            enabled: p.captcha.enabled,
            loginPathsText: formatListInput(p.captcha.login_paths),
            excludePathsText: formatListInput(p.captcha.exclude_paths),
            mode: 'log_only',
          }
        : f,
    )
    setOtpForm((f) =>
      f
        ? {
            ...f,
            enabled: p.otp.enabled,
            loginPathsText: formatListInput(p.otp.login_paths),
            excludePathsText: formatListInput(p.otp.exclude_paths),
            accessMode: p.otp.access_mode,
            clearanceTtl: p.otp.clearance_ttl,
            mode: 'log_only',
          }
        : f,
    )
    setAppliedPreset(p.key)
  }

  const origin = data?.data || null
  const domains = domainsData?.data?.domains || []
  const verifiedDomainCount = domains.filter((d: Domain) => d.verification_status === 'verified').length

  const isOwner = !!origin && !!currentUser && origin.admin_user_id === currentUser.user_id
  // Origin "Admin": the creator or anyone granted Admin (stored as editor_user_ids).
  // The backend gives every Admin the same rights, so the UI gates on this,
  // not on isOwner (creator only).
  const isAdmin = isOwner || (!!origin && !!currentUser && (origin.editor_user_ids ?? []).includes(currentUser.user_id))

  const { data: viewersData, isLoading: viewersLoading } = useQuery({
    queryKey: ['origin-viewers', id],
    queryFn: () => getOriginViewers(id!),
    enabled: !!id && isAdmin,
  })
  const viewers = viewersData?.data?.viewers || []

  const addViewerMutation = useMutation({
    mutationFn: (email: string) => addOriginViewer(id!, email),
    onSuccess: (res) => {
      toast.success(`${res.data.viewer.username || res.data.viewer.email} can now view this origin`)
      setViewerEmailInput('')
      queryClient.invalidateQueries({ queryKey: ['origin-viewers', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to add viewer'),
  })

  const removeViewerMutation = useMutation({
    mutationFn: (viewerId: string) => removeOriginViewer(id!, viewerId),
    onSuccess: () => {
      toast.success('Viewer access removed')
      queryClient.invalidateQueries({ queryKey: ['origin-viewers', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to remove viewer'),
  })

  // Team Workspace (2026-09-22): editors can make routine, reversible
  // changes (origin fields, CAPTCHA/OTP config, domains) but never
  // delete/restore the origin or manage viewers/editors -- that stays
  // owner-only, mirrored exactly from the viewer pattern above.
  const { data: editorsData, isLoading: editorsLoading } = useQuery({
    queryKey: ['origin-editors', id],
    queryFn: () => getOriginEditors(id!),
    enabled: !!id && isAdmin,
  })
  const editors = editorsData?.data?.editors || []

  const addEditorMutation = useMutation({
    mutationFn: (email: string) => addOriginEditor(id!, email),
    onSuccess: (res) => {
      toast.success(`${res.data.editor.username || res.data.editor.email} can now edit this origin`)
      setEditorEmailInput('')
      queryClient.invalidateQueries({ queryKey: ['origin-editors', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to add editor'),
  })

  const removeEditorMutation = useMutation({
    mutationFn: (editorId: string) => removeOriginEditor(id!, editorId),
    onSuccess: () => {
      toast.success('Admin access removed')
      queryClient.invalidateQueries({ queryKey: ['origin-editors', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to remove editor'),
  })

  // Audit log is readable by owner, editor, and viewer alike (backend
  // enforces via verify_origin_access) -- anyone who can already see this
  // origin can see what changed on it and by whom.
  const { data: auditLogData, isLoading: auditLogLoading } = useQuery({
    queryKey: ['origin-audit-log', id],
    queryFn: () => getOriginAuditLog(id!),
    enabled: !!id && activeTab === 'team',
  })
  const auditEvents = auditLogData?.data?.events || []

  // AI Incident Postmortem (2026-09-22): owner-only, matching the backend
  // (a postmortem merges in global-scope audit events an editor/viewer of
  // this one origin has no business seeing).
  const { data: postmortemsData, isLoading: postmortemsLoading } = useQuery({
    queryKey: ['origin-postmortems', id],
    queryFn: () => getPostmortems(id!),
    enabled: !!id && isAdmin && activeTab === 'postmortem',
  })
  const postmortems = postmortemsData?.data?.postmortems || []

  const { data: selectedPostmortemData, isLoading: selectedPostmortemLoading } = useQuery({
    queryKey: ['origin-postmortem', id, selectedPostmortemId],
    queryFn: () => getPostmortem(id!, selectedPostmortemId!),
    enabled: !!id && !!selectedPostmortemId,
  })
  const selectedPostmortem = selectedPostmortemData?.data?.postmortem || null

  const createPostmortemMutation = useMutation({
    mutationFn: () => createPostmortem(id!, pmStart.replace('T', ' ') + ':00', pmEnd.replace('T', ' ') + ':00'),
    onSuccess: (res) => {
      toast.success('สร้างรายงาน Postmortem สำเร็จ')
      queryClient.invalidateQueries({ queryKey: ['origin-postmortems', id] })
      queryClient.setQueryData(['origin-postmortem', id, res.data.postmortem.id], res)
      setSelectedPostmortemId(res.data.postmortem.id)
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to generate postmortem'),
  })

  // CVE Auto-Patch (2026-09-22): feeds POST /api/ml-rules/cve-scan's
  // matching -- self-declared, no real fingerprinting.
  const updateTechTagsMutation = useMutation({
    mutationFn: (tags: string[]) => updateOrigin(id!, { tech_stack_tags: tags }),
    onSuccess: () => {
      toast.success('อัปเดต Tech Stack Tags แล้ว')
      queryClient.invalidateQueries({ queryKey: ['origin', id] })
      setTechTagInput('')
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Failed to update tech stack tags'),
  })

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
          { id: 'shield', label: 'Bot & Login Shield', icon: <Bot size={14} /> },
          { id: 'team', label: 'Team & Audit Log', icon: <Users size={14} /> },
          { id: 'postmortem', label: 'Incident Postmortem', icon: <FileText size={14} /> },
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
                {origin.is_tunnel && (
                  <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                    <span className="text-[var(--text-muted)]">Tunnel Connectivity</span>
                    {(() => {
                      const b = tunnelConnectivityBadge(origin.live_connected)
                      return <Badge color={b.color}>{b.label}</Badge>
                    })()}
                  </div>
                )}
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
                  {/* Was a hardcoded "100 REQ/MIN" -- matched only the
                      global fallback default (api/limiter.py), not the
                      per-rule-configurable real values (see
                      RateLimiting.tsx), and even that fallback's real
                      window is 10s not 60s. No per-origin rate-limit value
                      is fetched on this page, so this states what's true
                      without a specific number. */}
                  <Badge color="brand">ENABLED</Badge>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-[var(--text-muted)]">Attached Domains</span>
                  <span className="font-bold text-[var(--text-primary)]">{domains.length} Domain(s)</span>
                </div>
              </div>
            </div>

            {isAdmin && (
              <div className="dash-card p-5 space-y-4 md:col-span-2">
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)]">
                  Tech Stack Tags
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  Self-declared, not auto-detected. Feeds CVE Auto-Patch: a scan matches these
                  tags against the real NVD CVE feed and drafts a proposal into the ML Anomaly
                  Rules queue for review -- it never applies anything automatically.
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={techTagInput}
                    onChange={(e) => setTechTagInput(e.target.value)}
                    onKeyDown={(e) => {
                      // isPending guard matches the Add Tag button and the
                      // remove buttons below -- without it, two fast Enter
                      // presses fire two updateOrigin calls built off the
                      // same stale origin.tech_stack_tags, and the second
                      // overwrites the first (lost-update race).
                      if (e.key === 'Enter' && techTagInput.trim() && !updateTechTagsMutation.isPending) {
                        const current = origin.tech_stack_tags || []
                        if (!current.includes(techTagInput.trim())) {
                          updateTechTagsMutation.mutate([...current, techTagInput.trim()])
                        } else {
                          setTechTagInput('')
                        }
                      }
                    }}
                    placeholder="e.g. nginx, wordpress, php 8.1"
                    className="flex-1 bg-[var(--bg-surface-2)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                  />
                  <Button
                    size="sm"
                    icon={<Plus size={14} />}
                    onClick={() => {
                      if (!techTagInput.trim()) return
                      const current = origin.tech_stack_tags || []
                      if (!current.includes(techTagInput.trim())) {
                        updateTechTagsMutation.mutate([...current, techTagInput.trim()])
                      } else {
                        setTechTagInput('')
                      }
                    }}
                    disabled={!techTagInput.trim() || updateTechTagsMutation.isPending}
                  >
                    Add Tag
                  </Button>
                </div>
                {(origin.tech_stack_tags || []).length === 0 ? (
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    No tags set yet -- CVE Auto-Patch has nothing to match against this origin.
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {(origin.tech_stack_tags || []).map((tag) => (
                      <span
                        key={tag}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[var(--bg-surface-2)] border border-[var(--bg-border-subtle)] text-[12px] font-mono text-[var(--text-primary)]"
                      >
                        {tag}
                        <button
                          onClick={() =>
                            updateTechTagsMutation.mutate((origin.tech_stack_tags || []).filter((t) => t !== tag))
                          }
                          disabled={updateTechTagsMutation.isPending}
                          className="text-[var(--text-muted)] hover:text-red-500"
                          title="Remove tag"
                        >
                          <Trash2 size={11} />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
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

        {activeTab === 'waf' && id && <OriginWafRules originId={id} canEdit={isAdmin} />}

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
                {domains.map((domain: Domain) => {
                  // Real status from services/ssl_cert_monitor.py's periodic
                  // probe (was previously always the literal string
                  // "ACTIVE", regardless of whether a certificate existed
                  // at all -- see api/domains.py's format_domain()).
                  const sslBadgeColor =
                    domain.ssl_status === 'active'
                      ? 'success'
                      : domain.ssl_status === 'error'
                      ? 'danger'
                      : 'gray'
                  const sslSubtitle =
                    domain.ssl_status === 'active'
                      ? `Issuer: ${domain.ssl_issuer || 'unknown'}${
                          typeof domain.ssl_days_remaining === 'number'
                            ? domain.ssl_days_remaining < 0
                              ? ' • EXPIRED'
                              : ` • expires in ${domain.ssl_days_remaining} day(s)`
                            : ''
                        }`
                      : domain.ssl_status === 'error'
                      ? 'Certificate check failed -- see Alerts for details'
                      : 'Not checked yet -- the SSL monitor probes new domains on its next cycle'

                  return (
                    <div
                      key={domain.domain_id}
                      className="dash-card p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                            domain.ssl_status === 'active'
                              ? 'bg-emerald-500/10 text-emerald-500'
                              : domain.ssl_status === 'error'
                              ? 'bg-red-500/10 text-red-500'
                              : 'bg-[var(--bg-hover)] text-[var(--text-muted)]'
                          }`}
                        >
                          <Lock size={18} />
                        </div>
                        <div>
                          <p className="font-bold text-[14px] text-[var(--text-primary)] font-mono m-0">
                            {domain.domain_name}
                          </p>
                          <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                            {sslSubtitle}
                          </p>
                        </div>
                      </div>

                      <Badge color={sslBadgeColor}>
                        {(domain.ssl_status || 'pending').toUpperCase()}
                      </Badge>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {activeTab === 'shield' && (
          <div className="space-y-4">
            <div>
              <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                Bot & Login Shield
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                Proof-of-work challenge in front of login-shaped paths, for origins you can&apos;t
                patch directly
              </p>
            </div>

            {shieldForm && otpForm && <ShieldPresets onApply={applyPreset} appliedKey={appliedPreset} />}
            {impactCheck.dialog}

            {captchaLoading || !shieldForm ? (
              <div className="dash-card p-12 text-center text-[var(--text-muted)] font-mono text-[12px]">
                <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                Loading shield configuration...
              </div>
            ) : (
              <>
                <div className="dash-card p-5 flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${
                        shieldForm.enabled
                          ? 'bg-orange-500/10 text-orange-500'
                          : 'bg-[var(--bg-surface-elevated)] text-[var(--text-muted)]'
                      }`}
                    >
                      <Bot size={18} />
                    </div>
                    <div>
                      <p className="font-bold text-[13.5px] text-[var(--text-primary)] font-mono m-0">
                        {!shieldForm.enabled ? 'Shield is off' : shieldForm.mode === 'log_only' ? 'Shield is logging only' : 'Shield is active'}
                      </p>
                      <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                        {shieldForm.enabled
                          ? 'Visitors solve a challenge before reaching the paths below'
                          : 'Every request passes straight through, unchanged'}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={shieldForm.enabled}
                    onClick={() =>
                      setShieldForm((f) => (f ? { ...f, enabled: !f.enabled } : f))
                    }
                    className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors cursor-pointer ${
                      shieldForm.enabled ? 'bg-orange-500' : 'bg-[var(--bg-border)]'
                    }`}
                  >
                    <span
                      className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                        shieldForm.enabled ? 'translate-x-5' : 'translate-x-0.5'
                      }`}
                    />
                  </button>
                </div>

                {shieldForm.enabled && verifiedDomainCount === 0 && (
                  <div className="dash-card p-4 border-l-2 border-l-amber-500 bg-amber-500/[0.04] flex items-start gap-3">
                    <AlertTriangle size={16} className="text-amber-500 shrink-0 mt-0.5" />
                    <p className="text-[12px] font-mono text-[var(--text-secondary)] m-0">
                      No domain on this pool is DNS-verified yet, so this config has nowhere to
                      sync to. Verify a domain under Domains &amp; DNS and save here again.
                    </p>
                  </div>
                )}

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    Protected paths
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    One path pattern per line. Everything else on the domain is left alone.
                  </p>
                  <textarea
                    className="w-full dash-input font-mono text-[12px] min-h-[110px] resize-y"
                    placeholder="/login*"
                    value={shieldForm.loginPathsText}
                    onChange={(e) =>
                      setShieldForm((f) => (f ? { ...f, loginPathsText: e.target.value } : f))
                    }
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  <ModeSelector
                    mode={shieldForm.mode}
                    onChange={(mode) => setShieldForm((f) => (f ? { ...f, mode } : f))}
                  />
                  <ExcludePathsField
                    value={shieldForm.excludePathsText}
                    onChange={(v) => setShieldForm((f) => (f ? { ...f, excludePathsText: v } : f))}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  <div className="dash-card p-5 space-y-4">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      Challenge difficulty
                    </h3>
                    <div className="flex items-center gap-4">
                      <input
                        type="range"
                        min={1}
                        max={5}
                        step={1}
                        value={shieldForm.powDifficulty}
                        onChange={(e) =>
                          setShieldForm((f) =>
                            f ? { ...f, powDifficulty: Number(e.target.value) } : f
                          )
                        }
                        className="flex-1 accent-orange-500 cursor-pointer"
                      />
                      <Badge color="brand">{shieldForm.powDifficulty} / 5</Badge>
                    </div>
                    <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0">
                      Higher takes a visitor's browser longer to solve — 3 is a fraction of a
                      second, 5 is closer to two.
                    </p>
                  </div>

                  <div className="dash-card p-5 space-y-4">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      Clearance lifetime
                    </h3>
                    <div className="flex items-center gap-2">
                      <input
                        type="number"
                        min={15}
                        max={720}
                        className="w-24 dash-input font-mono text-[12px]"
                        value={Math.round(shieldForm.clearanceTtl / 60)}
                        onChange={(e) =>
                          setShieldForm((f) =>
                            f
                              ? {
                                  ...f,
                                  clearanceTtl: Math.min(
                                    43200,
                                    Math.max(900, Number(e.target.value) * 60 || 0)
                                  ),
                                }
                              : f
                          )
                        }
                      />
                      <span className="text-[12px] font-mono text-[var(--text-muted)]">
                        minutes before a solved visitor is challenged again
                      </span>
                    </div>
                  </div>
                </div>

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    Skip the challenge from these addresses
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    IPs or CIDR ranges, one per line — your office, monitoring, or CI. Leave empty
                    to challenge everyone.
                  </p>
                  <textarea
                    className="w-full dash-input font-mono text-[12px] min-h-[80px] resize-y"
                    placeholder="203.0.113.4/32"
                    value={shieldForm.bypassIpsText}
                    onChange={(e) =>
                      setShieldForm((f) => (f ? { ...f, bypassIpsText: e.target.value } : f))
                    }
                  />
                </div>

                <div className="flex justify-end">
                  <Button
                    variant="brand"
                    onClick={handleSaveShield}
                    disabled={saveShieldMutation.isPending}
                    isLoading={saveShieldMutation.isPending}
                  >
                    Save Shield Settings
                  </Button>
                </div>
              </>
            )}

            <div className="pt-2 border-t border-[var(--bg-border)]">
              <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                OTP Shield
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                Email a one-time code to whoever reaches a login-shaped path, and only let them
                through once they enter it. Independent of Bot Shield above -- either or both can
                be on at once.
              </p>
            </div>

            {otpLoading || !otpForm ? (
              <div className="dash-card p-12 text-center text-[var(--text-muted)] font-mono text-[12px]">
                <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                Loading OTP configuration...
              </div>
            ) : (
              <>
                <div className="dash-card p-5 flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${
                        otpForm.enabled
                          ? 'bg-orange-500/10 text-orange-500'
                          : 'bg-[var(--bg-surface-elevated)] text-[var(--text-muted)]'
                      }`}
                    >
                      <Mail size={18} />
                    </div>
                    <div>
                      <p className="font-bold text-[13.5px] text-[var(--text-primary)] font-mono m-0">
                        {!otpForm.enabled ? 'OTP Shield is off' : otpForm.mode === 'log_only' ? 'OTP Shield is logging only' : 'OTP Shield is active'}
                      </p>
                      <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                        {otpForm.enabled
                          ? 'Visitors verify an emailed code before reaching the paths below'
                          : 'Every request passes straight through, unchanged'}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={otpForm.enabled}
                    onClick={() => setOtpForm((f) => (f ? { ...f, enabled: !f.enabled } : f))}
                    className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors cursor-pointer ${
                      otpForm.enabled ? 'bg-orange-500' : 'bg-[var(--bg-border)]'
                    }`}
                  >
                    <span
                      className={`inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                        otpForm.enabled ? 'translate-x-5' : 'translate-x-0.5'
                      }`}
                    />
                  </button>
                </div>

                {otpForm.enabled && verifiedDomainCount === 0 && (
                  <div className="dash-card p-4 border-l-2 border-l-amber-500 bg-amber-500/[0.04] flex items-start gap-3">
                    <AlertTriangle size={16} className="text-amber-500 shrink-0 mt-0.5" />
                    <p className="text-[12px] font-mono text-[var(--text-secondary)] m-0">
                      No domain on this pool is DNS-verified yet, so this config has nowhere to
                      sync to. Verify a domain under Domains &amp; DNS and save here again.
                    </p>
                  </div>
                )}

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    Protected paths
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    One path pattern per line. Everything else on the domain is left alone.
                  </p>
                  <textarea
                    className="w-full dash-input font-mono text-[12px] min-h-[110px] resize-y"
                    placeholder="/login*"
                    value={otpForm.loginPathsText}
                    onChange={(e) =>
                      setOtpForm((f) => (f ? { ...f, loginPathsText: e.target.value } : f))
                    }
                  />
                </div>

                <OtpAccessField
                  accessMode={otpForm.accessMode}
                  allowedText={otpForm.allowedEmailsText}
                  onModeChange={(accessMode) => setOtpForm((f) => (f ? { ...f, accessMode } : f))}
                  onAllowedChange={(v) => setOtpForm((f) => (f ? { ...f, allowedEmailsText: v } : f))}
                />

                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  <ModeSelector
                    mode={otpForm.mode}
                    onChange={(mode) => setOtpForm((f) => (f ? { ...f, mode } : f))}
                  />
                  <ExcludePathsField
                    value={otpForm.excludePathsText}
                    onChange={(v) => setOtpForm((f) => (f ? { ...f, excludePathsText: v } : f))}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                  <div className="dash-card p-5 space-y-3">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      Delivery channel
                    </h3>
                    <select
                      className="w-full dash-input font-mono text-[12px]"
                      value="email"
                      disabled
                    >
                      <option value="email">Email</option>
                    </select>
                    <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0">
                      More channels later -- SMS/etc need their own delivery integration first.
                    </p>
                  </div>

                  <div className="dash-card p-5 space-y-3">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      Code length
                    </h3>
                    <div className="flex items-center gap-4">
                      <input
                        type="range"
                        min={4}
                        max={8}
                        step={1}
                        value={otpForm.codeLength}
                        onChange={(e) =>
                          setOtpForm((f) => (f ? { ...f, codeLength: Number(e.target.value) } : f))
                        }
                        className="flex-1 accent-orange-500 cursor-pointer"
                      />
                      <Badge color="brand">{otpForm.codeLength} digits</Badge>
                    </div>
                  </div>

                  <div className="dash-card p-5 space-y-3">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      Code expires in
                    </h3>
                    <select
                      aria-label="Code expires in"
                      className="w-full dash-input font-mono text-[12px]"
                      value={otpForm.codeTtl}
                      onChange={(e) => setOtpForm((f) => (f ? { ...f, codeTtl: Number(e.target.value) } : f))}
                    >
                      {withCurrent(OTP_CODE_TTL_OPTIONS, otpForm.codeTtl).map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </select>
                    <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0">
                      How long the emailed code works. The email states this time.
                    </p>
                  </div>
                </div>

                <div className="dash-card p-5 space-y-3">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    Remember a verified visitor for
                  </h3>
                  <select
                    aria-label="Remember a verified visitor for"
                    className="w-full md:w-72 dash-input font-mono text-[12px]"
                    value={otpForm.clearanceTtl}
                    onChange={(e) => setOtpForm((f) => (f ? { ...f, clearanceTtl: Number(e.target.value) } : f))}
                  >
                    {withCurrent(OTP_CLEARANCE_OPTIONS, otpForm.clearanceTtl).map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0">
                    After this, the visitor gets a new code. Changing network (Wi-Fi to 4G) or browser also asks
                    again. Days-long values suit &quot;Only these emails&quot; mode, where removing someone takes
                    effect immediately.
                  </p>
                </div>

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    Skip the challenge from these addresses
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    IPs or CIDR ranges, one per line. Leave empty to challenge everyone.
                  </p>
                  <textarea
                    className="w-full dash-input font-mono text-[12px] min-h-[80px] resize-y"
                    placeholder="203.0.113.4/32"
                    value={otpForm.bypassIpsText}
                    onChange={(e) =>
                      setOtpForm((f) => (f ? { ...f, bypassIpsText: e.target.value } : f))
                    }
                  />
                </div>

                <div className="flex justify-end">
                  <Button
                    variant="brand"
                    onClick={handleSaveOtp}
                    disabled={saveOtpMutation.isPending}
                    isLoading={saveOtpMutation.isPending}
                  >
                    Save OTP Settings
                  </Button>
                </div>
              </>
            )}

            {id && <ShieldActivity originId={id} />}
          </div>
        )}

        {activeTab === 'team' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {isAdmin && (
              <div className="dash-card p-5 space-y-4">
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)] flex items-center gap-2">
                  <Users size={14} /> Viewer Access
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  Only you can see this origin by default. Grant another registered account
                  read-only access below -- they will see it in their Origins list and in their
                  Traffic Logs / Analytics, but cannot edit, delete, or manage its settings.
                </p>
                <div className="flex gap-2">
                  <input
                    type="email"
                    value={viewerEmailInput}
                    onChange={(e) => setViewerEmailInput(e.target.value)}
                    placeholder="teammate@example.com"
                    className="flex-1 bg-[var(--bg-surface-2)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                  />
                  <Button
                    size="sm"
                    icon={<Plus size={14} />}
                    onClick={() => viewerEmailInput.trim() && addViewerMutation.mutate(viewerEmailInput.trim())}
                    disabled={!viewerEmailInput.trim() || addViewerMutation.isPending}
                  >
                    Add Viewer
                  </Button>
                </div>
                {viewersLoading ? (
                  <LoadingSpinner />
                ) : viewers.length === 0 ? (
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    No viewers granted yet -- this origin is only visible to you.
                  </p>
                ) : (
                  <div className="space-y-2 font-mono text-[12px]">
                    {viewers.map((v) => (
                      <div
                        key={v.user_id}
                        className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]"
                      >
                        <span className="text-[var(--text-primary)]">
                          {v.username || v.email} <span className="text-[var(--text-muted)]">({v.email})</span>
                        </span>
                        <button
                          onClick={() => removeViewerMutation.mutate(v.user_id)}
                          disabled={removeViewerMutation.isPending}
                          className="text-red-500 hover:text-red-400"
                          title="Revoke viewer access"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {isAdmin && (
              <div className="dash-card p-5 space-y-4">
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)] flex items-center gap-2">
                  <Users size={14} /> Admin Access
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  An Admin has full control of this origin: rename it, change its IP/port,
                  configure the CAPTCHA/OTP shield, manage domains and WAF rules, and grant or
                  revoke Viewer/Admin access -- except they cannot remove the origin's creator
                  or archive/restore the origin itself.
                </p>
                <div className="flex gap-2">
                  <input
                    type="email"
                    value={editorEmailInput}
                    onChange={(e) => setEditorEmailInput(e.target.value)}
                    placeholder="teammate@example.com"
                    className="flex-1 bg-[var(--bg-surface-2)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                  />
                  <Button
                    size="sm"
                    icon={<Plus size={14} />}
                    onClick={() => editorEmailInput.trim() && addEditorMutation.mutate(editorEmailInput.trim())}
                    disabled={!editorEmailInput.trim() || addEditorMutation.isPending}
                  >
                    Add Admin
                  </Button>
                </div>
                {editorsLoading ? (
                  <LoadingSpinner />
                ) : editors.length === 0 ? (
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    No additional Admins granted yet.
                  </p>
                ) : (
                  <div className="space-y-2 font-mono text-[12px]">
                    {editors.map((ed) => (
                      <div
                        key={ed.user_id}
                        className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]"
                      >
                        <span className="text-[var(--text-primary)]">
                          {ed.username || ed.email} <span className="text-[var(--text-muted)]">({ed.email})</span>
                        </span>
                        <button
                          onClick={() => removeEditorMutation.mutate(ed.user_id)}
                          disabled={removeEditorMutation.isPending}
                          className="text-red-500 hover:text-red-400"
                          title="Revoke Admin access"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className={`dash-card p-5 space-y-4 ${isAdmin ? 'md:col-span-2' : 'md:col-span-2'}`}>
              <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)] flex items-center gap-2">
                <Code size={14} /> Audit Log
              </h3>
              <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                Who changed what and when on this origin -- settings, domains, and access
                grants. Kept for 180 days.
              </p>
              {auditLogLoading ? (
                <LoadingSpinner />
              ) : auditEvents.length === 0 ? (
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  No changes recorded yet.
                </p>
              ) : (
                <div className="space-y-2 font-mono text-[12px] max-h-[480px] overflow-y-auto">
                  {auditEvents.map((ev) => (
                    <div
                      key={ev.event_id}
                      className="flex flex-col gap-1 py-2 border-b border-[var(--bg-border-subtle)]"
                    >
                      <div className="flex justify-between items-center gap-2">
                        <span className="text-[var(--text-primary)]">{ev.summary}</span>
                        <Badge color="gray">{ev.action}</Badge>
                      </div>
                      <span className="text-[var(--text-muted)] text-[11px]">
                        {ev.actor_username || ev.actor_user_id} &middot;{' '}
                        {new Date(ev.timestamp).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'postmortem' && (
          <div className="space-y-5">
            {!isAdmin ? (
              <EmptyState
                icon={<FileText size={24} />}
                title="Admin only"
                subtitle="Incident Postmortem reports are visible to this origin's Admins only -- they can include system-wide settings changes, not just this origin's own activity."
              />
            ) : (
              <>
                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)] flex items-center gap-2">
                    <FileText size={14} /> Generate Incident Report
                  </h3>
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    Pick a time range around an incident. The report correlates real traffic/alert
                    volume in that window against the real audit trail -- including system-wide
                    settings and ML rule changes -- and asks AI to draft an executive summary,
                    timeline, root-cause hypothesis, and recommendations.
                  </p>
                  <div className="flex flex-wrap items-end gap-3">
                    <div className="space-y-1">
                      <label className="block text-[11px] text-[var(--text-muted)] font-mono">Start</label>
                      <input
                        type="datetime-local"
                        value={pmStart}
                        onChange={(e) => setPmStart(e.target.value)}
                        className="bg-[var(--bg-surface-2)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="block text-[11px] text-[var(--text-muted)] font-mono">End</label>
                      <input
                        type="datetime-local"
                        value={pmEnd}
                        onChange={(e) => setPmEnd(e.target.value)}
                        className="bg-[var(--bg-surface-2)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                      />
                    </div>
                    <Button
                      icon={<FileText size={14} />}
                      onClick={() => createPostmortemMutation.mutate()}
                      disabled={!pmStart || !pmEnd || createPostmortemMutation.isPending}
                      isLoading={createPostmortemMutation.isPending}
                    >
                      Generate Report
                    </Button>
                  </div>
                </div>

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)]">
                    Past Reports
                  </h3>
                  {postmortemsLoading ? (
                    <LoadingSpinner />
                  ) : postmortems.length === 0 ? (
                    <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                      No reports generated yet.
                    </p>
                  ) : (
                    <div className="space-y-2 font-mono text-[12px]">
                      {postmortems.map((p) => (
                        <button
                          key={p.id}
                          onClick={() => setSelectedPostmortemId(p.id)}
                          className={`w-full text-left flex justify-between items-center py-2 px-3 rounded border transition-colors cursor-pointer ${
                            selectedPostmortemId === p.id
                              ? 'border-orange-500 bg-[var(--bg-hover)]'
                              : 'border-[var(--bg-border-subtle)] hover:bg-[var(--bg-hover)]'
                          }`}
                        >
                          <span className="text-[var(--text-primary)]">
                            {p.start_time} &rarr; {p.end_time}
                          </span>
                          <span className="flex items-center gap-2 text-[var(--text-muted)]">
                            {p.stats?.total_alerts ?? 0} alerts
                            {p.has_ai_narrative && <Badge color="brand">AI</Badge>}
                          </span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                {selectedPostmortemId && (
                  <div className="dash-card p-5 space-y-4">
                    {selectedPostmortemLoading ? (
                      <LoadingSpinner />
                    ) : !selectedPostmortem ? (
                      <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                        Report not found.
                      </p>
                    ) : (
                      <>
                        <div className="flex justify-between items-start gap-3 pb-3 border-b border-[var(--bg-border-subtle)]">
                          <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
                            Report: {selectedPostmortem.start_time} &rarr; {selectedPostmortem.end_time}
                          </h3>
                          <button
                            onClick={() => setSelectedPostmortemId(null)}
                            className="text-[var(--text-muted)] hover:text-[var(--text-primary)] text-[11px] font-mono"
                          >
                            Close
                          </button>
                        </div>

                        <div className="grid grid-cols-3 gap-3 font-mono text-[12px]">
                          <div className="dash-card p-3 text-center">
                            <div className="text-[var(--text-muted)] text-[11px]">Total Requests</div>
                            <div className="text-[18px] font-bold text-[var(--text-primary)]">
                              {selectedPostmortem.stats?.total_requests ?? 0}
                            </div>
                          </div>
                          <div className="dash-card p-3 text-center">
                            <div className="text-[var(--text-muted)] text-[11px]">Alerts / Blocked</div>
                            <div className="text-[18px] font-bold text-orange-500">
                              {selectedPostmortem.stats?.total_alerts ?? 0}
                            </div>
                          </div>
                          <div className="dash-card p-3 text-center">
                            <div className="text-[var(--text-muted)] text-[11px]">Top Attack Type</div>
                            <div className="text-[14px] font-bold text-[var(--text-primary)]">
                              {selectedPostmortem.stats?.top_attack_types?.[0]?.type || '-'}
                            </div>
                          </div>
                        </div>

                        {selectedPostmortem.ai_narrative ? (
                          <div className="space-y-2">
                            {selectedPostmortem.ai_narrative_degraded && (
                              <Badge color="warning">AI summary may be truncated</Badge>
                            )}
                            <div className="whitespace-pre-wrap text-[12.5px] font-mono text-[var(--text-primary)] bg-[var(--bg-surface-2)] rounded p-4 leading-relaxed">
                              {selectedPostmortem.ai_narrative}
                            </div>
                          </div>
                        ) : (
                          <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                            AI summary unavailable for this report -- showing raw data below.
                          </p>
                        )}

                        <details className="font-mono text-[12px]">
                          <summary className="cursor-pointer text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                            Raw timeline ({selectedPostmortem.audit_events?.length ?? 0} audit event(s),{' '}
                            {selectedPostmortem.hourly_buckets?.length ?? 0} hourly bucket(s))
                          </summary>
                          <div className="mt-3 space-y-2">
                            {(selectedPostmortem.audit_events || []).map((ev) => (
                              <div
                                key={ev.event_id}
                                className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]"
                              >
                                <span className="text-[var(--text-primary)]">{ev.summary}</span>
                                <span className="flex items-center gap-2">
                                  <Badge color={ev.scope === 'global' ? 'warning' : 'gray'}>{ev.scope}</Badge>
                                  <span className="text-[var(--text-muted)] text-[11px]">
                                    {new Date(ev.timestamp).toLocaleString()}
                                  </span>
                                </span>
                              </div>
                            ))}
                          </div>
                        </details>
                      </>
                    )}
                  </div>
                )}
              </>
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
