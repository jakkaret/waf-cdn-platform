import React, { useEffect, useState } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getOrigin, deleteOrigin, restoreOrigin, updateOrigin, getOriginCves } from '../api/origins'
import { getDomains, deleteDomain } from '../api/domains'
import { onboardingApi } from '../api/onboarding'
import { getCaptchaConfig, updateCaptchaConfig } from '../api/captcha'
import { getOtpConfig, updateOtpConfig } from '../api/otp'
import { getOriginViewers, addOriginViewer, removeOriginViewer } from '../api/origin_viewers'
import { getOriginEditors, addOriginEditor, removeOriginEditor } from '../api/origin_editors'
import { getOriginAuditLog } from '../api/origin_audit_log'
import { createPostmortem, getPostmortems, getPostmortem } from '../api/postmortems'
import { useAuthStore } from '../store/authStore'
import { tunnelConnectivityBadge } from '../lib/tunnelStatus'
import { CRS_VERSION } from '../lib/crsVersion'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { LoadingSpinner } from '../components/ui/LoadingSpinner'
import { ConfirmDialog } from '../components/ui/ConfirmDialog'
import { EmptyState } from '../components/ui/EmptyState'
import { ConnectSiteFlow } from '../components/ConnectSiteFlow'
import { OriginTarget } from '../components/OriginTarget'
import { PurgeCache } from '../components/PurgeCache'
import { DomainStatusCard } from '../components/DomainStatusCard'
import { Modal } from '../components/ui/Modal'
import { OriginWafRules } from '../components/OriginWafRules'
import { OriginIpAccess } from '../components/OriginIpAccess'
import { OriginMlProtection } from '../components/OriginMlProtection'
import { OriginRateLimits } from '../components/OriginRateLimits'
import { ShieldActivity } from '../components/ShieldActivity'
import { OriginTabs } from '../components/OriginTabs'
import { getSiteRateRules } from '../api/siteAccess'
import { originUpstreamLabel } from '../lib/originUpstream'
import { isOriginTab, type OriginTabId } from '../components/layout/navigation'
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
  Bug,
  ExternalLink,
  ListChecks,
  Gauge,
  Brain,
} from 'lucide-react'
import { ORIGIN_ROLE_LABEL, canEditOrigin, canManageOrigin, originRoleOf } from '../lib/roles'
import { useVerifiedGuard } from '../components/auth/EmailVerifyGate'
import { ReportText } from '../components/ai/ReportText'
import { BKK_LABEL, formatBkkDateTime } from '../lib/time'
import { severityLabel, statusWord, useT } from '../i18n'

const cveSeverityClass = (sev: string): string => {
  switch (sev) {
    case 'CRITICAL':
      return 'bg-red-500/15 text-red-500 border-red-500/30'
    case 'HIGH':
      return 'bg-orange-500/15 text-orange-500 border-orange-500/30'
    case 'MEDIUM':
      return 'bg-yellow-500/15 text-yellow-600 border-yellow-500/30'
    case 'LOW':
      return 'bg-sky-500/15 text-sky-500 border-sky-500/30'
    default:
      return 'bg-[var(--bg-surface-elevated)] text-[var(--text-muted)] border-[var(--bg-border-subtle)]'
  }
}

export const OriginDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const currentUser = useAuthStore((s) => s.user)
  const guard = useVerifiedGuard()
  const { t, lang } = useT()
  const [viewerEmailInput, setViewerEmailInput] = useState('')
  const [editorEmailInput, setEditorEmailInput] = useState('')
  const [searchParams, setSearchParams] = useSearchParams()
  // The tab lives in the URL (?tab=), so a link from All rules, Alerts or the
  // quick search opens the right one and Back/refresh keep it. ?tab=domains
  // lands a just-connected site on its setup status; the old ?tab=ssl link
  // target is now part of the Domains tab.
  const requestedTab = searchParams.get('tab') === 'ssl' ? 'domains' : searchParams.get('tab')
  const activeTab: OriginTabId = isOriginTab(requestedTab) ? requestedTab : 'overview'
  const setActiveTab = (tab: OriginTabId) => {
    const p = new URLSearchParams(searchParams)
    p.set('tab', tab)
    // Prefill values (?ip=, ?note=) belong to the tab they were sent to.
    if (tab !== 'ip-access') {
      p.delete('ip')
      p.delete('note')
    }
    setSearchParams(p, { replace: true })
  }
  // "Block IP" links from Alerts / the dashboard / logs prefill the form.
  const prefillIp = activeTab === 'ip-access' ? searchParams.get('ip') : null
  const prefillNote = activeTab === 'ip-access' ? searchParams.get('note') : null
  const [pmStart, setPmStart] = useState('')
  const [pmEnd, setPmEnd] = useState('')
  const [selectedPostmortemId, setSelectedPostmortemId] = useState<string | null>(null)
  const [techTagInput, setTechTagInput] = useState('')
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [isRestoreModalOpen, setIsRestoreModalOpen] = useState(false)
  const [isDomainWizardOpen, setIsDomainWizardOpen] = useState(false)
  const [domainToDelete, setDomainToDelete] = useState<string | null>(null)
  const queryClient = useQueryClient()
  const impactCheck = useShieldImpactCheck(id || '')

  const { data, isLoading, isError } = useQuery({
    queryKey: ['origin', id],
    queryFn: () => getOrigin(id!),
    enabled: !!id,
  })

  // Same key as the Rate limits tab (OriginRateLimits), so both agree.
  const { data: rateRules, isLoading: rateRulesLoading, isError: rateRulesError } = useQuery({
    queryKey: ['site-rate-limits', id],
    queryFn: () => getSiteRateRules(id!),
    enabled: !!id && activeTab === 'overview',
  })
  const activeRateRules = (rateRules ?? []).filter((r) => r.enabled).length

  const originHasTags = (data?.data?.tech_stack_tags || []).length > 0
  const { data: cveData, isLoading: cveLoading, isError: cveError } = useQuery({
    queryKey: ['origin-cves', id, data?.data?.tech_stack_tags],
    queryFn: () => getOriginCves(id!),
    enabled: !!id && originHasTags,
    staleTime: 10 * 60 * 1000,
  })
  const originCves = cveData?.data?.cves || []

  const { data: domainsData, refetch: refetchDomains } = useQuery({
    queryKey: ['domains', id],
    queryFn: () => getDomains(id!),
    enabled: !!id,
  })

  // Per-domain DNS / connection / HTTPS, re-checked by the backend on each
  // call (it throttles the real lookups). Poll fast while something is still
  // being set up, slowly once everything is live.
  const { data: progress, refetch: refetchProgress, isFetching: progressFetching } = useQuery({
    queryKey: ['origin-progress', id],
    queryFn: () => onboardingApi.progress(id!),
    enabled: !!id && activeTab === 'domains',
    refetchInterval: (q) => (q.state.data?.all_ready ? 60_000 : 10_000),
  })

  // The Domains tab lists what /progress returns: it is readable by viewers,
  // unlike getDomains (edit-only), which left viewers on an empty state.
  const tabDomains = progress?.domains ?? []

  // The progress check is what activates an origin once its agent or route is
  // up; reload the header (status badge, "Cancel Setup") when that happens.
  const originStatus = data?.data?.status
  useEffect(() => {
    if (progress?.origin_status && originStatus && progress.origin_status !== originStatus) {
      queryClient.invalidateQueries({ queryKey: ['origin', id] })
    }
  }, [progress?.origin_status, originStatus, id, queryClient])

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
      toast.success(t('Bot & Login Shield settings saved', 'บันทึกการตั้งค่า Bot & Login Shield แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['captcha-shield', id] })
    },
    onError: (e: any) =>
      toast.error(e.response?.data?.detail || t('Failed to save Bot & Login Shield settings', 'บันทึกการตั้งค่า Bot & Login Shield ไม่สำเร็จ')),
  })

  const handleSaveShield = () => {
    if (!shieldForm) return
    const login_paths = parseListInput(shieldForm.loginPathsText)
    if (login_paths.length === 0) {
      toast.error(t('Add at least one login path to protect', 'เพิ่ม path ล็อกอินที่จะป้องกันอย่างน้อย 1 รายการ'))
      return
    }
    if (login_paths.some((p) => !p.startsWith('/'))) {
      toast.error(t('Every login path must start with /', 'path ล็อกอินทุกรายการต้องขึ้นต้นด้วย /'))
      return
    }
    const exclude_paths = parseListInput(shieldForm.excludePathsText)
    if (exclude_paths.some((p) => !p.startsWith('/'))) {
      toast.error(t('Every excluded path must start with /', 'path ที่ยกเว้นทุกรายการต้องขึ้นต้นด้วย /'))
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
      toast.success(t('OTP Shield settings saved', 'บันทึกการตั้งค่า OTP Shield แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['otp-shield', id] })
    },
    onError: (e: any) =>
      toast.error(e.response?.data?.detail || t('Failed to save OTP Shield settings', 'บันทึกการตั้งค่า OTP Shield ไม่สำเร็จ')),
  })

  const handleSaveOtp = () => {
    if (!otpForm) return
    const login_paths = parseListInput(otpForm.loginPathsText)
    if (login_paths.length === 0) {
      toast.error(t('Add at least one login path to protect', 'เพิ่ม path ล็อกอินที่จะป้องกันอย่างน้อย 1 รายการ'))
      return
    }
    if (login_paths.some((p) => !p.startsWith('/'))) {
      toast.error(t('Every login path must start with /', 'path ล็อกอินทุกรายการต้องขึ้นต้นด้วย /'))
      return
    }
    const exclude_paths = parseListInput(otpForm.excludePathsText)
    if (exclude_paths.some((p) => !p.startsWith('/'))) {
      toast.error(t('Every excluded path must start with /', 'path ที่ยกเว้นทุกรายการต้องขึ้นต้นด้วย /'))
      return
    }
    const allowed_emails = parseListInput(otpForm.allowedEmailsText)
    if (otpForm.enabled && otpForm.accessMode === 'allowlist' && allowed_emails.length === 0) {
      toast.error(t('Add at least one email address or @domain to the allowlist', 'เพิ่มอีเมลหรือ @domain ในรายการที่อนุญาตอย่างน้อย 1 รายการ'))
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

  // Owner > Editor > Viewer (lib/roles). isAdmin = may edit (Owner or Editor);
  // isOwner = may manage the team, delete/restore and issue tunnel credentials.
  const myOriginRole = originRoleOf(origin, currentUser?.user_id)
  const isOwner = canManageOrigin(myOriginRole)
  const isAdmin = canEditOrigin(myOriginRole)

  const { data: viewersData, isLoading: viewersLoading } = useQuery({
    queryKey: ['origin-viewers', id],
    queryFn: () => getOriginViewers(id!),
    enabled: !!id && isOwner,
  })
  const viewers = viewersData?.data?.viewers || []

  const addViewerMutation = useMutation({
    mutationFn: (email: string) => addOriginViewer(id!, email),
    onSuccess: (res) => {
      toast.success(res.data.email_sent
        ? t(`Invitation sent to ${res.data.email}. They get view access after opening the link.`, `ส่งคำเชิญไปที่ ${res.data.email} แล้ว ผู้รับจะได้สิทธิ์ดูหลังเปิดลิงก์`)
        : t(`Invitation created for ${res.data.email}, but the email could not be sent.`, `สร้างคำเชิญสำหรับ ${res.data.email} แล้ว แต่ส่งอีเมลไม่สำเร็จ`))
      setViewerEmailInput('')
      queryClient.invalidateQueries({ queryKey: ['origin-viewers', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Failed to add viewer', 'เพิ่ม viewer ไม่สำเร็จ')),
  })

  const removeViewerMutation = useMutation({
    mutationFn: (viewerId: string) => removeOriginViewer(id!, viewerId),
    onSuccess: () => {
      toast.success(t('Viewer access removed', 'ยกเลิกสิทธิ์ viewer แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['origin-viewers', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Failed to remove viewer', 'ยกเลิกสิทธิ์ viewer ไม่สำเร็จ')),
  })

  // Team Workspace (2026-09-22): editors can make routine, reversible
  // changes (origin fields, CAPTCHA/OTP config, domains) but never
  // delete/restore the origin or manage viewers/editors -- that stays
  // owner-only, mirrored exactly from the viewer pattern above.
  const { data: editorsData, isLoading: editorsLoading } = useQuery({
    queryKey: ['origin-editors', id],
    queryFn: () => getOriginEditors(id!),
    enabled: !!id && isOwner,
  })
  const editors = editorsData?.data?.editors || []

  const addEditorMutation = useMutation({
    mutationFn: (email: string) => addOriginEditor(id!, email),
    onSuccess: (res) => {
      toast.success(res.data.email_sent
        ? t(`Invitation sent to ${res.data.email}. They get edit access after opening the link.`, `ส่งคำเชิญไปที่ ${res.data.email} แล้ว ผู้รับจะได้สิทธิ์แก้ไขหลังเปิดลิงก์`)
        : t(`Invitation created for ${res.data.email}, but the email could not be sent.`, `สร้างคำเชิญสำหรับ ${res.data.email} แล้ว แต่ส่งอีเมลไม่สำเร็จ`))
      setEditorEmailInput('')
      queryClient.invalidateQueries({ queryKey: ['origin-editors', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Failed to add editor', 'เพิ่ม editor ไม่สำเร็จ')),
  })

  const removeEditorMutation = useMutation({
    mutationFn: (editorId: string) => removeOriginEditor(id!, editorId),
    onSuccess: () => {
      toast.success(t('Editor removed', 'นำ editor ออกแล้ว'))
      queryClient.invalidateQueries({ queryKey: ['origin-editors', id] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Failed to remove editor', 'นำ editor ออกไม่สำเร็จ')),
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
      toast.success(t('Postmortem report created', 'สร้างรายงาน Postmortem สำเร็จ'))
      queryClient.invalidateQueries({ queryKey: ['origin-postmortems', id] })
      queryClient.setQueryData(['origin-postmortem', id, res.data.postmortem.id], res)
      setSelectedPostmortemId(res.data.postmortem.id)
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Failed to generate postmortem', 'สร้างรายงาน postmortem ไม่สำเร็จ')),
  })

  // CVE Auto-Patch (2026-09-22): feeds POST /api/ml-rules/cve-scan's
  // matching -- self-declared, no real fingerprinting.
  const updateTechTagsMutation = useMutation({
    mutationFn: (tags: string[]) => updateOrigin(id!, { tech_stack_tags: tags }),
    onSuccess: () => {
      toast.success(t('Tech stack tags updated', 'อัปเดต Tech Stack Tags แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['origin', id] })
      setTechTagInput('')
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Failed to update tech stack tags', 'อัปเดต tech stack tags ไม่สำเร็จ')),
  })

  const handleDelete = async () => {
    const isPending = origin?.status === 'pending'
    try {
      await deleteOrigin(id!)
      toast.success(isPending ? t('Origin setup cancelled', 'ยกเลิกการตั้งค่า origin แล้ว') : t('Origin archived', 'เก็บ origin ถาวรแล้ว'))
      navigate('/origins')
    } catch (error: any) {
      toast.error(error.response?.data?.detail || (isPending ? t('Failed to cancel setup', 'ยกเลิกการตั้งค่าไม่สำเร็จ') : t('Failed to archive origin', 'เก็บ origin ถาวรไม่สำเร็จ')))
    }
  }

  const handleRestore = async () => {
    try {
      await restoreOrigin(id!)
      toast.success(t('Origin restored', 'กู้คืน origin แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['origin', id] })
    } catch (error: any) {
      toast.error(error.response?.data?.detail || t('Failed to restore origin', 'กู้คืน origin ไม่สำเร็จ'))
    } finally {
      setIsRestoreModalOpen(false)
    }
  }

  const handleDeleteDomain = async () => {
    if (!domainToDelete) return
    try {
      await deleteDomain(id!, domainToDelete)
      toast.success(t('Domain removed', 'ลบโดเมนแล้ว'))
      refetchDomains()
      refetchProgress()
    } catch (error: any) {
      toast.error(error.response?.data?.detail || t('Failed to remove domain', 'ลบโดเมนไม่สำเร็จ'))
    } finally {
      setDomainToDelete(null)
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-full items-center justify-center py-24 text-[var(--text-muted)] font-mono text-[12px]">
        <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
        {t('Loading origin configuration...', 'กำลังโหลดการตั้งค่า origin...')}
      </div>
    )
  }

  if (isError || !origin) {
    return (
      <div className="p-6">
        <div className="dash-card p-12 text-center text-[var(--text-muted)] space-y-3 font-mono">
          <p>{t('Failed to load origin server details.', 'โหลดข้อมูล origin server ไม่สำเร็จ')}</p>
          <Button variant="secondary" onClick={() => navigate('/origins')}>
            {t('Back to Origins', 'กลับไปหน้า Origins')}
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
            title={t('Back to Origins', 'กลับไปหน้า Origins')}
            aria-label={t('Back to Origins', 'กลับไปหน้า Origins')}
          >
            <ArrowLeft size={16} />
          </button>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-[20px] font-bold text-[var(--text-primary)] font-mono m-0">
                {origin.label}
              </h1>
              {myOriginRole && (
                <Badge color="info">{t('You:', 'คุณ:')} {ORIGIN_ROLE_LABEL[myOriginRole]}</Badge>
              )}
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
                {statusWord(origin.status.toUpperCase(), lang)}
              </Badge>
            </div>
            <p className="text-[12px] font-mono text-[var(--text-muted)] mt-1 m-0">
              {t('Upstream:', 'ปลายทาง:')} {originUpstreamLabel(origin, lang)}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          {/* Archive / restore / cancel are Owner-only (lib/roles). */}
          {!isOwner ? null : origin.status === 'archived' ? (
            <Button
              variant="brand"
              onClick={() => setIsRestoreModalOpen(true)}
              icon={<RotateCcw size={14} />}
            >
              {t('Restore origin', 'กู้คืน origin')}
            </Button>
          ) : origin.status === 'pending' ? (
            <Button
              variant="outline"
              onClick={() => setIsDeleteModalOpen(true)}
            >
              {t('Cancel setup', 'ยกเลิกการตั้งค่า')}
            </Button>
          ) : (
            <Button
              variant="danger"
              onClick={() => setIsDeleteModalOpen(true)}
              icon={<Trash2 size={14} />}
            >
              {t('Archive origin', 'เก็บ origin ถาวร')}
            </Button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <OriginTabs
        active={activeTab}
        onSelect={setActiveTab}
        icons={{
          overview: <Server size={14} />,
          domains: <Globe size={14} />,
          waf: <Shield size={14} />,
          ml: <Brain size={14} />,
          'ip-access': <ListChecks size={14} />,
          'rate-limits': <Gauge size={14} />,
          shield: <Bot size={14} />,
          team: <Users size={14} />,
          postmortem: <FileText size={14} />,
        }}
      />

      {/* Tab Panels */}
      <div id="origin-tab-panel" role="tabpanel" aria-labelledby={`origin-tab-${activeTab}`} className="py-2">
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <OriginTarget originId={id!} origin={origin} canEdit={isAdmin} />

            <div className="dash-card p-5 space-y-4">
              <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)]">
                {t('Security & protection status', 'สถานะความปลอดภัยและการป้องกัน')}
              </h3>
              <div className="space-y-3 font-mono text-[12px]">
                {origin.is_tunnel && (
                  <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                    <span className="text-[var(--text-muted)]">{t('Tunnel connectivity', 'การเชื่อมต่อ tunnel')}</span>
                    {(() => {
                      const b = tunnelConnectivityBadge(origin.live_connected)
                      return <Badge color={b.color}>{statusWord(b.label, lang)}</Badge>
                    })()}
                  </div>
                )}
                <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">ModSecurity WAF</span>
                  <Badge color="success">{t('ENABLED', 'เปิดใช้งาน')} (CRS {CRS_VERSION})</Badge>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">SSL / TLS termination</span>
                  <Badge color="success">{t('AUTO (CADDY)', 'อัตโนมัติ (CADDY)')}</Badge>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-[var(--bg-border-subtle)]">
                  <span className="text-[var(--text-muted)]">Rate limit</span>
                  {/* From the origin's own rate-limit rules (the same query
                      as the Rate limits tab). It used to say ENABLED with no
                      data behind it while that tab showed none. */}
                  <button
                    type="button"
                    onClick={() => setActiveTab('rate-limits')}
                    className="cursor-pointer hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] rounded"
                  >
                    {rateRulesLoading ? (
                      <Badge color="gray">{t('Checking…', 'กำลังตรวจ…')}</Badge>
                    ) : rateRulesError ? (
                      <Badge color="gray">{t('Unavailable', 'ไม่มีข้อมูล')}</Badge>
                    ) : activeRateRules > 0 ? (
                      <Badge color="success">{activeRateRules} {t('active', 'ใช้งานอยู่')}</Badge>
                    ) : (
                      <Badge color="gray">{t('None set', 'ยังไม่ได้ตั้ง')}</Badge>
                    )}
                  </button>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-[var(--text-muted)]">{t('Attached domains', 'โดเมนที่ผูกไว้')}</span>
                  <span className="font-bold text-[var(--text-primary)]">{domains.length} {t('domain(s)', 'โดเมน')}</span>
                </div>
              </div>
            </div>

            <div className="md:col-span-2">
              <PurgeCache
                domains={domains.filter((d: Domain) => d.verification_status === 'verified').map((d: Domain) => d.domain_name)}
                canEdit={isAdmin}
              />
            </div>

            {isAdmin && (
              <div className="dash-card p-5 space-y-4 md:col-span-2">
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)]">
                  Tech stack tags
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  {t(
                    'Self-declared, not auto-detected. Feeds CVE Auto-Patch: a scan matches these tags against the real NVD CVE feed and drafts a proposal into the ML Anomaly Rules queue for review -- it never applies anything automatically.',
                    'กรอกเอง ระบบไม่ได้ตรวจหาให้ ใช้กับ CVE Auto-Patch: ระบบจับคู่ tag เหล่านี้กับฐานข้อมูล CVE ของ NVD แล้วร่างข้อเสนอเข้าคิว ML Anomaly Rules ให้ตรวจ — ไม่มีการนำไปใช้อัตโนมัติ',
                  )}
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
                    placeholder={t('e.g. nginx, wordpress, php 8.1', 'เช่น nginx, wordpress, php 8.1')}
                    className="flex-1 bg-[var(--bg-surface-elevated)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
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
                    {t('Add tag', 'เพิ่ม tag')}
                  </Button>
                </div>
                {(origin.tech_stack_tags || []).length === 0 ? (
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    {t('No tags set yet -- CVE Auto-Patch has nothing to match against this origin.', 'ยังไม่มี tag — CVE Auto-Patch จึงยังไม่มีอะไรให้จับคู่กับ origin นี้')}
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {(origin.tech_stack_tags || []).map((tag) => (
                      <span
                        key={tag}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border-subtle)] text-[12px] font-mono text-[var(--text-primary)]"
                      >
                        {tag}
                        <button
                          onClick={() =>
                            updateTechTagsMutation.mutate((origin.tech_stack_tags || []).filter((t) => t !== tag))
                          }
                          disabled={updateTechTagsMutation.isPending}
                          className="text-[var(--text-muted)] hover:text-red-500"
                          title={t('Remove tag', 'ลบ tag')}
                        >
                          <Trash2 size={11} />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="dash-card p-5 space-y-4 md:col-span-2">
              <div className="flex items-center justify-between pb-3 border-b border-[var(--bg-border-subtle)]">
                <h3 className="flex items-center gap-2 text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
                  <Bug size={15} className="text-red-500" />
                  {t('Known CVEs', 'CVE ที่เกี่ยวข้อง')}
                </h3>
                <span className="text-[11px] text-[var(--text-muted)] font-mono">
                  {t('matched against tech stack tags', 'จับคู่กับ tech stack tags')}
                </span>
              </div>
              <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                {t(
                  "CVEs from the NVD feed that match this origin's tech stack tags. Advisory only -- nothing is blocked until a virtual-patch proposal is reviewed and approved in ML Anomaly Rules.",
                  'CVE จาก NVD ที่ตรงกับ tech stack tags ของ origin นี้ เป็นข้อมูลแนะนำเท่านั้น — จะยังไม่บล็อกอะไรจนกว่าข้อเสนอ virtual patch จะผ่านการตรวจและอนุมัติใน ML Anomaly Rules',
                )}
              </p>
              {!originHasTags ? (
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  {t(
                    'No tech stack tags on this origin yet, so there is nothing to match. An admin of this origin can add tags such as nginx or wordpress.',
                    'origin นี้ยังไม่มี tech stack tags จึงยังไม่มีอะไรให้จับคู่ ผู้ดูแล origin เพิ่ม tag เช่น nginx หรือ wordpress ได้',
                  )}
                </p>
              ) : cveLoading ? (
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  {t(
                    `Searching the NVD feed for ${(origin.tech_stack_tags || []).join(', ')}... the first search can take up to 30 seconds.`,
                    `กำลังค้นหา ${(origin.tech_stack_tags || []).join(', ')} ใน NVD... การค้นหาครั้งแรกอาจใช้เวลาถึง 30 วินาที`,
                  )}
                </p>
              ) : cveError ? (
                <p className="text-[12px] text-red-500 font-mono m-0">
                  {t('Could not load CVEs. Reload the page to try again.', 'โหลด CVE ไม่สำเร็จ รีโหลดหน้าเพื่อลองใหม่')}
                </p>
              ) : originCves.length === 0 ? (
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  {t(
                    `No CVEs modified in the last ${cveData?.data?.window_days ?? 14} days match ${(cveData?.data?.keywords_searched || []).join(', ')}.`,
                    `ไม่มี CVE ที่แก้ไขในช่วง ${cveData?.data?.window_days ?? 14} วันล่าสุดที่ตรงกับ ${(cveData?.data?.keywords_searched || []).join(', ')}`,
                  )}
                </p>
              ) : (
                <div className="space-y-2">
                  {(cveData?.data?.total ?? 0) > originCves.length && (
                    <p className="text-[11px] text-[var(--text-muted)] font-mono m-0">
                      {t(
                        `Showing the ${originCves.length} highest CVSS scores of ${cveData?.data?.total} matches.`,
                        `แสดง ${originCves.length} รายการที่ CVSS สูงสุด จากทั้งหมด ${cveData?.data?.total} รายการ`,
                      )}
                    </p>
                  )}
                  {originCves.map((cve) => (
                    <div
                      key={cve.cve_id}
                      className="flex flex-col gap-2 p-3 rounded bg-[var(--bg-surface-elevated)] border border-[var(--bg-border-subtle)]"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`px-2 py-0.5 rounded border text-[11px] font-bold font-mono ${cveSeverityClass(cve.severity)}`}
                        >
                          {severityLabel(cve.severity, lang)}
                        </span>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                          className="flex items-center gap-1 text-[12px] font-bold font-mono text-[var(--text-primary)] hover:text-[var(--accent)]"
                        >
                          {cve.cve_id}
                          <ExternalLink size={11} />
                        </a>
                        {cve.cvss_score !== null && (
                          <span className="text-[11px] text-[var(--text-muted)] font-mono">
                            CVSS {cve.cvss_score.toFixed(1)}
                          </span>
                        )}
                        <span className="ml-auto text-[11px] text-[var(--text-muted)] font-mono">
                          tag: {cve.matched_tag}
                        </span>
                      </div>
                      <p className="text-[12px] text-[var(--text-secondary)] font-mono m-0 leading-relaxed">
                        {cve.description}
                      </p>
                      {cve.published && (
                        <span className="text-[11px] text-[var(--text-muted)] font-mono">
                          {t('published', 'เผยแพร่')} {cve.published.slice(0, 10)}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'domains' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row justify-between items-start gap-3">
              <div>
                <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                  {t('Domains', 'โดเมน')}
                </h2>
                <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                  {progress
                    ? t(
                        `Point the domain's CNAME to ${progress.domains[0]?.dns.instructions.cname_record.value ?? 'our edge'} — DNS, connection and HTTPS are checked automatically`,
                        `ชี้ CNAME ของโดเมนไปที่ ${progress.domains[0]?.dns.instructions.cname_record.value ?? 'edge ของเรา'} — DNS, การเชื่อมต่อ และ HTTPS ตรวจให้อัตโนมัติ`,
                      )
                    : t('DNS, connection and HTTPS are checked automatically', 'DNS, การเชื่อมต่อ และ HTTPS ตรวจให้อัตโนมัติ')}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {tabDomains.length > 0 && (
                  <Button variant="ghost" size="sm" onClick={() => refetchProgress()} isLoading={progressFetching}>
                    {t('Check now', 'ตรวจเดี๋ยวนี้')}
                  </Button>
                )}
                {isAdmin && tabDomains.length > 0 && (
                  <Button variant="brand" size="sm" onClick={() => setIsDomainWizardOpen(true)} icon={<Plus size={14} />}>
                    {t('Add domain', 'เพิ่มโดเมน')}
                  </Button>
                )}
              </div>
            </div>

            {!progress ? (
              <div className="dash-card p-8 flex justify-center">
                <LoadingSpinner />
              </div>
            ) : tabDomains.length === 0 ? (
              <div className="dash-card p-12 text-center space-y-3 border-dashed">
                <Globe size={36} className="mx-auto text-[var(--text-muted)] opacity-40" />
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
                  {t('No domains yet', 'ยังไม่มีโดเมน')}
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] m-0 font-mono">
                  {t('Add a domain so visitors pass through the WAF before reaching this server', 'เพิ่มโดเมนเพื่อให้ผู้เข้าชมวิ่งผ่าน WAF ก่อนถึงเซิร์ฟเวอร์นี้')}
                </p>
                {isAdmin && (
                  <Button variant="brand" onClick={() => setIsDomainWizardOpen(true)} icon={<Plus size={14} />}>
                    {t('Add domain', 'เพิ่มโดเมน')}
                  </Button>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                {tabDomains.map((item) => (
                  <DomainStatusCard
                    key={item.domain_id}
                    item={item}
                    mode={progress.connection_mode}
                    originPort={progress.origin_port}
                    egressIps={progress.origin_egress_ips}
                    canEdit={isAdmin && progress.can_edit}
                    canMintAgent={progress.can_mint_agent}
                    onRemove={(domainId) => setDomainToDelete(domainId)}
                  />
                ))}
              </div>
            )}

            <Modal open={isDomainWizardOpen} onClose={() => setIsDomainWizardOpen(false)} title={t('Add domain', 'เพิ่มโดเมน')}>
              <ConnectSiteFlow
                existingOriginId={id!}
                onCancel={() => setIsDomainWizardOpen(false)}
                onDone={() => {
                  setIsDomainWizardOpen(false)
                  refetchDomains()
                  refetchProgress()
                }}
              />
            </Modal>

            <ConfirmDialog
              open={!!domainToDelete}
              onCancel={() => setDomainToDelete(null)}
              onConfirm={handleDeleteDomain}
              title={t('Remove domain', 'ลบโดเมน')}
              message={t(
                'Are you sure you want to remove this domain? Web traffic through this hostname will stop immediately.',
                'ต้องการลบโดเมนนี้ใช่ไหม? ทราฟฟิกที่เข้าผ่านชื่อนี้จะหยุดทันที',
              )}
              confirmText={t('Remove domain', 'ลบโดเมน')}
              isDanger={true}
            />
          </div>
        )}

        {activeTab === 'waf' && id && <OriginWafRules originId={id} canEdit={isAdmin} />}
        {activeTab === 'ml' && id && <OriginMlProtection originId={id} canEdit={isAdmin} />}
        {activeTab === 'ip-access' && id && (
          <OriginIpAccess originId={id} canEdit={isAdmin} prefillIp={prefillIp} prefillNote={prefillNote} />
        )}
        {activeTab === 'rate-limits' && id && <OriginRateLimits originId={id} canEdit={isAdmin} />}

        {activeTab === 'shield' && (
          <div className="space-y-4">
            <div>
              <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                Bot & Login Shield
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                {t(
                  "Proof-of-work challenge in front of login-shaped paths, for origins you can't patch directly",
                  'ด่านทดสอบแบบ proof-of-work หน้า path ล็อกอิน สำหรับ origin ที่คุณแก้โค้ดเองไม่ได้',
                )}
              </p>
            </div>

            {shieldForm && otpForm && <ShieldPresets onApply={applyPreset} appliedKey={appliedPreset} />}
            {impactCheck.dialog}

            {captchaLoading || !shieldForm ? (
              <div className="dash-card p-12 text-center text-[var(--text-muted)] font-mono text-[12px]">
                <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                {t('Loading shield configuration...', 'กำลังโหลดการตั้งค่า shield...')}
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
                        {!shieldForm.enabled
                          ? t('Shield is off', 'Shield ปิดอยู่')
                          : shieldForm.mode === 'log_only'
                            ? t('Shield is logging only', 'Shield บันทึก log อย่างเดียว')
                            : t('Shield is active', 'Shield ทำงานอยู่')}
                      </p>
                      <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                        {shieldForm.enabled
                          ? t('Visitors solve a challenge before reaching the paths below', 'ผู้เข้าชมต้องผ่านด่านทดสอบก่อนเข้า path ด้านล่าง')
                          : t('Every request passes straight through, unchanged', 'ทุก request ผ่านไปตรง ๆ ไม่มีการเปลี่ยนแปลง')}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={shieldForm.enabled}
                    aria-label={t('Turn Bot Shield on or off', 'เปิด/ปิด Bot Shield')}
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
                      {t(
                        'No domain on this origin is DNS-verified yet, so this config has nowhere to sync to. Verify a domain under Domains & DNS and save here again.',
                        'ยังไม่มีโดเมนของ origin นี้ที่ยืนยัน DNS แล้ว การตั้งค่านี้จึงยังไม่ถูกส่งไปใช้ ยืนยันโดเมนที่แท็บโดเมนและ DNS แล้วกดบันทึกที่นี่อีกครั้ง',
                      )}
                    </p>
                  </div>
                )}

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    {t('Protected paths', 'Path ที่ป้องกัน')}
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    {t('One path pattern per line. Everything else on the domain is left alone.', 'บรรทัดละหนึ่ง path ส่วนอื่นของโดเมนไม่ถูกแตะต้อง')}
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
                      {t('Challenge difficulty', 'ความยากของด่านทดสอบ')}
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
                      {t(
                        "Higher takes a visitor's browser longer to solve — 3 is a fraction of a second, 5 is closer to two.",
                        'ค่าสูงทำให้เบราว์เซอร์ของผู้เข้าชมใช้เวลาแก้นานขึ้น — ระดับ 3 ไม่ถึงวินาที ระดับ 5 ราวสองวินาที',
                      )}
                    </p>
                  </div>

                  <div className="dash-card p-5 space-y-4">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      {t('Clearance lifetime', 'ระยะเวลาที่ผ่านด่านแล้ว')}
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
                        {t('minutes before a solved visitor is challenged again', 'นาที ก่อนผู้ที่ผ่านแล้วต้องทำด่านอีกครั้ง')}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    {t('Skip the challenge from these addresses', 'ไม่ต้องทำด่านทดสอบสำหรับที่อยู่เหล่านี้')}
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    {t(
                      'IPs or CIDR ranges, one per line — your office, monitoring, or CI. Leave empty to challenge everyone.',
                      'IP หรือช่วง CIDR บรรทัดละหนึ่งรายการ เช่น ออฟฟิศ ระบบ monitoring หรือ CI เว้นว่างไว้เพื่อให้ทุกคนต้องทำด่าน',
                    )}
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
                    {t('Save shield settings', 'บันทึกการตั้งค่า Shield')}
                  </Button>
                </div>
              </>
            )}

            <div className="pt-2 border-t border-[var(--bg-border)]">
              <h2 className="text-[15px] font-bold text-[var(--text-primary)] font-mono m-0">
                OTP Shield
              </h2>
              <p className="text-[12px] text-[var(--text-muted)] m-0 mt-0.5">
                {t(
                  'Email a one-time code to whoever reaches a login-shaped path, and only let them through once they enter it. Independent of Bot Shield above -- either or both can be on at once.',
                  'ส่งรหัสใช้ครั้งเดียวทางอีเมลให้ผู้ที่เข้าถึง path ล็อกอิน และให้ผ่านได้เมื่อกรอกรหัสแล้ว แยกจาก Bot Shield ด้านบน — เปิดอย่างใดอย่างหนึ่งหรือทั้งคู่ก็ได้',
                )}
              </p>
            </div>

            {otpLoading || !otpForm ? (
              <div className="dash-card p-12 text-center text-[var(--text-muted)] font-mono text-[12px]">
                <RefreshCw size={18} className="animate-spin inline mr-2 text-orange-500" />
                {t('Loading OTP configuration...', 'กำลังโหลดการตั้งค่า OTP...')}
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
                        {!otpForm.enabled
                          ? t('OTP Shield is off', 'OTP Shield ปิดอยู่')
                          : otpForm.mode === 'log_only'
                            ? t('OTP Shield is logging only', 'OTP Shield บันทึก log อย่างเดียว')
                            : t('OTP Shield is active', 'OTP Shield ทำงานอยู่')}
                      </p>
                      <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 mt-0.5">
                        {otpForm.enabled
                          ? t('Visitors verify an emailed code before reaching the paths below', 'ผู้เข้าชมต้องยืนยันรหัสทางอีเมลก่อนเข้า path ด้านล่าง')
                          : t('Every request passes straight through, unchanged', 'ทุก request ผ่านไปตรง ๆ ไม่มีการเปลี่ยนแปลง')}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={otpForm.enabled}
                    aria-label={t('Turn OTP Shield on or off', 'เปิด/ปิด OTP Shield')}
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
                      {t(
                        'No domain on this origin is DNS-verified yet, so this config has nowhere to sync to. Verify a domain under Domains & DNS and save here again.',
                        'ยังไม่มีโดเมนของ origin นี้ที่ยืนยัน DNS แล้ว การตั้งค่านี้จึงยังไม่ถูกส่งไปใช้ ยืนยันโดเมนที่แท็บโดเมนและ DNS แล้วกดบันทึกที่นี่อีกครั้ง',
                      )}
                    </p>
                  </div>
                )}

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    {t('Protected paths', 'Path ที่ป้องกัน')}
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    {t('One path pattern per line. Everything else on the domain is left alone.', 'บรรทัดละหนึ่ง path ส่วนอื่นของโดเมนไม่ถูกแตะต้อง')}
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
                      {t('Delivery channel', 'ช่องทางส่งรหัส')}
                    </h3>
                    <select
                      className="w-full dash-input font-mono text-[12px]"
                      value="email"
                      disabled
                    >
                      <option value="email">{t('Email', 'อีเมล')}</option>
                    </select>
                    <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0">
                      {t('Email is the only delivery channel for codes today.', 'ตอนนี้ส่งรหัสได้ทางอีเมลเท่านั้น')}
                    </p>
                  </div>

                  <div className="dash-card p-5 space-y-3">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      {t('Code length', 'ความยาวรหัส')}
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
                      <Badge color="brand">{otpForm.codeLength} {t('digits', 'หลัก')}</Badge>
                    </div>
                  </div>

                  <div className="dash-card p-5 space-y-3">
                    <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                      {t('Code expires in', 'รหัสหมดอายุใน')}
                    </h3>
                    <select
                      aria-label={t('Code expires in', 'รหัสหมดอายุใน')}
                      className="w-full dash-input font-mono text-[12px]"
                      value={otpForm.codeTtl}
                      onChange={(e) => setOtpForm((f) => (f ? { ...f, codeTtl: Number(e.target.value) } : f))}
                    >
                      {withCurrent(OTP_CODE_TTL_OPTIONS, otpForm.codeTtl, lang).map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </select>
                    <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0">
                      {t('How long the emailed code works. The email states this time.', 'ระยะเวลาที่รหัสในอีเมลใช้ได้ ในอีเมลจะระบุเวลานี้ไว้')}
                    </p>
                  </div>
                </div>

                <div className="dash-card p-5 space-y-3">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    {t('Remember a verified visitor for', 'จำผู้เข้าชมที่ยืนยันแล้วเป็นเวลา')}
                  </h3>
                  <select
                    aria-label={t('Remember a verified visitor for', 'จำผู้เข้าชมที่ยืนยันแล้วเป็นเวลา')}
                    className="w-full md:w-72 dash-input font-mono text-[12px]"
                    value={otpForm.clearanceTtl}
                    onChange={(e) => setOtpForm((f) => (f ? { ...f, clearanceTtl: Number(e.target.value) } : f))}
                  >
                    {withCurrent(OTP_CLEARANCE_OPTIONS, otpForm.clearanceTtl, lang).map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0">
                    {t(
                      'After this, the visitor gets a new code. Changing network (Wi-Fi to 4G) or browser also asks again. Days-long values suit "Only these emails" mode, where removing someone takes effect immediately.',
                      'หลังจากนี้ผู้เข้าชมจะได้รหัสใหม่ การเปลี่ยนเครือข่าย (Wi-Fi เป็น 4G) หรือเปลี่ยนเบราว์เซอร์ก็ต้องยืนยันใหม่ ค่าที่นานเป็นวันเหมาะกับโหมด "เฉพาะอีเมลเหล่านี้" ซึ่งการนำใครออกมีผลทันที',
                    )}
                  </p>
                </div>

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono m-0">
                    {t('Skip the challenge from these addresses', 'ไม่ต้องทำด่านทดสอบสำหรับที่อยู่เหล่านี้')}
                  </h3>
                  <p className="text-[11.5px] font-mono text-[var(--text-muted)] m-0 -mt-2">
                    {t('IPs or CIDR ranges, one per line. Leave empty to challenge everyone.', 'IP หรือช่วง CIDR บรรทัดละหนึ่งรายการ เว้นว่างไว้เพื่อให้ทุกคนต้องยืนยัน')}
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
                    {t('Save OTP settings', 'บันทึกการตั้งค่า OTP')}
                  </Button>
                </div>
              </>
            )}

            {id && <ShieldActivity originId={id} />}
          </div>
        )}

        {activeTab === 'team' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {isOwner && (
              <div className="dash-card p-5 space-y-4">
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)] flex items-center gap-2">
                  <Users size={14} /> {t('Viewer access', 'สิทธิ์ Viewer')}
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  {t(
                    'Only you can see this origin by default. Grant another registered account read-only access below -- they will see it in their Origins list and in their Traffic Logs / Analytics, but cannot edit, delete, or manage its settings.',
                    'ปกติมีแค่คุณที่เห็น origin นี้ ให้สิทธิ์ดูอย่างเดียวกับบัญชีอื่นได้ด้านล่าง — ผู้ได้รับสิทธิ์จะเห็น origin นี้ในรายการ Origins, Log ทราฟฟิก และการวิเคราะห์ แต่แก้ไข ลบ หรือจัดการการตั้งค่าไม่ได้',
                  )}
                </p>
                <div className="flex gap-2">
                  <input
                    type="email"
                    value={viewerEmailInput}
                    onChange={(e) => setViewerEmailInput(e.target.value)}
                    placeholder="teammate@example.com"
                    className="flex-1 bg-[var(--bg-surface-elevated)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                  />
                  <Button
                    size="sm"
                    icon={<Plus size={14} />}
                    onClick={() => viewerEmailInput.trim() && guard('invite', () => addViewerMutation.mutate(viewerEmailInput.trim()))}
                    disabled={!viewerEmailInput.trim() || addViewerMutation.isPending}
                  >
                    {t('Add viewer', 'เพิ่ม viewer')}
                  </Button>
                </div>
                {viewersLoading ? (
                  <LoadingSpinner />
                ) : viewers.length === 0 ? (
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    {t('No viewers granted yet -- this origin is only visible to you.', 'ยังไม่มี viewer — ตอนนี้มีแค่คุณที่เห็น origin นี้')}
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
                          title={t('Revoke viewer access', 'ยกเลิกสิทธิ์ viewer')}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {isOwner && (
              <div className="dash-card p-5 space-y-4">
                <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)] flex items-center gap-2">
                  <Users size={14} /> {t('Editor access', 'สิทธิ์ Editor')}
                </h3>
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  {t(
                    'An Editor can rename this origin, change its IP/port, configure the CAPTCHA/OTP shield, and manage domains and WAF rules. Only the Owner can add or remove Editors and Viewers, or archive/restore the origin.',
                    'Editor เปลี่ยนชื่อ origin, แก้ IP/port, ตั้งค่า CAPTCHA/OTP shield และจัดการโดเมนกับกฎ WAF ได้ มีแค่ Owner ที่เพิ่ม/นำ Editor และ Viewer ออก หรือเก็บถาวร/กู้คืน origin ได้',
                  )}
                </p>
                <div className="flex gap-2">
                  <input
                    type="email"
                    value={editorEmailInput}
                    onChange={(e) => setEditorEmailInput(e.target.value)}
                    placeholder="teammate@example.com"
                    className="flex-1 bg-[var(--bg-surface-elevated)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                  />
                  <Button
                    size="sm"
                    icon={<Plus size={14} />}
                    onClick={() => editorEmailInput.trim() && guard('invite', () => addEditorMutation.mutate(editorEmailInput.trim()))}
                    disabled={!editorEmailInput.trim() || addEditorMutation.isPending}
                  >
                    {t('Add editor', 'เพิ่ม editor')}
                  </Button>
                </div>
                {editorsLoading ? (
                  <LoadingSpinner />
                ) : editors.length === 0 ? (
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    {t('No editors yet.', 'ยังไม่มี editor')}
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
                          title={t('Remove editor', 'นำ editor ออก')}
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
                <Code size={14} /> {t('Audit log', 'ประวัติการแก้ไข')}
              </h3>
              <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                {t(
                  'Who changed what and when on this origin -- settings, domains, and access grants. Kept for 180 days.',
                  'ใครเปลี่ยนอะไรเมื่อไรใน origin นี้ ทั้งการตั้งค่า โดเมน และการให้สิทธิ์ เก็บไว้ 180 วัน',
                )}
              </p>
              {auditLogLoading ? (
                <LoadingSpinner />
              ) : auditEvents.length === 0 ? (
                <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                  {t('No changes recorded yet.', 'ยังไม่มีการเปลี่ยนแปลง')}
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
                        {formatBkkDateTime(ev.timestamp)}
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
                title={t('Admins only', 'เฉพาะผู้ดูแล')}
                subtitle={t(
                  "Incident Postmortem reports are visible to this origin's Owner and Editors only -- they can include system-wide settings changes, not just this origin's own activity.",
                  'รายงานหลังเหตุการณ์ดูได้เฉพาะ Owner และ Editor ของ origin นี้ เพราะอาจมีการเปลี่ยนการตั้งค่าทั้งระบบ ไม่ใช่แค่กิจกรรมของ origin นี้',
                )}
              />
            ) : (
              <>
                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)] flex items-center gap-2">
                    <FileText size={14} /> {t('Generate incident report', 'สร้างรายงานเหตุการณ์')}
                  </h3>
                  <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                    {t(
                      'Pick a time range around an incident. The report correlates real traffic/alert volume in that window against the real audit trail -- including system-wide settings and ML rule changes -- and asks AI to draft an executive summary, timeline, root-cause hypothesis, and recommendations.',
                      'เลือกช่วงเวลารอบเหตุการณ์ รายงานจะเทียบปริมาณทราฟฟิก/การแจ้งเตือนจริงในช่วงนั้นกับประวัติการแก้ไขจริง รวมถึงการตั้งค่าทั้งระบบและการเปลี่ยนกฎ ML แล้วให้ AI ร่างบทสรุปผู้บริหาร ไทม์ไลน์ สมมติฐานต้นเหตุ และข้อแนะนำ',
                    )}
                  </p>
                  <div className="flex flex-wrap items-end gap-3">
                    <div className="space-y-1">
                      <label className="block text-[11px] text-[var(--text-muted)] font-mono">{t(`Start (${BKK_LABEL})`, 'เริ่ม (เวลากรุงเทพฯ)')}</label>
                      <input
                        type="datetime-local"
                        value={pmStart}
                        onChange={(e) => setPmStart(e.target.value)}
                        className="bg-[var(--bg-surface-elevated)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="block text-[11px] text-[var(--text-muted)] font-mono">{t(`End (${BKK_LABEL})`, 'สิ้นสุด (เวลากรุงเทพฯ)')}</label>
                      <input
                        type="datetime-local"
                        value={pmEnd}
                        onChange={(e) => setPmEnd(e.target.value)}
                        className="bg-[var(--bg-surface-elevated)] border border-[var(--bg-border-subtle)] rounded px-3 py-2 text-[12px] font-mono text-[var(--text-primary)]"
                      />
                    </div>
                    <Button
                      icon={<FileText size={14} />}
                      onClick={() => createPostmortemMutation.mutate()}
                      disabled={!pmStart || !pmEnd || createPostmortemMutation.isPending}
                      isLoading={createPostmortemMutation.isPending}
                    >
                      {t('Generate report', 'สร้างรายงาน')}
                    </Button>
                  </div>
                </div>

                <div className="dash-card p-5 space-y-4">
                  <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 pb-3 border-b border-[var(--bg-border-subtle)]">
                    {t('Past reports', 'รายงานที่ผ่านมา')}
                  </h3>
                  {postmortemsLoading ? (
                    <LoadingSpinner />
                  ) : postmortems.length === 0 ? (
                    <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                      {t('No reports generated yet.', 'ยังไม่มีรายงาน')}
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
                            {p.stats?.total_alerts ?? 0} {t('alerts', 'การแจ้งเตือน')}
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
                        {t('Report not found.', 'ไม่พบรายงาน')}
                      </p>
                    ) : (
                      <>
                        <div className="flex justify-between items-start gap-3 pb-3 border-b border-[var(--bg-border-subtle)]">
                          <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
                            {t('Report:', 'รายงาน:')} {selectedPostmortem.start_time} &rarr; {selectedPostmortem.end_time}
                          </h3>
                          <button
                            onClick={() => setSelectedPostmortemId(null)}
                            className="text-[var(--text-muted)] hover:text-[var(--text-primary)] text-[11px] font-mono"
                          >
                            {t('Close', 'ปิด')}
                          </button>
                        </div>

                        <div className="grid grid-cols-3 gap-3 font-mono text-[12px]">
                          <div className="dash-card p-3 text-center">
                            <div className="text-[var(--text-muted)] text-[11px]">{t('Total requests', 'Request ทั้งหมด')}</div>
                            <div className="text-[18px] font-bold text-[var(--text-primary)]">
                              {selectedPostmortem.stats?.total_requests ?? 0}
                            </div>
                          </div>
                          <div className="dash-card p-3 text-center">
                            <div className="text-[var(--text-muted)] text-[11px]">{t('Alerts / blocked', 'การแจ้งเตือน / ถูกบล็อก')}</div>
                            <div className="text-[18px] font-bold text-orange-500">
                              {selectedPostmortem.stats?.total_alerts ?? 0}
                            </div>
                          </div>
                          <div className="dash-card p-3 text-center">
                            <div className="text-[var(--text-muted)] text-[11px]">{t('Top attack type', 'ประเภทการโจมตีที่พบมากสุด')}</div>
                            <div className="text-[14px] font-bold text-[var(--text-primary)]">
                              {selectedPostmortem.stats?.top_attack_types?.[0]?.type || '-'}
                            </div>
                          </div>
                        </div>

                        {selectedPostmortem.ai_narrative ? (
                          <div className="space-y-2">
                            {selectedPostmortem.ai_narrative_degraded && (
                              <Badge color="warning">{t('AI summary may be truncated', 'สรุปจาก AI อาจไม่ครบ')}</Badge>
                            )}
                            <ReportText
                              text={selectedPostmortem.ai_narrative}
                              className="text-[12.5px] bg-[var(--bg-surface-elevated)] rounded p-4"
                            />
                          </div>
                        ) : (
                          <p className="text-[12px] text-[var(--text-muted)] font-mono m-0">
                            {t('AI summary unavailable for this report -- showing raw data below.', 'รายงานนี้ไม่มีสรุปจาก AI — แสดงข้อมูลดิบด้านล่าง')}
                          </p>
                        )}

                        <details className="font-mono text-[12px]">
                          <summary className="cursor-pointer text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                            {t(
                              `Raw timeline (${selectedPostmortem.audit_events?.length ?? 0} audit event(s), ${selectedPostmortem.hourly_buckets?.length ?? 0} hourly bucket(s))`,
                              `ไทม์ไลน์ดิบ (${selectedPostmortem.audit_events?.length ?? 0} เหตุการณ์ในประวัติ, ${selectedPostmortem.hourly_buckets?.length ?? 0} ช่วงรายชั่วโมง)`,
                            )}
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
                                    {formatBkkDateTime(ev.timestamp)}
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
        title={origin?.status === 'pending' ? t('Cancel setup', 'ยกเลิกการตั้งค่า') : t('Archive origin', 'เก็บ origin ถาวร')}
        message={
          origin
            ? origin.status === 'pending'
              ? t(`Are you sure you want to cancel the setup of origin "${origin.label}"?`, `ต้องการยกเลิกการตั้งค่า origin "${origin.label}" ใช่ไหม?`)
              : t(`Are you sure you want to archive origin "${origin.label}"?`, `ต้องการเก็บ origin "${origin.label}" ถาวรใช่ไหม?`)
            : ''
        }
        confirmText={origin?.status === 'pending' ? t('Cancel setup', 'ยกเลิกการตั้งค่า') : t('Archive origin', 'เก็บ origin ถาวร')}
        isDanger={true}
      />

      <ConfirmDialog
        open={isRestoreModalOpen}
        onCancel={() => setIsRestoreModalOpen(false)}
        onConfirm={handleRestore}
        title={t('Restore origin', 'กู้คืน origin')}
        message={t(
          `Are you sure you want to restore origin "${origin.label}" back to active service?`,
          `ต้องการกู้คืน origin "${origin.label}" ให้กลับมาใช้งานใช่ไหม?`,
        )}
        confirmText={t('Restore origin', 'กู้คืน origin')}
        isDanger={false}
      />
    </div>
  )
}

export default OriginDetail
