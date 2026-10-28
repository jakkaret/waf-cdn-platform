import React, { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  Ban,
  Bug,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  FlaskConical,
  Globe,
  RefreshCw,
  Server,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react'
import { mlRulesApi } from '../api/mlRules'
import { getOrigins } from '../api/origins'
import { useAuthStore } from '../store/authStore'
import { isOperator } from '../lib/permissions'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { Modal } from '../components/ui/Modal'
import { MLPendingRule, MLRuleGenerator } from '../types'
import {
  GENERATOR_LABEL,
  approveScope,
  approveWarning,
  backtestView,
  canBacktest,
  canBacktestRule,
  canReviewRule,
  canRevokeRule,
  cveScanOriginChoices,
  deployScopeOf,
  filterAndSortRules,
  generatorHint,
  generatorLabel,
  generatorOf,
  legacyPendingCount,
  renderSecRule,
  revokeScope,
  ruleOriginLabel,
  ruleOriginOptions,
  timeAgo,
  type BacktestTone,
  type RuleFilters,
} from '../lib/mlRules'
import { useT } from '../i18n'

const PAGE_SIZE = 15
// One empty list for "no data yet". `= []` in the destructuring made a new
// array on every render, so the prune effect below set state on every
// render while the query was loading or failing:
// "Maximum update depth exceeded".
const NO_RULES: MLPendingRule[] = []

type StatusTab = RuleFilters['status']

const STATUS_TABS: { id: StatusTab; label: string; labelEn: string }[] = [
  { id: 'pending', label: 'รออนุมัติ', labelEn: 'Pending' },
  { id: 'approved', label: 'ใช้งานอยู่', labelEn: 'Active' },
  { id: 'rejected', label: 'ปฏิเสธแล้ว', labelEn: 'Rejected' },
  { id: 'revoked', label: 'ยกเลิกแล้ว', labelEn: 'Revoked' },
  { id: 'all', label: 'ทั้งหมด', labelEn: 'All' },
]
// The CVE-scan dialog's value for "every origin" (platform admin only).
const ALL_ORIGINS = '__all__'

const BACKTEST_DOT: Record<BacktestTone, string> = {
  none: 'bg-[var(--text-dim)]',
  clean: 'bg-emerald-500',
  warn: 'bg-amber-500',
  danger: 'bg-red-500',
}
const BACKTEST_TEXT: Record<BacktestTone, string> = {
  none: 'text-[var(--text-muted)]',
  clean: 'text-emerald-700 dark:text-emerald-400',
  warn: 'text-amber-700 dark:text-amber-400',
  danger: 'text-red-700 dark:text-red-400',
}
const GENERATOR_PILL: Record<MLRuleGenerator, string> = {
  'gen3-detector': 'bg-[var(--accent-subtle)] text-[var(--accent)] border-[var(--accent-border)]',
  'rf-regex': 'bg-[var(--bg-primary)] text-[var(--text-secondary)] border-[var(--bg-border)]',
  cve: 'bg-sky-500/10 text-sky-700 dark:text-sky-300 border-sky-500/25',
}

const selectClass = 'dash-input h-9 text-[13px] cursor-pointer'
const pillBase = 'inline-flex items-center rounded-full border px-2 py-px text-[11.5px] font-medium whitespace-nowrap'

interface PendingApproval {
  ids: string[]
  scope: string
  warning: string | null
}

// `embedded`: rendered inside Rule proposals, which owns the page header.
export const MLRules: React.FC<{ embedded?: boolean }> = ({ embedded = false }) => {
  const { user } = useAuthStore()
  const queryClient = useQueryClient()
  const { t, lang } = useT()
  const ago = (iso?: string) => timeAgo(iso, Date.now(), lang)

  const [filters, setFilters] = useState<RuleFilters>({
    status: 'pending', generator: 'all', attackType: 'all', search: '', sort: 'hits', origin: 'all',
  })
  const [page, setPage] = useState(1)
  const [expanded, setExpanded] = useState<string[]>([])
  const [selected, setSelected] = useState<string[]>([])
  const [testing, setTesting] = useState<string[]>([])
  const [rejecting, setRejecting] = useState<string[] | null>(null)
  const [rejectReason, setRejectReason] = useState('')
  const [approval, setApproval] = useState<PendingApproval | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirmLegacy, setConfirmLegacy] = useState(false)
  const [revoking, setRevoking] = useState<MLPendingRule | null>(null)
  const [revokeReason, setRevokeReason] = useState('')
  const [scanOpen, setScanOpen] = useState(false)
  const [scanTarget, setScanTarget] = useState('')

  // A platform admin gets the whole queue; anyone else only the rules of
  // origins they belong to, each flagged with what they may do to it.
  const { data, isLoading, isFetching, isError, refetch } = useQuery({
    queryKey: ['ml-rules'],
    queryFn: () => mlRulesApi.listQueue(),
    refetchInterval: 10000,
  })
  const rules = data?.rules ?? NO_RULES
  const isAdmin = data?.is_admin ?? isOperator(user)
  const canReview = (rule: MLPendingRule) => canReviewRule(rule, isAdmin)
  const mayBacktest = (rule: MLPendingRule) => canBacktestRule(rule, isAdmin)
  const refresh = () => queryClient.invalidateQueries({ queryKey: ['ml-rules'] })

  // Same key and response shape as the Origins page, so the cache is shared.
  const { data: originsRes } = useQuery({ queryKey: ['origins'], queryFn: () => getOrigins() })
  const scanChoices = useMemo(
    () => cveScanOriginChoices(originsRes?.data?.origins ?? [], user?.user_id),
    [originsRes, user?.user_id],
  )
  const canScan = isAdmin || scanChoices.length > 0
  const scanPick = scanChoices.find((c) => c.id === scanTarget)

  const originOptions = useMemo(() => ruleOriginOptions(rules), [rules])
  const reviewable = useMemo(() => rules.filter((r) => canReviewRule(r, isAdmin)), [rules, isAdmin])

  const counts = useMemo(() => {
    const by = (s: string) => rules.filter((r) => r.status === s).length
    return { pending: by('pending'), approved: by('approved'), rejected: by('rejected'), revoked: by('revoked'), all: rules.length }
  }, [rules])

  const legacyPending = useMemo(() => legacyPendingCount(rules), [rules])

  const rejectLegacy = useMutation({
    mutationFn: () => mlRulesApi.rejectLegacy(),
    onSuccess: (res) => {
      toast.success(
        t(
          `Rejected ${res.rejected} legacy rules` + (res.skipped ? ` (skipped ${res.skipped} already reviewed)` : ''),
          `ปฏิเสธกฎแบบเก่าแล้ว ${res.rejected} กฎ` + (res.skipped ? ` (ข้าม ${res.skipped} กฎที่มีคนรีวิวไปก่อน)` : ''),
        ),
      )
      setSelected([])
      setConfirmLegacy(false)
      refresh()
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || t('Could not reject the legacy rules', 'ปฏิเสธกฎแบบเก่าไม่สำเร็จ')),
  })

  const attackTypes = useMemo(
    () => Array.from(new Set(rules.map((r) => r.attack_type).filter(Boolean))).sort(),
    [rules],
  )

  const visible = useMemo(() => filterAndSortRules(rules, filters), [rules, filters])
  const totalPages = Math.max(1, Math.ceil(visible.length / PAGE_SIZE))
  const pageRules = visible.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)
  // Only rules the caller may approve or reject are selectable.
  const pendingOnPage = pageRules.filter(canReview)

  // The queue polls every 10 s; another reviewer can shrink it under the
  // current page or review a selected rule. Clamp and prune, never act on a
  // rule that is no longer pending.
  useEffect(() => {
    if (page > totalPages) setPage(totalPages)
  }, [page, totalPages])
  useEffect(() => {
    const open = new Set(reviewable.map((r) => r.rule_id))
    setSelected((prev) => prev.filter((id) => open.has(id)))
  }, [reviewable])
  // The selected origin left the queue (rules reviewed away, membership removed).
  useEffect(() => {
    if (filters.origin !== 'all' && !originOptions.some((o) => o.id === filters.origin)) {
      setFilters((f) => ({ ...f, origin: 'all' }))
    }
  }, [filters.origin, originOptions])

  const setFilter = <K extends keyof RuleFilters>(key: K, value: RuleFilters[K]) => {
    setFilters((f) => ({ ...f, [key]: value }))
    setPage(1)
  }
  const filtersActive =
    filters.generator !== 'all' || filters.attackType !== 'all' || filters.search.trim() !== '' || filters.origin !== 'all'

  // "" in the request = every origin (admin); otherwise one origin's tags only.
  const cveScan = useMutation({
    mutationFn: (originId: string) => mlRulesApi.runCveScan(originId || undefined),
    onSuccess: (res) => {
      setScanOpen(false)
      const searched: string[] = res.keywords_searched || []
      if (searched.length === 0) {
        toast.error(t('No origin has tech stack tags yet. Add tags on the origin page before scanning.', 'ยังไม่มี origin ที่ตั้ง tech stack tag ไว้ เพิ่ม tag ที่หน้า origin ก่อนสแกน'))
        return
      }
      toast.success(
        res.proposals_created > 0
          ? t(
              `CVE scan done: proposed ${res.proposals_created} new rules from ${res.matches_found} matches`,
              `สแกน CVE เสร็จ: เสนอกฎใหม่ ${res.proposals_created} ข้อ จาก ${res.matches_found} รายการที่ตรง`,
            )
          : t(
              `CVE scan done: ${res.matches_found} matches but no new rule (duplicates ${res.skipped_duplicate}, unusable pattern ${res.skipped_no_valid_pattern})`,
              `สแกน CVE เสร็จ: ตรง ${res.matches_found} รายการ แต่ไม่มีกฎใหม่ (ซ้ำ ${res.skipped_duplicate}, pattern ใช้ไม่ได้ ${res.skipped_no_valid_pattern})`,
            ),
      )
      refresh()
    },
    onError: (err: any) => toast.error(
      err.response?.status === 429
        ? t('This origin reached its scans per hour. Try again later.', 'สแกน origin นี้ครบจำนวนต่อชั่วโมงแล้ว ลองใหม่ภายหลัง')
        : err.response?.data?.detail || t('CVE scan failed', 'สแกน CVE ไม่สำเร็จ'),
    ),
  })

  const openScan = () => {
    setScanTarget(isAdmin ? ALL_ORIGINS : (scanChoices.find((c) => c.hasTags) ?? scanChoices[0])?.id ?? '')
    setScanOpen(true)
  }

  const revokeRule = async () => {
    if (!revoking) return
    setBusy(true)
    try {
      await mlRulesApi.revokeRule(revoking.rule_id, revokeReason.trim())
      toast.success(t('Revoked. The rule stopped on the WAF.', 'ยกเลิกการใช้งานแล้ว กฎหยุดทำงานกับ WAF ทันที'))
      setRevoking(null)
      setRevokeReason('')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || t('Could not revoke the rule', 'ยกเลิกการใช้งานไม่สำเร็จ'))
    } finally {
      setBusy(false)
      refresh()
    }
  }

  const runBacktest = async (ids: string[]) => {
    setTesting((cur) => [...cur, ...ids])
    let failed = 0
    for (const id of ids) {
      try {
        await mlRulesApi.backtestRule(id)
      } catch (err: any) {
        failed += 1
        if (ids.length === 1) toast.error(err.response?.data?.detail || t('Could not test the rule', 'ทดสอบกฎไม่สำเร็จ'))
      } finally {
        setTesting((cur) => cur.filter((x) => x !== id))
      }
    }
    if (ids.length > 1) {
      if (failed) toast.error(t(`${failed} of ${ids.length} tests failed`, `ทดสอบไม่สำเร็จ ${failed} จาก ${ids.length} กฎ`))
      else toast.success(t(`Tested all ${ids.length} rules`, `ทดสอบครบ ${ids.length} กฎแล้ว`))
    }
    refresh()
  }

  const approveIds = async (ids: string[]) => {
    setBusy(true)
    const results = await Promise.allSettled(ids.map((id) => mlRulesApi.approveRule(id)))
    const ok = results.filter((r) => r.status === 'fulfilled').length
    if (ok)
      toast.success(
        ids.length === 1
          ? t('Approved. The rule is live in ModSecurity.', 'อนุมัติแล้ว กฎมีผลกับ ModSecurity ทันที')
          : t(`Approved ${ok} rules`, `อนุมัติแล้ว ${ok} กฎ`),
      )
    // e.g. 403 "Owner or Editor of this origin required" after a role change.
    if (ok < ids.length) {
      const first = results.find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined
      toast.error(first?.reason?.response?.data?.detail || t(`${ids.length - ok} approvals failed`, `อนุมัติไม่สำเร็จ ${ids.length - ok} กฎ`))
    }
    setSelected((s) => s.filter((id) => !ids.includes(id)))
    setApproval(null)
    setBusy(false)
    refresh()
  }

  // Always confirm: the dialog says where the rule takes effect (one origin
  // or every origin) and any backtest risk.
  const requestApprove = (ids: string[]) => {
    const targets = rules.filter((r) => ids.includes(r.rule_id) && canReview(r))
    if (targets.length === 0) return
    const risky = targets.filter((r) => approveWarning(r) !== null).length
    setApproval({
      ids: targets.map((r) => r.rule_id),
      scope: approveScope(targets, lang),
      warning:
        targets.length === 1
          ? approveWarning(targets[0], lang)
          : risky
            ? t(`${risky} of these are untested or match normal traffic`, `ในนี้มี ${risky} ข้อที่ยังไม่ได้ทดสอบหรือชน traffic ปกติ`)
            : null,
    })
  }

  const rejectIds = async () => {
    if (!rejecting) return
    setBusy(true)
    const results = await Promise.allSettled(rejecting.map((id) => mlRulesApi.rejectRule(id, rejectReason.trim())))
    const ok = results.filter((r) => r.status === 'fulfilled').length
    if (ok) toast.success(rejecting.length === 1 ? t('Rule rejected', 'ปฏิเสธกฎแล้ว') : t(`Rejected ${ok} rules`, `ปฏิเสธแล้ว ${ok} กฎ`))
    if (ok < rejecting.length) {
      const first = results.find((r) => r.status === 'rejected') as PromiseRejectedResult | undefined
      toast.error(first?.reason?.response?.data?.detail || t(`${rejecting.length - ok} rejections failed`, `ปฏิเสธไม่สำเร็จ ${rejecting.length - ok} กฎ`))
    }
    setSelected((s) => s.filter((id) => !rejecting.includes(id)))
    setRejecting(null)
    setRejectReason('')
    setBusy(false)
    refresh()
  }

  const copyRule = (rule: MLPendingRule) => {
    const text = renderSecRule(rule)
    navigator.clipboard.writeText(text).then(
      () => toast.success(t('Copied the SecRule', 'คัดลอก SecRule แล้ว')),
      () => toast.error(t('Could not copy', 'คัดลอกไม่สำเร็จ')),
    )
  }

  const toggle = (list: string[], id: string) => (list.includes(id) ? list.filter((x) => x !== id) : [...list, id])
  const allPageSelected = pendingOnPage.length > 0 && pendingOnPage.every((r) => selected.includes(r.rule_id))

  const renderRow = (rule: MLPendingRule) => {
    const gen = generatorOf(rule)
    const open = expanded.includes(rule.rule_id)
    const pending = rule.status === 'pending'
    const bt = backtestView(rule.backtest, lang)
    const isTesting = testing.includes(rule.rule_id)
    const hits = rule.hit_count ?? 1
    const panelId = `rule-panel-${rule.rule_id}`
    const reviewer = canReview(rule)
    const globalScope = deployScopeOf(rule) === 'global'

    return (
      <li key={rule.rule_id} className={`border-b border-[var(--bg-border-subtle)] last:border-b-0 ${selected.includes(rule.rule_id) ? 'bg-[var(--accent-subtle)]' : ''}`}>
        <div className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-2 px-4 py-3.5 xl:grid-cols-[auto_minmax(0,1fr)_8.5rem_12rem_16.5rem] xl:items-center">
          <div className="pt-0.5 xl:pt-0">
            {reviewer ? (
              <input
                type="checkbox"
                aria-label={t(`Select rule ${rule.attack_type}`, `เลือกกฎ ${rule.attack_type}`)}
                checked={selected.includes(rule.rule_id)}
                onChange={() => setSelected((s) => toggle(s, rule.rule_id))}
                className="h-4 w-4 accent-[var(--accent)] dark:[color-scheme:dark] cursor-pointer"
              />
            ) : (
              <span className="block h-4 w-4" aria-hidden="true" />
            )}
          </div>

          <button
            type="button"
            onClick={() => setExpanded((e) => toggle(e, rule.rule_id))}
            aria-expanded={open}
            aria-controls={panelId}
            className="min-w-0 text-left rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] cursor-pointer"
          >
            <span className="flex flex-wrap items-center gap-2">
              <ChevronRight
                size={15}
                aria-hidden="true"
                className={`shrink-0 text-[var(--text-muted)] transition-transform duration-150 motion-reduce:transition-none ${open ? 'rotate-90' : ''}`}
              />
              <span className="text-[14px] font-semibold text-[var(--text-primary)]">{rule.attack_type}</span>
              <span className={`${pillBase} ${GENERATOR_PILL[gen]}`} title={generatorHint(gen, lang)}>{generatorLabel(gen, lang)}</span>
              <span
                className={`${pillBase} gap-1 border-[var(--bg-border)] bg-[var(--bg-primary)] text-[var(--text-secondary)]`}
                title={globalScope ? t('This rule applies to every origin', 'กฎนี้มีผลกับทุก origin') : t(`This rule applies only to ${ruleOriginLabel(rule)}`, `กฎนี้มีผลเฉพาะ ${ruleOriginLabel(rule)}`)}
              >
                {globalScope ? <Globe size={11} aria-hidden="true" /> : <Server size={11} aria-hidden="true" />}
                <span className="max-w-[14rem] truncate">{ruleOriginLabel(rule)}</span>
              </span>
              {rule.status === 'approved' && (
                <span className={`${pillBase} border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300`}>
                  {t('Active', 'ใช้งานอยู่')} #{rule.deployed_rule_id}
                </span>
              )}
              {rule.status === 'rejected' && (
                <span className={`${pillBase} border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-300`}>{t('Rejected', 'ปฏิเสธแล้ว')}</span>
              )}
              {rule.status === 'revoked' && (
                <span className={`${pillBase} border-[var(--bg-border)] bg-[var(--bg-primary)] text-[var(--text-secondary)]`}>
                  {t('Revoked', 'ยกเลิกแล้ว')} #{rule.deployed_rule_id}
                </span>
              )}
            </span>
            <span className="mt-1 ml-[23px] block truncate font-mono text-[12.5px] text-[var(--text-secondary)]" title={rule.pattern}>
              {rule.pattern}
            </span>
          </button>

          <div className="col-start-2 xl:col-start-auto text-[12.5px]">
            <span className="font-semibold tabular-nums text-[var(--text-primary)]">{hits.toLocaleString()}</span>
            <span className="text-[var(--text-muted)]"> request</span>
            <span className="block text-[12px] text-[var(--text-muted)]">{ago(rule.last_seen_at || rule.created_at)}</span>
          </div>

          <div className="col-start-2 xl:col-start-auto text-[12.5px]">
            {canBacktest(rule) ? (
              <>
                <span className={`flex items-center gap-1.5 font-medium ${BACKTEST_TEXT[bt.tone]}`}>
                  <span className={`h-2 w-2 shrink-0 rounded-full ${BACKTEST_DOT[bt.tone]}`} aria-hidden="true" />
                  {isTesting ? t('Testing...', 'กำลังทดสอบ...') : bt.label}
                </span>
                {rule.backtest && !isTesting && (
                  <span className="block text-[12px] text-[var(--text-muted)]">{t('tested', 'ทดสอบ')} {ago(rule.backtest.ran_at)}</span>
                )}
              </>
            ) : (
              <span className="text-[var(--text-muted)]">{t('Cannot test (CVE)', 'ทดสอบไม่ได้ (CVE)')}</span>
            )}
          </div>

          <div className="col-start-2 xl:col-start-auto flex flex-wrap xl:flex-nowrap items-center gap-2 xl:justify-end">
            {mayBacktest(rule) && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => runBacktest([rule.rule_id])}
                isLoading={isTesting}
                icon={<FlaskConical size={13} />}
              >
                {t('Test', 'ทดสอบ')}
              </Button>
            )}
            {pending && !reviewer && (
              <span
                className="text-[12px] text-[var(--text-muted)]"
                title={t('Only an Owner or Editor of this origin can approve or reject', 'อนุมัติหรือปฏิเสธได้เฉพาะ Owner หรือ Editor ของ origin นี้')}
              >
                {t('Waiting for an Owner/Editor', 'รอ Owner/Editor อนุมัติ')}
              </span>
            )}
            {reviewer && (
              <>
                <Button variant="ghost" size="sm" onClick={() => { setRejectReason(''); setRejecting([rule.rule_id]) }}>
                  {t('Reject', 'ปฏิเสธ')}
                </Button>
                <Button variant="brand" size="sm" onClick={() => requestApprove([rule.rule_id])} disabled={busy} icon={<Check size={13} />}>
                  {t('Approve', 'อนุมัติ')}
                </Button>
              </>
            )}
            {canRevokeRule(rule) && (
              <Button variant="ghost" size="sm" onClick={() => { setRevokeReason(''); setRevoking(rule) }} icon={<Ban size={13} />}>
                {t('Revoke', 'ยกเลิกการใช้งาน')}
              </Button>
            )}
            {rule.status === 'approved' && !canRevokeRule(rule) && !isAdmin && globalScope && (
              <span
                className="text-[12px] text-[var(--text-muted)]"
                title={t('This rule applies to every origin, so only the platform operator can revoke it', 'กฎนี้มีผลกับทุก origin จึงยกเลิกได้เฉพาะผู้ดูแลแพลตฟอร์ม')}
              >
                {t('Only the platform operator can revoke', 'ยกเลิกได้เฉพาะผู้ดูแลแพลตฟอร์ม')}
              </span>
            )}
          </div>
        </div>

        {open && (
          <div id={panelId} className="grid gap-4 px-4 pb-4 md:pl-[3.25rem] lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <section className="min-w-0">
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <h3 className="m-0 text-[12.5px] font-medium text-[var(--text-secondary)]">
                  {rule.deploy_scope === 'origin'
                    ? t('SecRule (the part that checks the request)', 'SecRule (ส่วนที่ใช้ตรวจ request)')
                    : t('SecRule to be deployed', 'SecRule ที่จะติดตั้ง')}
                </h3>
                <button
                  type="button"
                  onClick={() => copyRule(rule)}
                  className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[12px] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
                >
                  <Copy size={12} aria-hidden="true" /> {t('Copy', 'คัดลอก')}
                </button>
              </div>
              <pre className="m-0 overflow-x-auto rounded-lg border border-[var(--bg-border)] bg-[var(--bg-primary)] p-3 font-mono text-[12px] leading-relaxed text-[var(--text-primary)]">
                {rule.secrule_template
                  ? renderSecRule(rule)
                  : t('No SecRule template', 'ไม่มี SecRule template')}
              </pre>
              {/* What approve writes is a two-link chain (rule_manager.scope_ml_rule_to_origin):
                  the origin guard first, then this rule as the chained link. */}
              {rule.deploy_scope === 'origin' && (
                <p className="mt-2 mb-0 text-[12px] leading-relaxed text-[var(--text-muted)]">
                  {t('On deploy, the rule is wrapped in a', 'ตอนติดตั้ง ระบบจะครอบกฎนี้ด้วยเงื่อนไข')}{' '}
                  <code className="font-mono">TX:waf_origin_id</code>{' '}
                  {t(
                    `condition so it only runs for requests of ${rule.origin_label || 'this origin'} (the chain's first rule checks the origin, then the rule above).`,
                    `ให้ทำงานเฉพาะ request ของ ${rule.origin_label || 'origin นี้'} (กฎแรกของ chain เช็ค origin แล้วค่อยเช็คกฎด้านบน)`,
                  )}
                </p>
              )}
              <p className="mt-2 mb-0 text-[12px] leading-relaxed text-[var(--text-muted)]">{generatorHint(gen, lang)}</p>
            </section>

            <section className="min-w-0 space-y-4">
              {canBacktest(rule) && (
                <div>
                  <h3 className="m-0 mb-1.5 text-[12.5px] font-medium text-[var(--text-secondary)]">{t('Test against real traffic', 'ผลทดสอบกับ traffic จริง')}</h3>
                  <p className={`m-0 text-[13px] ${BACKTEST_TEXT[bt.tone]}`}>{bt.detail}</p>
                  {rule.backtest && rule.backtest.example_paths.length > 0 && (
                    <ul className="mt-1.5 mb-0 space-y-0.5 pl-0 list-none">
                      {rule.backtest.example_paths.map((p) => (
                        <li key={p} className="truncate font-mono text-[12px] text-[var(--text-secondary)]">{p}</li>
                      ))}
                    </ul>
                  )}
                  <p className="mt-1.5 mb-0 text-[11.5px] leading-relaxed text-[var(--text-muted)]">
                    {t('Uses the latest requests the WAF let through, without bodies; only paths are shown.', 'ใช้ request ล่าสุดที่ WAF ปล่อยผ่าน ไม่รวม body และแสดงเฉพาะ path')}
                  </p>
                </div>
              )}

              <div>
                <h3 className="m-0 mb-1.5 text-[12.5px] font-medium text-[var(--text-secondary)]">{t('Requests that led to this rule', 'Request ที่ทำให้เสนอกฎนี้')}</h3>
                <ul className="m-0 space-y-1 pl-0 list-none">
                  {(rule.examples && rule.examples.length > 0
                    ? rule.examples
                    : [{ url: rule.source_url, method: rule.source_method, seen_at: rule.created_at, requested_by: undefined as string | undefined }]
                  ).map((ex, i) => (
                    <li key={`${ex.seen_at}-${i}`} className="flex items-baseline gap-2 text-[12px]">
                      <span className="shrink-0 font-mono text-[var(--text-muted)]">{ex.method || 'GET'}</span>
                      <span className="min-w-0 truncate font-mono text-[var(--text-primary)]" title={ex.url}>{ex.url || '/'}</span>
                      {ex.requested_by && (
                        <span className="shrink-0 text-[var(--text-secondary)]" title={t('Who asked for this proposal', 'ผู้ที่กดขอให้เสนอกฎนี้')}>{t('requested by', 'ขอโดย')} {ex.requested_by}</span>
                      )}
                      <span className="ml-auto shrink-0 text-[var(--text-muted)]">{ago(ex.seen_at)}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {rule.status !== 'pending' && rule.reviewed_by && (
                <p className="m-0 text-[12px] text-[var(--text-muted)]">
                  {rule.status === 'rejected' ? t('Rejected by', 'ปฏิเสธโดย') : t('Approved by', 'อนุมัติโดย')} {rule.reviewed_by} {ago(rule.reviewed_at)}
                  {rule.reject_reason && <span className="block text-[var(--text-secondary)]">{t('Reason:', 'เหตุผล:')} {rule.reject_reason}</span>}
                </p>
              )}
              {rule.status === 'revoked' && rule.revoked_by && (
                <p className="m-0 text-[12px] text-[var(--text-muted)]">
                  {t('Revoked by', 'ยกเลิกการใช้งานโดย')} {rule.revoked_by} {ago(rule.revoked_at)}
                  {rule.revoke_reason && <span className="block text-[var(--text-secondary)]">{t('Reason:', 'เหตุผล:')} {rule.revoke_reason}</span>}
                </p>
              )}
            </section>
          </div>
        )}
      </li>
    )
  }

  return (
    <div className={embedded ? '' : 'animate-fade-in pb-12'}>
      {(() => {
        const subtitle = isAdmin
          ? t(
              'Rules the ML model proposed from detected requests. A rule has no effect on ModSecurity until someone approves it.',
              'กฎที่โมเดล ML เสนอจาก request ที่ตรวจพบ กฎจะยังไม่มีผลกับ ModSecurity จนกว่าจะมีคนอนุมัติ',
            )
          : t(
              'Rules the ML model proposed for origins you belong to. Once an Owner or Editor approves one, it applies to that origin only.',
              'กฎที่โมเดล ML เสนอสำหรับ origin ที่คุณเป็นสมาชิก เมื่อ Owner หรือ Editor อนุมัติแล้ว กฎจะมีผลเฉพาะ origin นั้น',
            )
        const actions = (
          <div className="flex items-center gap-2">
            {canScan && (
              <Button variant="secondary" onClick={openScan} isLoading={cveScan.isPending} icon={<Bug size={14} />}>
                {t('Scan for CVEs', 'สแกน CVE')}
              </Button>
            )}
            <Button
              variant="secondary"
              onClick={() => refetch()}
              aria-label={t('Refresh the rule list', 'รีเฟรชรายการกฎ')}
              title={t('Refresh', 'รีเฟรช')}
              icon={<RefreshCw size={14} className={isFetching ? 'animate-spin motion-reduce:animate-none' : ''} />}
            />
          </div>
        )
        return embedded ? (
          <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="m-0 text-[13px] text-[var(--text-muted)] max-w-[72ch]">{subtitle}</p>
            {actions}
          </div>
        ) : (
          <TopBar title={t('ML anomaly rules', 'กฎ ML anomaly')} subtitle={subtitle} action={actions} />
        )
      })()}

      {isAdmin && legacyPending > 0 && (
        <div className="mb-4 flex flex-col gap-3 rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="m-0 text-[13px] leading-relaxed text-[var(--text-secondary)]">
            <strong className="font-medium text-[var(--text-primary)]">
              {t(`${legacyPending} legacy rules are waiting for approval`, `มีกฎแบบเก่ารออนุมัติ ${legacyPending} กฎ`)}
            </strong>{' '}
            {t(
              'They come from the retired RandomForest model and mostly match only their source request.',
              'มาจาก RandomForest ที่เลิกใช้แล้ว ส่วนใหญ่ตรงแค่ request ต้นทาง',
            )}
          </p>
          <Button variant="secondary" className="shrink-0" onClick={() => setConfirmLegacy(true)} icon={<X size={14} />}>
            {t('Reject all legacy rules', 'ปฏิเสธกฎแบบเก่าทั้งหมด')}
          </Button>
        </div>
      )}

      <div className="dash-card overflow-hidden">
        <div className="flex flex-col gap-3 border-b border-[var(--bg-border)] p-3.5 lg:flex-row lg:items-center lg:justify-between">
          <div role="tablist" aria-label={t('Rule status', 'สถานะกฎ')} className="flex flex-wrap gap-1">
            {STATUS_TABS.map((tab) => {
              const active = filters.status === tab.id
              return (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setFilter('status', tab.id)}
                  className={`flex items-center gap-2 rounded-md px-3 h-9 text-[13px] transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
                    active
                      ? 'bg-[var(--nav-active)] font-medium text-[var(--text-primary)]'
                      : 'text-[var(--text-secondary)] hover:bg-[var(--nav-hover)] hover:text-[var(--text-primary)]'
                  }`}
                >
                  {lang === 'th' ? tab.label : tab.labelEn}
                  <span className={`rounded-full px-1.5 text-[11.5px] tabular-nums ${active ? 'bg-[var(--bg-surface)] text-[var(--text-primary)]' : 'bg-[var(--bg-primary)] text-[var(--text-muted)]'}`}>
                    {counts[tab.id]}
                  </span>
                </button>
              )
            })}
          </div>

          <label className="relative block lg:w-80">
            <span className="sr-only">{t('Search rules', 'ค้นหากฎ')}</span>
            <Search size={15} aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)]" />
            <input
              type="search"
              value={filters.search}
              onChange={(e) => setFilter('search', e.target.value)}
              placeholder={t('Search type, pattern, URL, CVE', 'ค้นหาประเภท, pattern, URL, CVE')}
              className="dash-input h-9 w-full pl-9 text-[13px]"
            />
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--bg-border-subtle)] bg-[var(--bg-primary)] px-3.5 py-2.5">
          {originOptions.length > 1 && (
            <select aria-label="Origin" className={selectClass} value={filters.origin} onChange={(e) => setFilter('origin', e.target.value)}>
              <option value="all">{t('All origins', 'ทุก origin')}</option>
              {originOptions.map((o) => <option key={o.id || 'global'} value={o.id}>{o.label}</option>)}
            </select>
          )}
          <select aria-label={t('Rule generator', 'ตัวสร้างกฎ')} className={selectClass} value={filters.generator} onChange={(e) => setFilter('generator', e.target.value as RuleFilters['generator'])}>
            <option value="all">{t('All generators', 'ทุกตัวสร้างกฎ')}</option>
            {(Object.keys(GENERATOR_LABEL) as MLRuleGenerator[]).map((g) => (
              <option key={g} value={g}>{generatorLabel(g, lang)}</option>
            ))}
          </select>
          <select aria-label={t('Attack type', 'ประเภทการโจมตี')} className={selectClass} value={filters.attackType} onChange={(e) => setFilter('attackType', e.target.value)}>
            <option value="all">{t('All attack types', 'ทุกประเภทการโจมตี')}</option>
            {attackTypes.map((type) => <option key={type} value={type}>{type}</option>)}
          </select>
          <select aria-label={t('Sort by', 'เรียงตาม')} className={selectClass} value={filters.sort} onChange={(e) => setFilter('sort', e.target.value as RuleFilters['sort'])}>
            <option value="hits">{t('Sort by request count', 'เรียงตามจำนวน request')}</option>
            <option value="newest">{t('Sort by newest', 'เรียงตามล่าสุด')}</option>
          </select>
          {filtersActive && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => { setFilters((f) => ({ ...f, generator: 'all', attackType: 'all', search: '', origin: 'all' })); setPage(1) }}
            >
              {t('Clear filters', 'ล้างตัวกรอง')}
            </Button>
          )}
          <span className="ml-auto text-[12.5px] text-[var(--text-muted)]">{visible.length.toLocaleString()} {t('rules', 'กฎ')}</span>
        </div>

        {selected.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 border-b border-[var(--accent-border)] bg-[var(--accent-subtle)] px-3.5 py-2.5">
            <span className="text-[13px] font-medium text-[var(--text-primary)]">{t(`${selected.length} selected`, `เลือก ${selected.length} กฎ`)}</span>
            <Button variant="ghost" size="sm" onClick={() => setSelected([])}>{t('Clear selection', 'ยกเลิกการเลือก')}</Button>
            <div className="ml-auto flex flex-wrap gap-2">
              <Button
                variant="secondary"
                size="sm"
                icon={<FlaskConical size={13} />}
                isLoading={testing.length > 0}
                disabled={!rules.some((r) => selected.includes(r.rule_id) && mayBacktest(r))}
                onClick={() => runBacktest(rules.filter((r) => selected.includes(r.rule_id) && mayBacktest(r)).map((r) => r.rule_id))}
              >
                {t('Test selected', 'ทดสอบที่เลือก')}
              </Button>
              <Button variant="secondary" size="sm" onClick={() => { setRejectReason(''); setRejecting(selected) }}>{t('Reject', 'ปฏิเสธ')}</Button>
              <Button variant="brand" size="sm" icon={<Check size={13} />} onClick={() => requestApprove(selected)} disabled={busy}>
                {t('Approve', 'อนุมัติ')}
              </Button>
            </div>
          </div>
        )}

        {pageRules.length > 0 && (
          <div className="hidden xl:grid grid-cols-[auto_minmax(0,1fr)_8.5rem_12rem_16.5rem] items-center gap-x-3 border-b border-[var(--bg-border-subtle)] px-4 py-2 text-[12px] font-medium text-[var(--text-muted)]">
            {pendingOnPage.length > 0 ? (
              <input
                type="checkbox"
                aria-label={t('Select the pending rules on this page', 'เลือกกฎที่รออนุมัติในหน้านี้')}
                checked={allPageSelected}
                onChange={() =>
                  setSelected((s) =>
                    allPageSelected
                      ? s.filter((id) => !pendingOnPage.some((r) => r.rule_id === id))
                      : Array.from(new Set([...s, ...pendingOnPage.map((r) => r.rule_id)])),
                  )
                }
                className="h-4 w-4 accent-[var(--accent)] dark:[color-scheme:dark] cursor-pointer"
              />
            ) : (
              <span className="block w-4" aria-hidden="true" />
            )}
            <span>{t('Rule', 'กฎ')}</span>
            <span>{t('Seen', 'พบ')}</span>
            <span>{t('Test against real traffic', 'ทดสอบกับ traffic จริง')}</span>
            <span className="sr-only">{t('Actions', 'การทำงาน')}</span>
          </div>
        )}

        {isLoading ? (
          <p className="m-0 flex items-center justify-center gap-2 py-16 text-[13px] text-[var(--text-muted)]">
            <RefreshCw size={16} className="animate-spin motion-reduce:animate-none" aria-hidden="true" /> {t('Loading rules', 'กำลังโหลดกฎ')}
          </p>
        ) : isError ? (
          <div className="py-14 text-center">
            <p className="m-0 text-[13.5px] text-[var(--text-primary)]">{t('Could not load the rules', 'โหลดรายการกฎไม่สำเร็จ')}</p>
            <Button variant="secondary" size="sm" className="mt-3" onClick={() => refetch()}>{t('Try again', 'ลองใหม่')}</Button>
          </div>
        ) : pageRules.length === 0 ? (
          <div className="px-6 py-14 text-center">
            {filters.status === 'pending' && !filtersActive ? (
              <>
                <ShieldCheck size={28} className="mx-auto text-emerald-500" aria-hidden="true" />
                <p className="mt-3 mb-1 text-[14px] font-medium text-[var(--text-primary)]">{t('No rules waiting for approval', 'ไม่มีกฎรออนุมัติ')}</p>
                {isAdmin ? (
                  <p className="m-0 mx-auto max-w-md text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                    {t('New rules come from ML insights when Gen 3 detects an attack, and from the CVE scan button.', 'กฎใหม่มาจากหน้า ML insights เมื่อ Gen 3 ตรวจพบการโจมตี และจากปุ่มสแกน CVE')}
                  </p>
                ) : (
                  <p className="m-0 mx-auto max-w-md text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                    {t(
                      'Proposed rules show up here when, on',
                      'กฎที่เสนอจะขึ้นที่นี่เมื่อคุณวิเคราะห์ request ของ origin ที่คุณเป็น Owner หรือ Editor ในหน้า',
                    )}{' '}
                    <Link to="/ml-analyst" className="font-medium text-[var(--accent)] hover:text-[var(--accent-hover)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] rounded">
                      ML insights
                    </Link>{' '}
                    {t(
                      ', Gen 3 flags an attack on an origin where you are Owner or Editor. You only see rules of origins you belong to.',
                      'แล้ว Gen 3 ตรวจพบการโจมตี คุณเห็นเฉพาะกฎของ origin ที่คุณเป็นสมาชิก',
                    )}
                  </p>
                )}
              </>
            ) : (
              <>
                <Sparkles size={28} className="mx-auto text-[var(--text-muted)]" aria-hidden="true" />
                <p className="mt-3 mb-0 text-[14px] font-medium text-[var(--text-primary)]">{t('No rules match these filters', 'ไม่มีกฎที่ตรงกับตัวกรอง')}</p>
              </>
            )}
          </div>
        ) : (
          <ul className="m-0 list-none p-0">{pageRules.map(renderRow)}</ul>
        )}

        {totalPages > 1 && (
          <div className="flex items-center justify-between gap-3 border-t border-[var(--bg-border)] px-4 py-3 text-[12.5px] text-[var(--text-muted)]">
            <span>
              {((page - 1) * PAGE_SIZE + 1).toLocaleString()}–{Math.min(page * PAGE_SIZE, visible.length).toLocaleString()} {t('of', 'จาก')} {visible.length.toLocaleString()}
            </span>
            <div className="flex items-center gap-1.5">
              <Button variant="secondary" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)} icon={<ChevronLeft size={14} />}>
                {t('Previous', 'ก่อนหน้า')}
              </Button>
              <span className="px-2 tabular-nums">{page} / {totalPages}</span>
              <Button variant="secondary" size="sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                {t('Next', 'ถัดไป')} <ChevronRight size={14} aria-hidden="true" />
              </Button>
            </div>
          </div>
        )}
      </div>

      <Modal
        open={!!approval}
        onClose={() => !busy && setApproval(null)}
        title={
          approval && approval.ids.length > 1
            ? t(`Approve ${approval.ids.length} rules`, `อนุมัติ ${approval.ids.length} กฎ`)
            : t('Approve this rule', 'อนุมัติกฎนี้')
        }
      >
        <p className="m-0 text-[13.5px] font-medium leading-relaxed text-[var(--text-primary)]">{approval?.scope}</p>
        {approval?.warning && (
          <p className="mt-2 mb-0 text-[13px] leading-relaxed text-amber-700 dark:text-amber-400">{approval.warning}</p>
        )}
        <div className="mt-5 flex justify-end gap-2.5 border-t border-[var(--bg-border-subtle)] pt-4">
          <Button variant="ghost" size="lg" onClick={() => setApproval(null)} disabled={busy}>{t('Cancel', 'ยกเลิก')}</Button>
          <Button variant="brand" size="lg" onClick={() => approval && approveIds(approval.ids)} isLoading={busy} icon={<Check size={14} />}>
            {t('Approve', 'อนุมัติ')}
          </Button>
        </div>
      </Modal>

      <Modal
        open={confirmLegacy}
        onClose={() => !rejectLegacy.isPending && setConfirmLegacy(false)}
        title={t(`Reject ${legacyPending} legacy rules`, `ปฏิเสธกฎแบบเก่า ${legacyPending} กฎ`)}
        description={t(
          'Only pending legacy rules. Rules from Gen 3, CVE and rules already approved are not touched.',
          'เฉพาะกฎแบบเก่าที่ยังรออนุมัติ กฎจาก Gen 3, CVE และกฎที่อนุมัติไปแล้วไม่ถูกแตะ',
        )}
      >
        <p className="m-0 text-[13.5px] leading-relaxed text-[var(--text-primary)]">
          {t(
            'The reason "Legacy rule from RandomForest: the platform now uses Gen 3" is recorded, and they stay visible in the Rejected tab.',
            'ระบบจะบันทึกเหตุผลว่า "กฎแบบเก่าจาก RandomForest: ระบบเปลี่ยนมาใช้ Gen 3 แล้ว" และดูย้อนหลังได้ที่แท็บปฏิเสธแล้ว',
          )}
        </p>
        <div className="mt-5 flex justify-end gap-2.5 border-t border-[var(--bg-border-subtle)] pt-4">
          <Button variant="ghost" size="lg" onClick={() => setConfirmLegacy(false)} disabled={rejectLegacy.isPending}>{t('Cancel', 'ยกเลิก')}</Button>
          <Button variant="danger" size="lg" onClick={() => rejectLegacy.mutate()} isLoading={rejectLegacy.isPending} icon={<X size={14} />}>
            {t('Reject all', 'ปฏิเสธทั้งหมด')}
          </Button>
        </div>
      </Modal>

      <Modal
        open={!!rejecting}
        onClose={() => !busy && setRejecting(null)}
        title={rejecting && rejecting.length > 1 ? t(`Reject ${rejecting.length} rules`, `ปฏิเสธ ${rejecting.length} กฎ`) : t('Reject this rule', 'ปฏิเสธกฎนี้')}
        description={t(
          'A rejected rule is not deployed. If the same kind of request comes in again, it is proposed as a new rule.',
          'กฎที่ปฏิเสธจะไม่ถูกติดตั้ง และถ้า request แบบเดียวกันเข้ามาอีก ระบบจะเสนอเป็นกฎใหม่',
        )}
      >
        <form onSubmit={(e) => { e.preventDefault(); rejectIds() }}>
          <label htmlFor="reject-reason" className="block text-[12.5px] font-medium text-[var(--text-secondary)]">{t('Reason (optional)', 'เหตุผล (ไม่บังคับ)')}</label>
          <input
            id="reject-reason"
            value={rejectReason}
            onChange={(e) => setRejectReason(e.target.value)}
            placeholder={t('e.g. matches normal traffic on /search', 'เช่น ชน traffic ปกติของ /search')}
            className="dash-input mt-1.5 h-10 w-full text-[13.5px]"
            autoFocus
          />
          <div className="mt-5 flex justify-end gap-2.5 border-t border-[var(--bg-border-subtle)] pt-4">
            <Button variant="ghost" size="lg" type="button" onClick={() => setRejecting(null)} disabled={busy}>{t('Cancel', 'ยกเลิก')}</Button>
            <Button variant="danger" size="lg" type="submit" isLoading={busy} icon={<X size={14} />}>{t('Reject', 'ปฏิเสธ')}</Button>
          </div>
        </form>
      </Modal>

      <Modal
        open={!!revoking}
        onClose={() => !busy && setRevoking(null)}
        title={t('Revoke this rule', 'ยกเลิกการใช้งานกฎนี้')}
        description={t(
          'The rule is removed from the WAF and reloaded at once. It stays in the Revoked tab with who revoked it and why. To use it again, propose a new rule.',
          'ระบบจะเอากฎออกจาก WAF แล้ว reload ทันที กฎยังอยู่ในแท็บยกเลิกแล้วพร้อมบันทึกว่าใครยกเลิกและเพราะอะไร ถ้าต้องการใช้อีกต้องเสนอกฎใหม่',
        )}
      >
        <form onSubmit={(e) => { e.preventDefault(); revokeRule() }}>
          {revoking && (
            <p className="m-0 mb-3 text-[13.5px] font-medium leading-relaxed text-[var(--text-primary)]">
              {revokeScope(revoking, lang)}: {revoking.attack_type} (#{revoking.deployed_rule_id})
            </p>
          )}
          <label htmlFor="revoke-reason" className="block text-[12.5px] font-medium text-[var(--text-secondary)]">{t('Reason (optional)', 'เหตุผล (ไม่บังคับ)')}</label>
          <input
            id="revoke-reason"
            value={revokeReason}
            onChange={(e) => setRevokeReason(e.target.value)}
            placeholder={t('e.g. blocks real users on /search', 'เช่น block ผู้ใช้จริงที่หน้า /search')}
            maxLength={500}
            className="dash-input mt-1.5 h-10 w-full text-[13.5px]"
            autoFocus
          />
          <div className="mt-5 flex justify-end gap-2.5 border-t border-[var(--bg-border-subtle)] pt-4">
            <Button variant="ghost" size="lg" type="button" onClick={() => setRevoking(null)} disabled={busy}>{t('Keep it', 'ไม่ยกเลิก')}</Button>
            <Button variant="danger" size="lg" type="submit" isLoading={busy} icon={<Ban size={14} />}>{t('Revoke', 'ยกเลิกการใช้งาน')}</Button>
          </div>
        </form>
      </Modal>

      <Modal
        open={scanOpen}
        onClose={() => !cveScan.isPending && setScanOpen(false)}
        title={t('Scan for CVEs', 'สแกน CVE')}
        description={t(
          "Search NVD for recent CVEs that match the origin's tech stack and propose them as pending rules. No rule takes effect until someone approves it.",
          'ค้นหา CVE ล่าสุดจาก NVD ที่ตรงกับ tech stack ของ origin แล้วเสนอเป็นกฎรออนุมัติ ไม่มีกฎไหนมีผลจนกว่าจะมีคนอนุมัติ',
        )}
      >
        <form onSubmit={(e) => { e.preventDefault(); cveScan.mutate(scanTarget === ALL_ORIGINS ? '' : scanTarget) }}>
          <label htmlFor="scan-origin" className="block text-[12.5px] font-medium text-[var(--text-secondary)]">{t('Scan for', 'สแกนให้')}</label>
          <select
            id="scan-origin"
            value={scanTarget}
            onChange={(e) => setScanTarget(e.target.value)}
            className="dash-input mt-1.5 h-10 w-full text-[13.5px] cursor-pointer"
          >
            {isAdmin && <option value={ALL_ORIGINS}>{t('Every origin with a tech stack', 'ทุก origin ที่มี tech stack')}</option>}
            {scanChoices.map((c) => (
              <option key={c.id} value={c.id}>{c.label}{c.hasTags ? '' : t(' (no tech stack set)', ' (ยังไม่ได้ตั้ง tech stack)')}</option>
            ))}
          </select>
          {scanPick && !scanPick.hasTags ? (
            <p className="mt-2 mb-0 text-[12.5px] leading-relaxed text-amber-700 dark:text-amber-400">
              {t('This origin has no tech stack tags yet. Add them on the', 'origin นี้ยังไม่มี tech stack tag เพิ่มได้ที่')}{' '}
              <Link to={`/origins/${scanPick.id}`} className="font-medium underline">{t('origin page', 'หน้า origin')}</Link>{' '}
              {t('before scanning.', 'ก่อนสแกน')}
            </p>
          ) : (
            <p className="mt-2 mb-0 text-[12px] leading-relaxed text-[var(--text-muted)]">
              {scanTarget === ALL_ORIGINS
                ? t('Scans every origin, up to 5 rules per scan; the rest come in the next scan.', 'สแกนทุก origin ครั้งละไม่เกิน 5 กฎ ที่เหลือจะมาในการสแกนครั้งถัดไป')
                : t(
                    'The rules belong to this origin and, once approved, apply to it only. Each origin can be scanned 3 times per hour.',
                    'กฎที่ได้เป็นของ origin นี้ และถ้าอนุมัติจะมีผลเฉพาะ origin นี้ แต่ละ origin สแกนได้ 3 ครั้งต่อชั่วโมง',
                  )}
            </p>
          )}
          <div className="mt-5 flex justify-end gap-2.5 border-t border-[var(--bg-border-subtle)] pt-4">
            <Button variant="ghost" size="lg" type="button" onClick={() => setScanOpen(false)} disabled={cveScan.isPending}>{t('Cancel', 'ยกเลิก')}</Button>
            <Button
              variant="brand"
              size="lg"
              type="submit"
              isLoading={cveScan.isPending}
              disabled={!scanTarget || (!!scanPick && !scanPick.hasTags)}
              icon={<Bug size={14} />}
            >
              {t('Scan', 'สแกน')}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  )
}

export default MLRules
