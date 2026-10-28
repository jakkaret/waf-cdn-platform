import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { toast } from 'react-hot-toast'
import { AlertTriangle } from 'lucide-react'
import { getMLVerdict, suggestRuleFromVerdict } from '../../api/mlVerdicts'
import { mlRulesApi } from '../../api/mlRules'
import { MLPendingRule, MLRuleBacktest } from '../../types'
import { InsightRequest, looksLikeServiceTraffic, proposeHint, suggestReasonText } from '../../lib/mlInsights'
import { useT } from '../../i18n'

// The Owner/Editor part of an expanded ML Insights row (2026-10-27): the
// request's masked body, and a rule proposal from it. A proposal joins the
// origin's pending queue (ML anomaly rules); using it here goes through the
// same approve endpoint, so nothing reaches the WAF without a click.

const errText = (e: any, fallback: string) => {
  const detail = e?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

const muted = 'text-[12px] text-[var(--text-muted)]'
const btn =
  'h-8 px-3 rounded-md text-[12.5px] font-medium cursor-pointer disabled:opacity-50 disabled:cursor-default focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]'

const STATUS_TEXT: Record<string, { en: string; th: string }> = {
  pending: { en: 'Waiting for a decision', th: 'รอการตัดสินใจ' },
  approved: { en: 'In use', th: 'ใช้งานอยู่' },
  rejected: { en: 'Not used', th: 'ไม่ใช้' },
}

const ProposedRule: React.FC<{ rule: MLPendingRule }> = ({ rule }) => {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState(rule.status)
  const [confirming, setConfirming] = useState(false)
  const [backtest, setBacktest] = useState<MLRuleBacktest | undefined>(rule.backtest)
  const { t, lang } = useT()

  const done = () => queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
  const approve = useMutation({
    mutationFn: () => mlRulesApi.approveRule(rule.rule_id),
    onSuccess: () => { setStatus('approved'); setConfirming(false); done(); toast.success(t("Rule approved. It now applies to this site's WAF.", 'อนุมัติกฎแล้ว กฎมีผลกับ WAF ของเว็บนี้แล้ว')) },
    onError: (e) => toast.error(errText(e, t('Could not approve the rule. Nothing was changed.', 'อนุมัติกฎไม่สำเร็จ ยังไม่มีอะไรเปลี่ยน'))),
  })
  const reject = useMutation({
    mutationFn: () => mlRulesApi.rejectRule(rule.rule_id, 'Not used, from ML insights'),
    onSuccess: () => { setStatus('rejected'); done(); toast.success(t('Rule rejected', 'ปฏิเสธกฎแล้ว')) },
    onError: (e) => toast.error(errText(e, t('Could not save. Try again.', 'บันทึกไม่สำเร็จ ลองใหม่อีกครั้ง'))),
  })
  const runBacktest = useMutation({
    mutationFn: () => mlRulesApi.backtestRule(rule.rule_id),
    onSuccess: (bt) => setBacktest(bt),
    onError: (e) => toast.error(errText(e, t('The test against past traffic failed. Try again.', 'ทดสอบกับทราฟฟิกย้อนหลังไม่สำเร็จ ลองใหม่อีกครั้ง'))),
  })

  return (
    <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <span className="font-medium text-[var(--text-primary)]">{rule.attack_type || t('Proposed rule', 'กฎที่เสนอ')}</span>
        <span className="rounded border border-[var(--bg-border)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">{rule.severity}</span>
        <span className={muted}>
          {STATUS_TEXT[status]?.[lang] ?? status}
          {(rule.hit_count ?? 1) > 1 ? t(`, seen ${rule.hit_count} times`, `, พบ ${rule.hit_count} ครั้ง`) : ''}
        </span>
      </div>
      <pre className="m-0 max-h-32 overflow-auto rounded bg-[var(--bg-primary)] p-2 font-mono text-[11.5px] whitespace-pre-wrap break-all text-[var(--text-primary)]">
        {rule.secrule_template || `${rule.variable} ${rule.pattern}`}
      </pre>
      {backtest && (
        <p className="m-0 text-[12px] text-[var(--text-secondary)]">
          {t(
            `In the last ${backtest.window_days} days of traffic through the WAF, ${backtest.matched.toLocaleString()} of ${backtest.scanned.toLocaleString()} requests match this rule.`,
            `ในทราฟฟิกที่ผ่าน WAF ช่วง ${backtest.window_days} วันล่าสุด มี ${backtest.matched.toLocaleString()} จาก ${backtest.scanned.toLocaleString()} request ที่ตรงกับกฎนี้`,
          )}
          {backtest.matched > 0
            ? t(
                ' If any of them were normal visitors, this rule would block them too. Check the examples first.',
                ' ถ้ามีผู้เข้าชมปกติอยู่ในนั้น กฎนี้จะบล็อกพวกเขาด้วย ตรวจตัวอย่างก่อน',
              )
            : ''}
          {backtest.example_paths.length > 0 && (
            <span className="block font-mono text-[11.5px] text-[var(--text-muted)] break-all">{backtest.example_paths.slice(0, 3).join('  ')}</span>
          )}
        </p>
      )}
      {status === 'pending' && rule.can_review && (
        <div className="flex flex-wrap items-center gap-2">
          {rule.can_backtest && (
            <button type="button" className={`${btn} border border-[var(--bg-border)] text-[var(--text-primary)]`}
              disabled={runBacktest.isPending} onClick={() => runBacktest.mutate()}>
              {runBacktest.isPending ? t('Testing…', 'กำลังทดสอบ…') : t('Test against past traffic', 'ทดสอบกับทราฟฟิกย้อนหลัง')}
            </button>
          )}
          {!confirming ? (
            <button type="button" className={`${btn} bg-[var(--accent-fill)] text-white`} onClick={() => setConfirming(true)}>
              {t('Approve rule', 'อนุมัติกฎ')}
            </button>
          ) : (
            <span className="flex flex-wrap items-center gap-2 rounded-md bg-[var(--bg-primary)] px-2 py-1">
              <span className="text-[12px] text-[var(--text-secondary)]">{t('Matching requests will be blocked on this site right away.', 'request ที่ตรงกันจะถูกบล็อกบนเว็บนี้ทันที')}</span>
              <button type="button" className={`${btn} bg-red-700 text-white`} disabled={approve.isPending} onClick={() => approve.mutate()}>
                {approve.isPending ? t('Approving…', 'กำลังอนุมัติ…') : t('Confirm and block', 'ยืนยันและบล็อก')}
              </button>
              <button type="button" className={`${btn} text-[var(--text-muted)]`} onClick={() => setConfirming(false)}>{t('Cancel', 'ยกเลิก')}</button>
            </span>
          )}
          <button type="button" className={`${btn} text-[var(--text-muted)] hover:text-[var(--text-primary)]`}
            disabled={reject.isPending} onClick={() => reject.mutate()}>
            {t('Reject', 'ปฏิเสธ')}
          </button>
        </div>
      )}
    </div>
  )
}

export const VerdictActions: React.FC<{ r: InsightRequest }> = ({ r }) => {
  const originId = r.origin_id || ''
  const { t, lang } = useT()
  const hint = proposeHint(r, lang)
  const serviceLike = looksLikeServiceTraffic(r.path)
  const { data: detail, isLoading, isError } = useQuery({
    queryKey: ['ml-verdict', originId, r.request_id],
    queryFn: () => getMLVerdict(originId, r.request_id),
    enabled: !!(r.can_edit && originId && r.request_id && r.has_body),
    staleTime: 60_000,
  })
  const suggest = useMutation({
    mutationFn: () => suggestRuleFromVerdict(originId, r.request_id),
    onError: (e) => toast.error(errText(e, t('Could not propose a rule. Try again.', 'เสนอกฎไม่สำเร็จ ลองใหม่อีกครั้ง'))),
  })

  if (!r.can_edit || !originId || !r.request_id) return null
  const result = suggest.data

  return (
    <div className="mt-3 space-y-3 border-t border-[var(--bg-border-subtle)] pt-3">
      {r.has_body && (
        <div>
          <p className="m-0 mb-1 text-[12px] font-medium text-[var(--text-secondary)]">
            {t('Stored body', 'body ที่เก็บไว้')}{' '}
            <span className="font-normal text-[var(--text-muted)]">
              {t(
                '(passwords, tokens, emails, phone and card numbers masked; at most 4,096 characters; deleted after 7 days)',
                '(ปิดบังรหัสผ่าน token อีเมล เบอร์โทร และเลขบัตร ยาวไม่เกิน 4,096 ตัวอักษร ลบทิ้งหลัง 7 วัน)',
              )}
            </span>
          </p>
          {isLoading ? (
            <p className={`m-0 ${muted}`}>{t('Loading…', 'กำลังโหลด…')}</p>
          ) : isError ? (
            <p className={`m-0 ${muted}`}>{t('Could not load the body. Open the row again to retry.', 'โหลด body ไม่สำเร็จ เปิดแถวนี้อีกครั้งเพื่อลองใหม่')}</p>
          ) : (
            <pre className="m-0 max-h-48 overflow-auto rounded bg-[var(--bg-surface)] p-2 font-mono text-[11.5px] whitespace-pre-wrap break-all text-[var(--text-primary)]">
              {detail?.body_sample || t('(empty)', '(ว่าง)')}
            </pre>
          )}
        </div>
      )}

      {r.can_propose ? (
        <div className="space-y-2">
          {serviceLike && (
            <p className="m-0 flex items-start gap-1.5 rounded-md border border-amber-600/30 bg-amber-500/10 px-2.5 py-2 text-[12px] text-amber-900 dark:text-amber-200">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              {t(
                'This path looks like a health check, monitoring or telemetry call rather than a visitor. A rule built from it can block that service. Check who sends it before proposing one.',
                'path นี้ดูเหมือน health check, ระบบ monitoring หรือ telemetry มากกว่าผู้เข้าชม กฎที่สร้างจากมันอาจบล็อกบริการนั้น ตรวจว่าใครส่งมาก่อนเสนอกฎ',
              )}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className={`${btn} border border-[var(--accent)] text-[var(--accent)]`}
              disabled={suggest.isPending} onClick={() => suggest.mutate()}>
              {suggest.isPending
                ? t('Asking the model…', 'กำลังถามโมเดล…')
                : serviceLike
                  ? t('Propose a rule anyway', 'เสนอกฎต่อไป')
                  : t('Propose a rule from this request', 'เสนอกฎจาก request นี้')}
            </button>
            <span className={muted}>{t('A proposed rule does nothing until someone approves it.', 'กฎที่เสนอจะยังไม่มีผลจนกว่าจะมีคนอนุมัติ')}</span>
          </div>
          {result && result.suggested_rules.length === 0 && (
            <p className={`m-0 ${muted}`}>{suggestReasonText(result.suggestion.reason, lang) || t('No rule could be proposed.', 'เสนอกฎไม่ได้')}</p>
          )}
          {result && result.suggested_rules.map((rule) => <ProposedRule key={rule.rule_id} rule={rule} />)}
          {result && result.suggested_rules.length > 0 && (
            <p className={`m-0 ${muted}`}>
              {t("All of this site's proposals are in", 'ข้อเสนอทั้งหมดของเว็บนี้อยู่ที่')}{' '}
              <Link to="/rule-proposals?type=ml" className="text-[var(--accent)] hover:underline">{t('Rule proposals', 'กฎที่รอตรวจ')}</Link>.
            </p>
          )}
        </div>
      ) : (
        hint && <p className={`m-0 ${muted}`}>{hint}</p>
      )}
    </div>
  )
}

export default VerdictActions
