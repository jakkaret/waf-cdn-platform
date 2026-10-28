import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { toast } from 'react-hot-toast'
import { AlertTriangle } from 'lucide-react'
import { getMLVerdict, suggestRuleFromVerdict } from '../../api/mlVerdicts'
import { mlRulesApi } from '../../api/mlRules'
import { MLPendingRule, MLRuleBacktest } from '../../types'
import { InsightRequest, looksLikeServiceTraffic, proposeHint, suggestReasonText } from '../../lib/mlInsights'

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

const STATUS_TEXT: Record<string, string> = { pending: 'Waiting for a decision', approved: 'In use', rejected: 'Not used' }

const ProposedRule: React.FC<{ rule: MLPendingRule }> = ({ rule }) => {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState(rule.status)
  const [confirming, setConfirming] = useState(false)
  const [backtest, setBacktest] = useState<MLRuleBacktest | undefined>(rule.backtest)

  const done = () => queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
  const approve = useMutation({
    mutationFn: () => mlRulesApi.approveRule(rule.rule_id),
    onSuccess: () => { setStatus('approved'); setConfirming(false); done(); toast.success("Rule approved. It now applies to this site's WAF.") },
    onError: (e) => toast.error(errText(e, 'Could not approve the rule. Nothing was changed.')),
  })
  const reject = useMutation({
    mutationFn: () => mlRulesApi.rejectRule(rule.rule_id, 'Not used, from ML insights'),
    onSuccess: () => { setStatus('rejected'); done(); toast.success('Rule rejected') },
    onError: (e) => toast.error(errText(e, 'Could not save. Try again.')),
  })
  const runBacktest = useMutation({
    mutationFn: () => mlRulesApi.backtestRule(rule.rule_id),
    onSuccess: (bt) => setBacktest(bt),
    onError: (e) => toast.error(errText(e, 'The test against past traffic failed. Try again.')),
  })

  return (
    <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <span className="font-medium text-[var(--text-primary)]">{rule.attack_type || 'Proposed rule'}</span>
        <span className="rounded border border-[var(--bg-border)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">{rule.severity}</span>
        <span className={muted}>
          {STATUS_TEXT[status] ?? status}
          {(rule.hit_count ?? 1) > 1 ? `, seen ${rule.hit_count} times` : ''}
        </span>
      </div>
      <pre className="m-0 max-h-32 overflow-auto rounded bg-[var(--bg-primary)] p-2 font-mono text-[11.5px] whitespace-pre-wrap break-all text-[var(--text-primary)]">
        {rule.secrule_template || `${rule.variable} ${rule.pattern}`}
      </pre>
      {backtest && (
        <p className="m-0 text-[12px] text-[var(--text-secondary)]">
          In the last {backtest.window_days} days of traffic through the WAF, {backtest.matched.toLocaleString()} of{' '}
          {backtest.scanned.toLocaleString()} requests match this rule.
          {backtest.matched > 0 ? ' If any of them were normal visitors, this rule would block them too. Check the examples first.' : ''}
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
              {runBacktest.isPending ? 'Testing…' : 'Test against past traffic'}
            </button>
          )}
          {!confirming ? (
            <button type="button" className={`${btn} bg-[var(--accent-fill)] text-white`} onClick={() => setConfirming(true)}>
              Approve rule
            </button>
          ) : (
            <span className="flex flex-wrap items-center gap-2 rounded-md bg-[var(--bg-primary)] px-2 py-1">
              <span className="text-[12px] text-[var(--text-secondary)]">Matching requests will be blocked on this site right away.</span>
              <button type="button" className={`${btn} bg-red-700 text-white`} disabled={approve.isPending} onClick={() => approve.mutate()}>
                {approve.isPending ? 'Approving…' : 'Confirm and block'}
              </button>
              <button type="button" className={`${btn} text-[var(--text-muted)]`} onClick={() => setConfirming(false)}>Cancel</button>
            </span>
          )}
          <button type="button" className={`${btn} text-[var(--text-muted)] hover:text-[var(--text-primary)]`}
            disabled={reject.isPending} onClick={() => reject.mutate()}>
            Reject
          </button>
        </div>
      )}
    </div>
  )
}

export const VerdictActions: React.FC<{ r: InsightRequest }> = ({ r }) => {
  const originId = r.origin_id || ''
  const hint = proposeHint(r)
  const serviceLike = looksLikeServiceTraffic(r.path)
  const { data: detail, isLoading, isError } = useQuery({
    queryKey: ['ml-verdict', originId, r.request_id],
    queryFn: () => getMLVerdict(originId, r.request_id),
    enabled: !!(r.can_edit && originId && r.request_id && r.has_body),
    staleTime: 60_000,
  })
  const suggest = useMutation({
    mutationFn: () => suggestRuleFromVerdict(originId, r.request_id),
    onError: (e) => toast.error(errText(e, 'Could not propose a rule. Try again.')),
  })

  if (!r.can_edit || !originId || !r.request_id) return null
  const result = suggest.data

  return (
    <div className="mt-3 space-y-3 border-t border-[var(--bg-border-subtle)] pt-3">
      {r.has_body && (
        <div>
          <p className="m-0 mb-1 text-[12px] font-medium text-[var(--text-secondary)]">
            Stored body{' '}
            <span className="font-normal text-[var(--text-muted)]">
              (passwords, tokens, emails, phone and card numbers masked; at most 4,096 characters; deleted after 7 days)
            </span>
          </p>
          {isLoading ? (
            <p className={`m-0 ${muted}`}>Loading…</p>
          ) : isError ? (
            <p className={`m-0 ${muted}`}>Could not load the body. Open the row again to retry.</p>
          ) : (
            <pre className="m-0 max-h-48 overflow-auto rounded bg-[var(--bg-surface)] p-2 font-mono text-[11.5px] whitespace-pre-wrap break-all text-[var(--text-primary)]">
              {detail?.body_sample || '(empty)'}
            </pre>
          )}
        </div>
      )}

      {r.can_propose ? (
        <div className="space-y-2">
          {serviceLike && (
            <p className="m-0 flex items-start gap-1.5 rounded-md border border-amber-600/30 bg-amber-500/10 px-2.5 py-2 text-[12px] text-amber-900 dark:text-amber-200">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              This path looks like a health check, monitoring or telemetry call rather than a visitor. A rule built from it can
              block that service. Check who sends it before proposing one.
            </p>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className={`${btn} border border-[var(--accent)] text-[var(--accent)]`}
              disabled={suggest.isPending} onClick={() => suggest.mutate()}>
              {suggest.isPending ? 'Asking the model…' : serviceLike ? 'Propose a rule anyway' : 'Propose a rule from this request'}
            </button>
            <span className={muted}>A proposed rule does nothing until someone approves it.</span>
          </div>
          {result && result.suggested_rules.length === 0 && (
            <p className={`m-0 ${muted}`}>{suggestReasonText(result.suggestion.reason) || 'No rule could be proposed.'}</p>
          )}
          {result && result.suggested_rules.map((rule) => <ProposedRule key={rule.rule_id} rule={rule} />)}
          {result && result.suggested_rules.length > 0 && (
            <p className={`m-0 ${muted}`}>
              All of this site's proposals are in{' '}
              <Link to="/rule-proposals?type=ml" className="text-[var(--accent)] hover:underline">Rule proposals</Link>.
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
