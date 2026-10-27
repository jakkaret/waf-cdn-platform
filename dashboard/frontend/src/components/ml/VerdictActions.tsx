import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { toast } from 'react-hot-toast'
import { getMLVerdict, suggestRuleFromVerdict } from '../../api/mlVerdicts'
import { mlRulesApi } from '../../api/mlRules'
import { MLPendingRule, MLRuleBacktest } from '../../types'
import { InsightRequest, proposeHint, suggestReasonText } from '../../lib/mlInsights'

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

const ProposedRule: React.FC<{ rule: MLPendingRule }> = ({ rule }) => {
  const queryClient = useQueryClient()
  const [status, setStatus] = useState(rule.status)
  const [confirming, setConfirming] = useState(false)
  const [backtest, setBacktest] = useState<MLRuleBacktest | undefined>(rule.backtest)

  const done = () => queryClient.invalidateQueries({ queryKey: ['ml-rules'] })
  const approve = useMutation({
    mutationFn: () => mlRulesApi.approveRule(rule.rule_id),
    onSuccess: () => { setStatus('approved'); setConfirming(false); done(); toast.success('ใช้กฎแล้ว กฎมีผลกับ WAF ของเว็บนี้') },
    onError: (e) => toast.error(errText(e, 'ใช้กฎไม่สำเร็จ')),
  })
  const reject = useMutation({
    mutationFn: () => mlRulesApi.rejectRule(rule.rule_id, 'ไม่ใช้จากหน้า ML Insights'),
    onSuccess: () => { setStatus('rejected'); done(); toast.success('ไม่ใช้กฎนี้แล้ว') },
    onError: (e) => toast.error(errText(e, 'บันทึกไม่สำเร็จ')),
  })
  const runBacktest = useMutation({
    mutationFn: () => mlRulesApi.backtestRule(rule.rule_id),
    onSuccess: (bt) => setBacktest(bt),
    onError: (e) => toast.error(errText(e, 'ทดสอบไม่สำเร็จ')),
  })

  return (
    <div className="rounded-lg border border-[var(--bg-border)] bg-[var(--bg-surface)] p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <span className="font-medium text-[var(--text-primary)]">{rule.attack_type || 'กฎที่เสนอ'}</span>
        <span className="rounded border border-[var(--bg-border)] px-1.5 py-0.5 text-[11px] text-[var(--text-secondary)]">{rule.severity}</span>
        <span className={muted}>
          {status === 'pending' ? 'รอตัดสินใจ' : status === 'approved' ? 'ใช้แล้ว' : status === 'rejected' ? 'ไม่ใช้' : status}
          {(rule.hit_count ?? 1) > 1 ? ` · เจอแบบนี้แล้ว ${rule.hit_count} ครั้ง` : ''}
        </span>
      </div>
      <pre className="m-0 max-h-32 overflow-auto rounded bg-[var(--bg-primary)] p-2 font-mono text-[11.5px] whitespace-pre-wrap break-all text-[var(--text-primary)]">
        {rule.secrule_template || `${rule.variable} ${rule.pattern}`}
      </pre>
      {backtest && (
        <p className="m-0 text-[12px] text-[var(--text-secondary)]">
          traffic ที่ผ่าน WAF ย้อนหลัง {backtest.window_days} วัน: ตรงกฎนี้ {backtest.matched.toLocaleString()} จาก{' '}
          {backtest.scanned.toLocaleString()} request
          {backtest.matched > 0 ? ' ถ้าเป็นผู้ใช้ปกติ กฎนี้จะบล็อกเขาด้วย ดูตัวอย่างก่อนใช้' : ''}
          {backtest.example_paths.length > 0 && (
            <span className="block font-mono text-[11.5px] text-[var(--text-muted)] break-all">{backtest.example_paths.slice(0, 3).join(' · ')}</span>
          )}
        </p>
      )}
      {status === 'pending' && rule.can_review && (
        <div className="flex flex-wrap items-center gap-2">
          {rule.can_backtest && (
            <button type="button" className={`${btn} border border-[var(--bg-border)] text-[var(--text-primary)]`}
              disabled={runBacktest.isPending} onClick={() => runBacktest.mutate()}>
              {runBacktest.isPending ? 'กำลังทดสอบ…' : 'ทดสอบกับ traffic ย้อนหลัง'}
            </button>
          )}
          {!confirming ? (
            <button type="button" className={`${btn} bg-[var(--accent)] text-white`} onClick={() => setConfirming(true)}>
              ใช้กฎนี้
            </button>
          ) : (
            <span className="flex flex-wrap items-center gap-2 rounded-md bg-[var(--bg-primary)] px-2 py-1">
              <span className="text-[12px] text-[var(--text-secondary)]">request ที่ตรงกฎจะถูกบล็อกทันทีบนเว็บนี้</span>
              <button type="button" className={`${btn} bg-[var(--danger)] text-white`} disabled={approve.isPending} onClick={() => approve.mutate()}>
                {approve.isPending ? 'กำลังใช้…' : 'ยืนยันใช้กฎ'}
              </button>
              <button type="button" className={`${btn} text-[var(--text-muted)]`} onClick={() => setConfirming(false)}>ยกเลิก</button>
            </span>
          )}
          <button type="button" className={`${btn} text-[var(--text-muted)] hover:text-[var(--text-primary)]`}
            disabled={reject.isPending} onClick={() => reject.mutate()}>
            ไม่ใช้
          </button>
        </div>
      )}
    </div>
  )
}

export const VerdictActions: React.FC<{ r: InsightRequest }> = ({ r }) => {
  const originId = r.origin_id || ''
  const hint = proposeHint(r)
  const { data: detail, isLoading, isError } = useQuery({
    queryKey: ['ml-verdict', originId, r.request_id],
    queryFn: () => getMLVerdict(originId, r.request_id),
    enabled: !!(r.can_edit && originId && r.request_id && r.has_body),
    staleTime: 60_000,
  })
  const suggest = useMutation({
    mutationFn: () => suggestRuleFromVerdict(originId, r.request_id),
    onError: (e) => toast.error(errText(e, 'เสนอกฎไม่สำเร็จ')),
  })

  if (!r.can_edit || !originId || !r.request_id) return null
  const result = suggest.data

  return (
    <div className="mt-3 space-y-3 border-t border-[var(--bg-border-subtle)] pt-3">
      {r.has_body && (
        <div>
          <p className="m-0 mb-1 text-[12px] font-medium text-[var(--text-secondary)]">
            Body ที่เก็บไว้ <span className="font-normal text-[var(--text-muted)]">(ซ่อนรหัสผ่าน token อีเมล เบอร์โทร และเลขบัตรแล้ว ไม่เกิน 4,096 ตัวอักษร ลบเองใน 7 วัน)</span>
          </p>
          {isLoading ? (
            <p className={`m-0 ${muted}`}>กำลังโหลด…</p>
          ) : isError ? (
            <p className={`m-0 ${muted}`}>โหลด body ไม่สำเร็จ ลองเปิดใหม่อีกครั้ง</p>
          ) : (
            <pre className="m-0 max-h-48 overflow-auto rounded bg-[var(--bg-surface)] p-2 font-mono text-[11.5px] whitespace-pre-wrap break-all text-[var(--text-primary)]">
              {detail?.body_sample || '(ว่าง)'}
            </pre>
          )}
        </div>
      )}

      {r.can_propose ? (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className={`${btn} border border-[var(--accent)] text-[var(--accent)]`}
              disabled={suggest.isPending} onClick={() => suggest.mutate()}>
              {suggest.isPending ? 'กำลังให้ ML เสนอกฎ…' : 'เสนอกฎจาก request นี้'}
            </button>
            <span className={muted}>กฎที่เสนอยังไม่มีผลจนกว่าคุณจะกด "ใช้กฎนี้"</span>
          </div>
          {result && result.suggested_rules.length === 0 && (
            <p className={`m-0 ${muted}`}>{suggestReasonText(result.suggestion.reason) || 'ไม่มีกฎที่เสนอได้'}</p>
          )}
          {result && result.suggested_rules.map((rule) => <ProposedRule key={rule.rule_id} rule={rule} />)}
          {result && result.suggested_rules.length > 0 && (
            <p className={`m-0 ${muted}`}>
              กฎทั้งหมดของเว็บนี้ดูได้ที่ <Link to="/ml-rules" className="text-[var(--accent)] hover:underline">ML anomaly rules</Link>
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
