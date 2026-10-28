import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { thresholdProposalsApi, ThresholdProposal } from '../api/thresholdProposals'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import toast from 'react-hot-toast'
import { RefreshCw, Check, X, Sparkles, RotateCcw } from 'lucide-react'
import { useT } from '../i18n'

// Each proposal tunes the inbound anomaly threshold of one origin, from that
// origin's own block rate, and only its Owner can generate, approve, reject
// or roll back (api/threshold_proposals.py). Editors and Viewers read only.
// `embedded`: rendered inside Rule proposals, which owns the page header.
export const ThresholdProposals: React.FC<{ embedded?: boolean }> = ({ embedded = false }) => {
  const queryClient = useQueryClient()
  const [picked, setPicked] = useState('')
  const { t } = useT()
  const statusText = (s: ThresholdProposal['status']) =>
    s === 'pending'
      ? t('pending', 'รอตรวจ')
      : s === 'approved'
        ? t('approved', 'อนุมัติแล้ว')
        : s === 'rolled_back'
          ? t('rolled back', 'ย้อนกลับแล้ว')
          : s === 'rejected'
            ? t('rejected', 'ปฏิเสธแล้ว')
            : s

  const { data: originsRes, isLoading: originsLoading } = useQuery({
    queryKey: ['threshold-origins'],
    queryFn: () => thresholdProposalsApi.getOrigins(),
  })
  const origins = originsRes?.origins ?? []
  const origin = origins.find((o) => o.origin_id === picked) ?? origins[0]
  const originId = origin?.origin_id ?? ''
  const isOwner = origin?.role === 'owner'

  const { data: proposals = [], isLoading } = useQuery({
    queryKey: ['threshold-proposals', originId],
    queryFn: () => thresholdProposalsApi.getProposals(originId),
    enabled: !!originId,
  })

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['threshold-proposals', originId] })
    queryClient.invalidateQueries({ queryKey: ['threshold-origins'] })
  }
  const onError = (fallback: string) => (err: any) => toast.error(err?.response?.data?.detail || fallback)

  const generateMutation = useMutation({
    mutationFn: () => thresholdProposalsApi.generateProposal(originId),
    onSuccess: (data) => {
      refresh()
      if (!data.proposal) toast(data.message || t('No change to propose right now', 'ตอนนี้ยังไม่มีอะไรให้เสนอปรับ'), { icon: 'ℹ️' })
      else toast.success(t('Generated a tuning proposal for this origin', 'สร้างข้อเสนอปรับค่าสำหรับ origin นี้แล้ว'))
    },
    onError: onError(t('Generation failed', 'สร้างข้อเสนอไม่สำเร็จ')),
  })
  const approveMutation = useMutation({
    mutationFn: (id: string) => thresholdProposalsApi.approveProposal(id),
    onSuccess: () => { refresh(); toast.success(t("Approved. This origin's threshold is updated.", 'อนุมัติแล้ว อัปเดต threshold ของ origin นี้แล้ว')) },
    onError: onError(t('Approval failed', 'อนุมัติไม่สำเร็จ')),
  })
  const rejectMutation = useMutation({
    mutationFn: (id: string) => thresholdProposalsApi.rejectProposal(id),
    onSuccess: () => { refresh(); toast.success(t('Proposal rejected', 'ปฏิเสธข้อเสนอแล้ว')) },
    onError: onError(t('Rejection failed', 'ปฏิเสธไม่สำเร็จ')),
  })
  const rollbackMutation = useMutation({
    mutationFn: (id: string) => thresholdProposalsApi.rollbackProposal(id),
    onSuccess: () => { refresh(); toast.success(t('Rolled back to the previous threshold', 'ย้อนกลับไปใช้ threshold เดิมแล้ว')) },
    onError: onError(t('Rollback failed', 'ย้อนกลับไม่สำเร็จ')),
  })

  const statusColor = (s: ThresholdProposal['status']) =>
    s === 'pending' ? 'warning' : s === 'approved' ? 'success' : s === 'rolled_back' ? 'gray' : 'danger'

  return (
    <div className="space-y-5">
      {!embedded && <TopBar title={t('Tuning proposals', 'ข้อเสนอปรับค่า')} />}

      <div className="dash-card">
        <div className="dash-card-header flex justify-between items-center bg-[var(--bg-surface-elevated)]">
          <div className="flex items-center gap-2">
            <Sparkles size={16} className="text-orange-500" />
            <h3 className="font-mono">{t('Tuning proposals', 'ข้อเสนอปรับค่า')}</h3>
          </div>
          {isOwner && (
            <Button onClick={() => generateMutation.mutate()} disabled={generateMutation.isPending} isLoading={generateMutation.isPending}>
              <RefreshCw size={14} className={generateMutation.isPending ? 'animate-spin' : ''} />
              {t('Generate proposal', 'สร้างข้อเสนอ')}
            </Button>
          )}
        </div>

        <div className="p-4 space-y-4">
          {originsLoading ? (
            <div className="p-6 text-center text-[var(--text-muted)]">{t('Loading origins...', 'กำลังโหลด origin...')}</div>
          ) : origins.length === 0 ? (
            <div className="p-6 text-center border border-dashed border-[var(--bg-border)] rounded-xl text-[var(--text-muted)]">
              {t(
                "You are not a member of any origin yet. Each tuning proposal belongs to one origin, and that origin's Owner decides it.",
                'คุณยังไม่ได้เป็นสมาชิกของ origin ใด ข้อเสนอปรับค่าแต่ละรายการเป็นของ origin หนึ่ง และ Owner ของ origin นั้นเป็นผู้ตัดสิน',
              )}
            </div>
          ) : (
            <>
              <div className="grid gap-3 sm:grid-cols-[minmax(0,320px)_1fr] items-start">
                <div>
                  <label htmlFor="tuning-origin" className="block text-[12px] text-[var(--text-muted)] mb-1">Origin</label>
                  <select
                    id="tuning-origin"
                    value={originId}
                    onChange={(e) => setPicked(e.target.value)}
                    className="w-full dash-input h-9 text-[13px] cursor-pointer"
                  >
                    {origins.map((o) => <option key={o.origin_id} value={o.origin_id}>{o.label} ({o.role})</option>)}
                  </select>
                </div>
                {origin && (
                  <div className="text-[12.5px] leading-relaxed text-[var(--text-muted)]">
                    <p className="m-0">
                      {t('Inbound anomaly threshold in use for this origin:', 'threshold คะแนน anomaly ขาเข้าที่ origin นี้ใช้อยู่:')}{' '}
                      <strong className="text-[var(--text-primary)]">{origin.effective_threshold}</strong>
                      {origin.anomaly_threshold == null
                        ? t(
                            ` (the platform value, currently ${originsRes?.platform_threshold})`,
                            ` (ค่าของแพลตฟอร์ม ตอนนี้คือ ${originsRes?.platform_threshold})`,
                          )
                        : t(
                            ` (this origin's own value; the platform value is currently ${originsRes?.platform_threshold})`,
                            ` (ค่าของ origin นี้เอง ส่วนค่าของแพลตฟอร์มตอนนี้คือ ${originsRes?.platform_threshold})`,
                          )}
                    </p>
                    <p className="m-0">
                      {t(
                        `Proposals are based on the block rate of ${origin.hosts.length ? origin.hosts.join(', ') : "this origin's domains"} only, and an approved value applies to this origin only.`,
                        `ข้อเสนออิงจากอัตราการบล็อกของ ${origin.hosts.length ? origin.hosts.join(', ') : 'โดเมนของ origin นี้'} เท่านั้น และค่าที่อนุมัติแล้วมีผลกับ origin นี้เท่านั้น`,
                      )}
                      {isOwner ? '' : t(' You can view proposals; only the Owner can generate and decide them.', ' คุณดูข้อเสนอได้ แต่มีเพียง Owner ที่สร้างและตัดสินได้')}
                    </p>
                  </div>
                )}
              </div>

              <div className="space-y-3">
                {isLoading ? (
                  <div className="p-6 text-center text-[var(--text-muted)]">{t('Loading proposals...', 'กำลังโหลดข้อเสนอ...')}</div>
                ) : proposals.length === 0 ? (
                  <div className="p-6 text-center border border-dashed border-[var(--bg-border)] rounded-xl text-[var(--text-muted)]">
                    {t('No proposals for this origin yet.', 'origin นี้ยังไม่มีข้อเสนอ')}
                    {isOwner ? t(' Select Generate proposal to analyse its recent traffic.', ' กดสร้างข้อเสนอเพื่อวิเคราะห์ทราฟฟิกล่าสุด') : ''}
                  </div>
                ) : (
                  proposals.map((p) => (
                    <div key={p.proposal_id} className="p-4 rounded-xl border border-[var(--bg-border)] bg-[var(--bg-surface)] flex flex-wrap gap-3 justify-between items-center">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-mono text-[11px] text-orange-500 truncate">{p.proposal_id}</span>
                          <Badge color={statusColor(p.status)}>{statusText(p.status)}</Badge>
                        </div>
                        <p className="text-[13px] font-bold m-0">Threshold: {p.current_threshold} &rarr; <span className="text-emerald-500">{p.proposed_threshold}</span></p>
                        <p className="text-[12px] text-[var(--text-muted)] mt-1 mb-0">{p.reason}</p>
                      </div>
                      {p.status === 'pending' && p.can_review && (
                        <div className="flex gap-2">
                          <Button color="ghost" onClick={() => rejectMutation.mutate(p.proposal_id)} isLoading={rejectMutation.isPending}>
                            <X size={14} /> {t('Reject', 'ปฏิเสธ')}
                          </Button>
                          <Button color="brand" onClick={() => approveMutation.mutate(p.proposal_id)} isLoading={approveMutation.isPending}>
                            <Check size={14} /> {t('Approve', 'อนุมัติ')}
                          </Button>
                        </div>
                      )}
                      {p.status === 'approved' && p.can_review && (
                        <Button color="ghost" onClick={() => rollbackMutation.mutate(p.proposal_id)} isLoading={rollbackMutation.isPending}>
                          <RotateCcw size={14} /> {t('Roll back', 'ย้อนกลับ')}
                        </Button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default ThresholdProposals
