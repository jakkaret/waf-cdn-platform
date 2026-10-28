import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { GRANT_HOURS, LEVEL_LABEL, LEVEL_LABEL_TH, SupportTicketDetail, activeGrant, grantSummary } from '../lib/support'
import { timeAgo } from '../lib/mlRules'
import { useT } from '../i18n'

// One support ticket: the conversation, the origin admin's support-access
// controls, and the log of every time support used that access.
const SupportTicket: React.FC = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [reply, setReply] = useState('')
  const [level, setLevel] = useState<'viewer' | 'editor'>('viewer')
  const [hours, setHours] = useState<number>(24)
  const [confirmEdit, setConfirmEdit] = useState(false)
  const { t, lang } = useT()
  const ago = (iso?: string) => timeAgo(iso, Date.now(), lang)

  const key = ['support-ticket', id]
  const { data, isLoading, isError } = useQuery({
    queryKey: key,
    queryFn: async () => (await api.get<SupportTicketDetail>(`/support/tickets/${id}`)).data,
    refetchInterval: 15000,
  })
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: key })
    queryClient.invalidateQueries({ queryKey: ['support-tickets'] })
  }
  const onError = (fallback: string) => (e: any) => toast.error(e.response?.data?.detail || fallback)

  const send = useMutation({
    mutationFn: async () => api.post(`/support/tickets/${id}/messages`, { body: reply }),
    onSuccess: () => {
      setReply('')
      refresh()
    },
    onError: onError(t('Could not send the message', 'ส่งข้อความไม่สำเร็จ')),
  })
  const grant = useMutation({
    mutationFn: async () =>
      api.post(`/support/tickets/${id}/grant`, { level, hours, confirm_edit: level === 'editor' && confirmEdit }),
    onSuccess: () => {
      toast.success(t('Support access granted', 'ให้สิทธิ์ support แล้ว'))
      setConfirmEdit(false)
      refresh()
    },
    onError: onError(t('Could not grant access', 'ให้สิทธิ์ไม่สำเร็จ')),
  })
  const revoke = useMutation({
    mutationFn: async () => api.delete(`/support/tickets/${id}/grant`),
    onSuccess: () => {
      toast.success(t('Support access removed', 'ยกเลิกสิทธิ์ support แล้ว'))
      refresh()
    },
    onError: onError(t('Could not remove access', 'ยกเลิกสิทธิ์ไม่สำเร็จ')),
  })
  const close = useMutation({
    mutationFn: async () => api.post(`/support/tickets/${id}/close`),
    onSuccess: () => {
      toast.success(t('Ticket closed', 'ปิด ticket แล้ว'))
      refresh()
    },
    onError: onError(t('Could not close the ticket', 'ปิด ticket ไม่สำเร็จ')),
  })

  if (isLoading) return <p className="p-5 text-[13px] text-[var(--text-muted)]">{t('Loading ticket...', 'กำลังโหลด ticket...')}</p>
  if (isError || !data) return <p className="p-5 text-[13px] text-[var(--text-muted)]">{t('Ticket not found.', 'ไม่พบ ticket')}</p>

  const { ticket, origin, messages, grants, access_log, can_grant, staff } = data
  const isOpen = ticket.status === 'open'
  const current = activeGrant(grants)
  return (
    <div className="animate-fade-in pb-12">
      <TopBar
        title={ticket.subject}
        subtitle={`${origin.label || origin.id} · ${isOpen ? t('Open', 'เปิดอยู่') : t('Closed', 'ปิดแล้ว')} · ${t('opened', 'เปิดเมื่อ')} ${ago(ticket.created_at)}`}
        action={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => navigate('/support')}>{t('All tickets', 'ticket ทั้งหมด')}</Button>
            {staff && current && (
              <Button variant="outline" onClick={() => navigate(`/origins/${origin.id}`)}>{t('Open origin', 'เปิด origin')}</Button>
            )}
            {isOpen && (
              <Button variant="outline" onClick={() => close.mutate()} isLoading={close.isPending}>{t('Close ticket', 'ปิด ticket')}</Button>
            )}
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <section className="dash-card p-5 grid gap-3 content-start">
          <h3 className="m-0 text-[13px] font-bold">{t('Conversation', 'การสนทนา')}</h3>
          {messages.map((m) => (
            <div
              key={m.message_id}
              className={`rounded-lg border border-[var(--bg-border)] p-3 ${m.is_support ? 'bg-[var(--bg-primary)]' : ''}`}
            >
              <div className="text-[11px] text-[var(--text-muted)] mb-1">
                {m.is_support ? 'Support' : m.author_name || t('Origin admin', 'ผู้ดูแล origin')} · {ago(m.created_at)}
              </div>
              <div className="text-[13px] whitespace-pre-wrap break-words text-[var(--text-primary)]">{m.body}</div>
            </div>
          ))}
          {isOpen ? (
            <form
              className="grid gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                send.mutate()
              }}
            >
              <textarea className="dash-input min-h-[90px]" maxLength={5000} value={reply} onChange={(e) => setReply(e.target.value)} placeholder={t('Write a reply', 'เขียนข้อความตอบกลับ')} />
              <div>
                <Button type="submit" variant="brand" isLoading={send.isPending} disabled={!reply.trim()}>{t('Send', 'ส่ง')}</Button>
              </div>
            </form>
          ) : (
            <p className="text-[12px] text-[var(--text-muted)] m-0">{t('This ticket is closed.', 'ticket นี้ปิดแล้ว')}</p>
          )}
        </section>

        <aside className="grid gap-4 content-start">
          <section className="dash-card p-5 grid gap-3">
            <h3 className="m-0 text-[13px] font-bold">{t('Support access', 'สิทธิ์ของ support')}</h3>
            <p className="m-0 text-[12.5px] text-[var(--text-secondary)]">{grantSummary(grants, new Date(), lang)}</p>
            {!can_grant && isOpen && !staff && (
              <p className="m-0 text-[11.5px] text-[var(--text-muted)]">{t("Only the origin's Owner can grant support access.", 'เฉพาะ Owner ของ origin ที่ให้สิทธิ์ support ได้')}</p>
            )}
            {can_grant && isOpen && (
              <div className="grid gap-2">
                <label className="grid gap-1 text-[12px] text-[var(--text-secondary)]">
                  {t('Level', 'ระดับสิทธิ์')}
                  <select className="dash-input" value={level} onChange={(e) => setLevel(e.target.value as 'viewer' | 'editor')}>
                    <option value="viewer">{t(`${LEVEL_LABEL.viewer} (recommended)`, `${LEVEL_LABEL_TH.viewer} (แนะนำ)`)}</option>
                    <option value="editor">{t(LEVEL_LABEL.editor, LEVEL_LABEL_TH.editor)}</option>
                  </select>
                </label>
                <label className="grid gap-1 text-[12px] text-[var(--text-secondary)]">
                  {t('For', 'เป็นเวลา')}
                  <select className="dash-input" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
                    {GRANT_HOURS.map((h) => (
                      <option key={h} value={h}>{t(`${h} hour${h > 1 ? 's' : ''}`, `${h} ชั่วโมง`)}</option>
                    ))}
                  </select>
                </label>
                {level === 'editor' && (
                  <label className="flex gap-2 items-start text-[12px] text-amber-500">
                    <input type="checkbox" checked={confirmEdit} onChange={(e) => setConfirmEdit(e.target.checked)} />
                    {t("I allow the support team to change this origin's settings, domains and rules.", 'ฉันอนุญาตให้ทีม support แก้การตั้งค่า โดเมน และกฎของ origin นี้')}
                  </label>
                )}
                <Button
                  variant="brand"
                  onClick={() => grant.mutate()}
                  isLoading={grant.isPending}
                  disabled={level === 'editor' && !confirmEdit}
                >
                  {current ? t('Replace access', 'เปลี่ยนสิทธิ์') : t('Grant access', 'ให้สิทธิ์')}
                </Button>
                {current && (
                  <Button variant="danger" onClick={() => revoke.mutate()} isLoading={revoke.isPending}>
                    {t('Remove access now', 'ยกเลิกสิทธิ์ทันที')}
                  </Button>
                )}
                <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
                  {t(
                    'Support can never delete the origin, manage its members or issue tunnel credentials. Access also ends when the ticket is closed.',
                    'support ลบ origin จัดการสมาชิก หรือออก tunnel credential ไม่ได้ และสิทธิ์จะหมดเมื่อปิด ticket',
                  )}
                </p>
              </div>
            )}
          </section>

          <section className="dash-card p-5 grid gap-2">
            <h3 className="m-0 text-[13px] font-bold">{t('Access log', 'ประวัติการเข้าถึง')}</h3>
            {access_log.length === 0 ? (
              <p className="m-0 text-[12px] text-[var(--text-muted)]">{t('Support has not used access on this ticket.', 'support ยังไม่ได้ใช้สิทธิ์ใน ticket นี้')}</p>
            ) : (
              <ul className="m-0 p-0 list-none grid gap-1 text-[12px]">
                {access_log.map((e, i) => (
                  <li key={i} className="text-[var(--text-secondary)]">
                    {e.staff_name || 'support'} · {e.kind === 'edit' ? t('changed something', 'แก้ไขบางอย่าง') : t('viewed', 'เปิดดู')} · {ago(e.at)}
                  </li>
                ))}
              </ul>
            )}
          </section>
        </aside>
      </div>
    </div>
  )
}

export default SupportTicket
