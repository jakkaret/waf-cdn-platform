import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { SupportTicket } from '../lib/support'
import { timeAgo } from '../lib/mlRules'
import { useT } from '../i18n'

// Support tickets (docs/tickets/support-access.md). An origin admin opens a
// ticket for one origin; platform support staff see every ticket here.
const Support: React.FC = () => {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [originId, setOriginId] = useState('')
  const [subject, setSubject] = useState('')
  const [message, setMessage] = useState('')
  const { t, lang } = useT()

  const tickets = useQuery({
    queryKey: ['support-tickets'],
    queryFn: async () => (await api.get<{ tickets: SupportTicket[]; staff: boolean }>('/support/tickets')).data,
    refetchInterval: 30000,
  })
  const origins = useQuery({
    queryKey: ['support-origins'],
    queryFn: async () => (await api.get<{ origins: { id: string; label?: string }[] }>('/support/origins')).data.origins,
  })

  const open = useMutation({
    mutationFn: async () =>
      (await api.post<SupportTicket>('/support/tickets', { origin_id: originId, subject, message })).data,
    onSuccess: (created) => {
      toast.success(t('Ticket opened', 'เปิด ticket แล้ว'))
      queryClient.invalidateQueries({ queryKey: ['support-tickets'] })
      navigate(`/support/${created.ticket_id}`)
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Could not open the ticket', 'เปิด ticket ไม่สำเร็จ')),
  })

  const list = tickets.data?.tickets || []
  const myOrigins = origins.data || []
  const staff = tickets.data?.staff
  return (
    <div className="animate-fade-in pb-12">
      <TopBar
        title={t('Support', 'ขอความช่วยเหลือ')}
        subtitle={
          staff
            ? t(
                'All tickets. You can open an origin only while its admin has granted support access on the ticket.',
                'ticket ทั้งหมด คุณเปิด origin ได้เฉพาะช่วงที่ผู้ดูแลของ origin ให้สิทธิ์ support ใน ticket นั้น',
              )
            : t(
                'Ask the support team for help with one of your origins. You decide if and how long they may access it.',
                'ขอความช่วยเหลือจากทีม support สำหรับ origin ของคุณ คุณเป็นผู้ตัดสินว่าจะให้เข้าถึงหรือไม่และนานเท่าไร',
              )
        }
        action={
          // The header button only opens the form; Cancel lives in the form
          // next to Open ticket (it used to turn into an orange "Cancel" here).
          myOrigins.length > 0 && !showForm ? (
            <Button variant="brand" onClick={() => setShowForm(true)}>
              {t('Open a ticket', 'เปิด ticket')}
            </Button>
          ) : undefined
        }
      />

      {showForm && (
        <form
          className="dash-card p-5 mb-4 grid gap-3 max-w-2xl"
          onSubmit={(e) => {
            e.preventDefault()
            open.mutate()
          }}
        >
          <label className="grid gap-1 text-[12px] text-[var(--text-secondary)]">
            Origin
            <select className="dash-input" value={originId} onChange={(e) => setOriginId(e.target.value)} required>
              <option value="">{t('Choose an origin you manage', 'เลือก origin ที่คุณดูแล')}</option>
              {myOrigins.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label || o.id}
                </option>
              ))}
            </select>
          </label>
          <label className="grid gap-1 text-[12px] text-[var(--text-secondary)]">
            {t('Subject', 'หัวข้อ')}
            <input className="dash-input" maxLength={200} value={subject} onChange={(e) => setSubject(e.target.value)} required />
          </label>
          <label className="grid gap-1 text-[12px] text-[var(--text-secondary)]">
            {t('What is wrong?', 'เกิดปัญหาอะไร?')}
            <textarea className="dash-input min-h-[120px]" maxLength={5000} value={message} onChange={(e) => setMessage(e.target.value)} required />
          </label>
          <p className="text-[12px] text-[var(--text-muted)] m-0">
            {t('Opening a ticket does not give the support team access. You can grant access from the ticket page.', 'การเปิด ticket ไม่ได้ให้สิทธิ์ทีม support คุณให้สิทธิ์ได้จากหน้า ticket')}
          </p>
          <div className="flex gap-2">
            <Button type="submit" variant="brand" isLoading={open.isPending} disabled={!originId || !subject.trim() || !message.trim()}>
              {t('Open ticket', 'เปิด ticket')}
            </Button>
            <Button type="button" variant="ghost" onClick={() => setShowForm(false)} disabled={open.isPending}>
              {t('Cancel', 'ยกเลิก')}
            </Button>
          </div>
        </form>
      )}

      <div className="dash-card p-0 overflow-x-auto">
        {tickets.isLoading && <p className="p-5 text-[13px] text-[var(--text-muted)]">{t('Loading tickets...', 'กำลังโหลด ticket...')}</p>}
        {tickets.isError && <p className="p-5 text-[13px] text-[var(--text-muted)]">{t('Could not load tickets.', 'โหลด ticket ไม่สำเร็จ')}</p>}
        {!tickets.isLoading && !tickets.isError && list.length === 0 && (
          <p className="p-5 text-[13px] text-[var(--text-muted)]">
            {myOrigins.length === 0 && !staff
              ? t('Only the Owner or an Editor of an origin can open a ticket.', 'เฉพาะ Owner หรือ Editor ของ origin ที่เปิด ticket ได้')
              : t('No tickets yet.', 'ยังไม่มี ticket')}
          </p>
        )}
        {list.length > 0 && (
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-[11px] text-[var(--text-muted)]">
                <th className="px-5 py-3 font-medium">{t('Subject', 'หัวข้อ')}</th>
                <th className="px-5 py-3 font-medium">Origin</th>
                <th className="px-5 py-3 font-medium">{t('Status', 'สถานะ')}</th>
                <th className="px-5 py-3 font-medium">{t('Support access', 'สิทธิ์ของ support')}</th>
                <th className="px-5 py-3 font-medium">{t('Updated', 'อัปเดต')}</th>
              </tr>
            </thead>
            <tbody>
              {list.map((ticket) => (
                <tr
                  key={ticket.ticket_id}
                  className="border-t border-[var(--bg-border)] cursor-pointer hover:bg-[var(--bg-hover)]"
                  onClick={() => navigate(`/support/${ticket.ticket_id}`)}
                >
                  <td className="px-5 py-3 font-medium text-[var(--text-primary)]">{ticket.subject}</td>
                  <td className="px-5 py-3 text-[var(--text-secondary)]">{ticket.origin_label || ticket.origin_id}</td>
                  <td className="px-5 py-3">{ticket.status === 'open' ? t('Open', 'เปิดอยู่') : t('Closed', 'ปิดแล้ว')}</td>
                  <td className="px-5 py-3 text-[var(--text-secondary)]">{ticket.access_granted ? t('Granted', 'ให้สิทธิ์แล้ว') : '—'}</td>
                  <td className="px-5 py-3 text-[var(--text-secondary)]">{timeAgo(ticket.updated_at, Date.now(), lang)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default Support
