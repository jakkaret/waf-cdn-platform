import React, { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import toast from 'react-hot-toast'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { GRANT_HOURS, LEVEL_LABEL, SupportTicketDetail, activeGrant, grantSummary } from '../lib/support'
import { timeAgo } from '../lib/mlRules'

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
    onError: onError('Could not send the message'),
  })
  const grant = useMutation({
    mutationFn: async () =>
      api.post(`/support/tickets/${id}/grant`, { level, hours, confirm_edit: level === 'editor' && confirmEdit }),
    onSuccess: () => {
      toast.success('Support access granted')
      setConfirmEdit(false)
      refresh()
    },
    onError: onError('Could not grant access'),
  })
  const revoke = useMutation({
    mutationFn: async () => api.delete(`/support/tickets/${id}/grant`),
    onSuccess: () => {
      toast.success('Support access removed')
      refresh()
    },
    onError: onError('Could not remove access'),
  })
  const close = useMutation({
    mutationFn: async () => api.post(`/support/tickets/${id}/close`),
    onSuccess: () => {
      toast.success('Ticket closed')
      refresh()
    },
    onError: onError('Could not close the ticket'),
  })

  if (isLoading) return <p className="p-5 text-[13px] text-[var(--text-muted)]">Loading ticket...</p>
  if (isError || !data) return <p className="p-5 text-[13px] text-[var(--text-muted)]">Ticket not found.</p>

  const { ticket, origin, messages, grants, access_log, can_grant, staff } = data
  const isOpen = ticket.status === 'open'
  const current = activeGrant(grants)
  return (
    <div className="animate-fade-in pb-12">
      <TopBar
        title={ticket.subject}
        subtitle={`${origin.label || origin.id} · ${isOpen ? 'Open' : 'Closed'} · opened ${timeAgo(ticket.created_at)}`}
        action={
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => navigate('/support')}>All tickets</Button>
            {staff && current && (
              <Button variant="outline" onClick={() => navigate(`/origins/${origin.id}`)}>Open origin</Button>
            )}
            {isOpen && (
              <Button variant="outline" onClick={() => close.mutate()} isLoading={close.isPending}>Close ticket</Button>
            )}
          </div>
        }
      />

      <div className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <section className="dash-card p-5 grid gap-3 content-start">
          <h3 className="m-0 text-[13px] font-bold">Conversation</h3>
          {messages.map((m) => (
            <div
              key={m.message_id}
              className={`rounded-lg border border-[var(--bg-border)] p-3 ${m.is_support ? 'bg-[var(--bg-primary)]' : ''}`}
            >
              <div className="text-[11px] text-[var(--text-muted)] mb-1">
                {m.is_support ? 'Support' : m.author_name || 'Origin admin'} · {timeAgo(m.created_at)}
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
              <textarea className="dash-input min-h-[90px]" maxLength={5000} value={reply} onChange={(e) => setReply(e.target.value)} placeholder="Write a reply" />
              <div>
                <Button type="submit" variant="brand" isLoading={send.isPending} disabled={!reply.trim()}>Send</Button>
              </div>
            </form>
          ) : (
            <p className="text-[12px] text-[var(--text-muted)] m-0">This ticket is closed.</p>
          )}
        </section>

        <aside className="grid gap-4 content-start">
          <section className="dash-card p-5 grid gap-3">
            <h3 className="m-0 text-[13px] font-bold">Support access</h3>
            <p className="m-0 text-[12.5px] text-[var(--text-secondary)]">{grantSummary(grants)}</p>
            {can_grant && isOpen && (
              <div className="grid gap-2">
                <label className="grid gap-1 text-[12px] text-[var(--text-secondary)]">
                  Level
                  <select className="dash-input" value={level} onChange={(e) => setLevel(e.target.value as 'viewer' | 'editor')}>
                    <option value="viewer">{LEVEL_LABEL.viewer} (recommended)</option>
                    <option value="editor">{LEVEL_LABEL.editor}</option>
                  </select>
                </label>
                <label className="grid gap-1 text-[12px] text-[var(--text-secondary)]">
                  For
                  <select className="dash-input" value={hours} onChange={(e) => setHours(Number(e.target.value))}>
                    {GRANT_HOURS.map((h) => (
                      <option key={h} value={h}>{h} hour{h > 1 ? 's' : ''}</option>
                    ))}
                  </select>
                </label>
                {level === 'editor' && (
                  <label className="flex gap-2 items-start text-[12px] text-amber-500">
                    <input type="checkbox" checked={confirmEdit} onChange={(e) => setConfirmEdit(e.target.checked)} />
                    I allow the support team to change this origin's settings, domains and rules.
                  </label>
                )}
                <Button
                  variant="brand"
                  onClick={() => grant.mutate()}
                  isLoading={grant.isPending}
                  disabled={level === 'editor' && !confirmEdit}
                >
                  {current ? 'Replace access' : 'Grant access'}
                </Button>
                {current && (
                  <Button variant="danger" onClick={() => revoke.mutate()} isLoading={revoke.isPending}>
                    Remove access now
                  </Button>
                )}
                <p className="m-0 text-[11.5px] text-[var(--text-muted)]">
                  Support can never delete the origin, manage its members or issue tunnel credentials.
                  Access also ends when the ticket is closed.
                </p>
              </div>
            )}
          </section>

          <section className="dash-card p-5 grid gap-2">
            <h3 className="m-0 text-[13px] font-bold">Access log</h3>
            {access_log.length === 0 ? (
              <p className="m-0 text-[12px] text-[var(--text-muted)]">Support has not used access on this ticket.</p>
            ) : (
              <ul className="m-0 p-0 list-none grid gap-1 text-[12px]">
                {access_log.map((e, i) => (
                  <li key={i} className="text-[var(--text-secondary)]">
                    {e.staff_name || 'support'} · {e.kind === 'edit' ? 'changed something' : 'viewed'} · {timeAgo(e.at)}
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
