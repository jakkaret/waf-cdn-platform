import React, { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, CheckCheck, Clock, Shield, Sparkles } from 'lucide-react'
import { aiSummaryApi, NotificationItem } from '../api/aiSummary'
import toast from 'react-hot-toast'
import { formatBkkTime } from '../lib/time'
import { alertSeverity } from '../lib/alertActions'

// The bell: the latest alerts and the unread count. The unread count is the
// backend's (`unread_count` of /ai/notifications/feed), the same number the
// dashboard's "Needs attention" shows. Opening an item marks it read and
// takes the person to its details in the Alert center.
export const NotificationCenter: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['notifications-feed'],
    queryFn: () => aiSummaryApi.getNotificationFeed(40),
    refetchInterval: 6000,
  })

  const markReadMutation = useMutation({
    mutationFn: (id?: string) => aiSummaryApi.markRead(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications-feed'] })
      queryClient.invalidateQueries({ queryKey: ['notifications-feed-dashboard'] })
    },
  })

  const notifications = data?.notifications || []
  const unreadCount = data?.unread_count || 0

  useEffect(() => {
    if (!isOpen) return
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) setIsOpen(false)
    }
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsOpen(false)
        buttonRef.current?.focus()
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('keydown', handleKey)
    panelRef.current?.focus()
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleKey)
    }
  }, [isOpen])

  const handleMarkAllRead = () => {
    markReadMutation.mutate(undefined, {
      onSuccess: () => toast.success('Marked all as read'),
      onError: () => toast.error('Could not mark the alerts as read'),
    })
  }

  const openItem = (item: NotificationItem) => {
    if (!item.read) markReadMutation.mutate(item.alert_id)
    setIsOpen(false)
    navigate(`/alerts?${new URLSearchParams({ alert: item.alert_id }).toString()}`)
  }

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-haspopup="dialog"
        aria-expanded={isOpen}
        aria-label={unreadCount > 0 ? `Alerts, ${unreadCount} unread` : 'Alerts'}
        className="relative h-9 w-9 rounded-lg bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--bg-border)] transition-colors cursor-pointer flex items-center justify-center focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
        title="Alerts"
      >
        <Bell size={17} aria-hidden="true" />
        {unreadCount > 0 && (
          <span className="absolute -top-1.5 -right-1.5 px-1 min-w-[18px] h-[18px] bg-red-600 text-white text-[10.5px] font-semibold rounded-full flex items-center justify-center border-2 border-[var(--bg-app)] tabular-nums">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div
          ref={panelRef}
          role="dialog"
          aria-label="Latest alerts"
          tabIndex={-1}
          className="absolute right-0 mt-2 w-[calc(100vw-2rem)] max-w-[420px] max-h-[560px] bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] rounded-xl shadow-xl z-50 flex flex-col overflow-hidden focus:outline-none"
        >
          <div className="px-4 py-3 border-b border-[var(--bg-border-subtle)] flex items-center justify-between gap-3 bg-[var(--bg-surface)]">
            <div className="min-w-0">
              <h3 className="text-[14px] font-semibold text-[var(--text-primary)] m-0">Latest alerts</h3>
              <span className="text-[12px] text-[var(--text-muted)]">
                {unreadCount} unread, showing the latest {notifications.length}
              </span>
            </div>
            {unreadCount > 0 && (
              <button
                type="button"
                onClick={handleMarkAllRead}
                disabled={markReadMutation.isPending}
                className="shrink-0 text-[12px] text-[var(--accent)] hover:underline flex items-center gap-1 cursor-pointer disabled:opacity-50"
              >
                <CheckCheck size={13} aria-hidden="true" />
                Mark all read
              </button>
            )}
          </div>

          <ul className="m-0 p-0 list-none flex-1 overflow-y-auto divide-y divide-[var(--bg-border-subtle)] max-h-[440px]">
            {isLoading ? (
              <li className="p-8 text-center text-[var(--text-muted)] text-[13px]">Loading alerts…</li>
            ) : isError ? (
              <li className="p-8 text-center text-[13px] text-red-600 dark:text-red-400">Could not load alerts. They will retry in a few seconds.</li>
            ) : notifications.length === 0 ? (
              <li className="p-8 text-center text-[var(--text-muted)]">
                <Shield size={28} className="mx-auto mb-2 opacity-40" aria-hidden="true" />
                <p className="text-[13px] font-medium text-[var(--text-secondary)] m-0">No alerts</p>
                <p className="text-[12px] mt-1 m-0">Nothing was flagged on your sites recently.</p>
              </li>
            ) : (
              notifications.map((item) => {
                const isUnread = !item.read
                const sev = alertSeverity(item.severity)
                return (
                  <li key={item.alert_id}>
                    <button
                      type="button"
                      onClick={() => openItem(item)}
                      className={`w-full text-left px-4 py-3 transition-colors cursor-pointer hover:bg-[var(--bg-hover)] focus-visible:outline-none focus-visible:bg-[var(--bg-hover)] ${isUnread ? 'bg-[var(--accent-subtle)]' : ''}`}
                    >
                      <span className="flex items-start justify-between gap-2 mb-1">
                        <span className="flex items-center gap-1.5 min-w-0">
                          {isUnread && <span className="h-2 w-2 rounded-full bg-[var(--accent)] shrink-0" aria-label="Unread" />}
                          <span className="font-mono text-[12px] text-[var(--text-primary)] font-semibold truncate">{item.ip}</span>
                          {sev && (
                            <span className={`text-[11px] font-medium ${sev === 'CRITICAL' || sev === 'HIGH' ? 'text-red-700 dark:text-red-400' : 'text-[var(--text-muted)]'}`}>
                              {sev.charAt(0) + sev.slice(1).toLowerCase()}
                            </span>
                          )}
                          {item.status && <span className="text-[11px] text-[var(--text-muted)]">HTTP {item.status}</span>}
                        </span>
                        <span className="text-[11px] text-[var(--text-muted)] flex items-center gap-1 shrink-0 tabular-nums">
                          <Clock size={10} aria-hidden="true" />
                          {formatBkkTime(item.timestamp)}
                        </span>
                      </span>
                      <span className="block text-[12px] text-[var(--text-secondary)] truncate font-mono">{item.url}</span>
                      <span className="block text-[12px] text-[var(--text-muted)] truncate">
                        {item.attack_type || item.message || 'WAF rule matched'}
                        {item.rule_id ? ` (rule ${item.rule_id})` : ''}
                      </span>
                      {item.ai_summary && (
                        <span className="mt-1.5 block rounded-md border border-[var(--bg-border)] bg-[var(--bg-surface)] p-2 text-[12px] text-[var(--text-secondary)]">
                          <span className="flex items-center gap-1 text-[11px] font-medium text-indigo-700 dark:text-indigo-300 mb-0.5">
                            <Sparkles size={11} aria-hidden="true" />
                            AI summary, may be inaccurate
                          </span>
                          {item.ai_summary}
                        </span>
                      )}
                    </button>
                  </li>
                )
              })
            )}
          </ul>
          <div className="border-t border-[var(--bg-border-subtle)] px-4 py-2.5 bg-[var(--bg-surface)]">
            <button
              type="button"
              onClick={() => {
                setIsOpen(false)
                navigate('/alerts')
              }}
              className="text-[12.5px] font-medium text-[var(--accent)] hover:underline cursor-pointer"
            >
              Open the Alert center
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
