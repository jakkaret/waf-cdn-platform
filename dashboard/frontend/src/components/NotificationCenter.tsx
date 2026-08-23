import React, { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, ShieldAlert, CheckCheck, Clock, Globe, Shield, Sparkles, X, ChevronRight } from 'lucide-react'
import { aiSummaryApi, NotificationItem } from '../api/aiSummary'
import toast from 'react-hot-toast'

export const NotificationCenter: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false)
  const [selectedNotification, setSelectedNotification] = useState<NotificationItem | null>(null)
  const dropdownRef = useRef<HTMLDivElement>(null)
  const queryClient = useQueryClient()

  // Real-time polling for notifications every 6s
  const { data, isLoading } = useQuery({
    queryKey: ['notifications-feed'],
    queryFn: () => aiSummaryApi.getNotificationFeed(40),
    refetchInterval: 6000,
  })

  const markReadMutation = useMutation({
    mutationFn: (id?: string) => aiSummaryApi.markRead(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications-feed'] })
    },
  })

  const notifications = data?.notifications || []
  const unreadCount = data?.unread_count || 0

  // Click outside to close
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false)
      }
    }
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isOpen])

  const handleMarkAllRead = () => {
    markReadMutation.mutate(undefined)
    toast.success('Marked all notifications as read')
  }

  const handleSelect = (item: NotificationItem) => {
    setSelectedNotification(item)
    if (!item.read) {
      markReadMutation.mutate(item.alert_id)
    }
  }

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Bell Button with Badge */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 rounded-lg bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] border border-[var(--bg-border)] transition-all cursor-pointer flex items-center justify-center"
        title="Security Notifications"
      >
        <Bell size={17} className={unreadCount > 0 ? 'text-amber-400 animate-pulse' : ''} />
        {unreadCount > 0 && (
          <span className="absolute -top-1 -right-1 px-1.5 py-0.2 min-w-[18px] h-[18px] bg-red-500 text-white font-mono text-[10px] font-bold rounded-full flex items-center justify-center border-2 border-[var(--bg-primary)] animate-bounce">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Notification Dropdown Panel */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-[360px] sm:w-[440px] max-h-[560px] bg-[var(--bg-surface-elevated)] border border-[var(--bg-border)] rounded-xl shadow-2xl z-50 flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150 backdrop-blur-md">
          {/* Header */}
          <div className="p-3.5 px-4 border-b border-[var(--bg-border-subtle)] flex items-center justify-between bg-[var(--bg-surface)]">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md bg-red-500/10 text-red-400 border border-red-500/20">
                <ShieldAlert size={15} />
              </div>
              <div>
                <h3 className="text-[13px] font-bold text-[var(--text-primary)] font-mono uppercase tracking-wider m-0">
                  Security Alerts
                </h3>
                <span className="text-[11px] text-[var(--text-muted)]">
                  {unreadCount} unread / {notifications.length} total events
                </span>
              </div>
            </div>
            {unreadCount > 0 && (
              <button
                type="button"
                onClick={handleMarkAllRead}
                className="text-[11px] font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1 transition-colors cursor-pointer"
              >
                <CheckCheck size={13} />
                Mark all read
              </button>
            )}
          </div>

          {/* Feed List */}
          <div className="flex-1 overflow-y-auto divide-y divide-[var(--bg-border-subtle)] max-h-[460px]">
            {isLoading ? (
              <div className="p-8 text-center text-[var(--text-muted)] text-[12px]">
                <div className="inline-block w-5 h-5 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin mb-2" />
                <p>Loading security events...</p>
              </div>
            ) : notifications.length === 0 ? (
              <div className="p-8 text-center text-[var(--text-muted)]">
                <Shield size={32} className="mx-auto mb-2 opacity-30 text-emerald-400" />
                <p className="text-[13px] font-medium text-[var(--text-secondary)] m-0">All clear!</p>
                <p className="text-[11.5px] mt-1 text-[var(--text-muted)] m-0">No security attacks detected recently.</p>
              </div>
            ) : (
              notifications.map((item) => {
                const isUnread = !item.read
                const isCritical = item.status === '403' || item.severity === 'CRITICAL'

                return (
                  <div
                    key={item.alert_id}
                    onClick={() => handleSelect(item)}
                    className={`p-3.5 px-4 transition-colors cursor-pointer hover:bg-[var(--bg-hover)] ${
                      isUnread ? 'bg-indigo-500/5' : ''
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span
                          className={`px-1.5 py-0.5 rounded font-mono text-[10px] font-bold ${
                            isCritical
                              ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                              : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                          }`}
                        >
                          HTTP {item.status || '403'}
                        </span>
                        <span className="font-mono text-[11px] text-[var(--text-primary)] font-semibold truncate max-w-[180px]">
                          {item.ip}
                        </span>
                      </div>
                      <span className="text-[10px] text-[var(--text-muted)] font-mono flex items-center gap-1 shrink-0">
                        <Clock size={10} />
                        {new Date(item.timestamp || '').toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>

                    <p className="text-[11.5px] text-[var(--text-secondary)] font-mono truncate m-0 mb-1.5">
                      <span className="text-[var(--text-muted)]">Target:</span> {item.url}
                    </p>

                    {/* Gemini AI Human-Readable Explanation Box */}
                    {item.ai_summary ? (
                      <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-[11.5px] text-indigo-200 space-y-1">
                        <div className="flex items-center gap-1 text-indigo-400 font-bold text-[10.5px] uppercase tracking-wider">
                          <Sparkles size={11} />
                          <span>Gemini AI Insights</span>
                        </div>
                        <p className="m-0 leading-relaxed font-sans text-[11px] text-[var(--text-primary)]">
                          {item.ai_summary}
                        </p>
                      </div>
                    ) : (
                      <p className="text-[11px] text-[var(--text-muted)] m-0">
                        {item.attack_type || item.message || 'WAF Security Rule triggered'}
                      </p>
                    )}
                  </div>
                )
              })
            )}
          </div>
        </div>
      )}
    </div>
  )
}
