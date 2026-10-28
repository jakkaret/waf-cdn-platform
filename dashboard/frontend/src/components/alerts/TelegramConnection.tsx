import React, { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, CheckCircle2, Copy, ExternalLink, RefreshCw, Send } from 'lucide-react'
import toast from 'react-hot-toast'
import { alertsApi } from '../../api/alerts'
import { Badge } from '../ui/Badge'
import { Button } from '../ui/Button'
import { ConfirmDialog } from '../ui/ConfirmDialog'
import { tr, useT } from '../../i18n'

// Link this account to the Telegram bot (moved here from the Alert center,
// 2026-10-28). Pairing: the backend issues a one-time code, the person sends
// it to the bot, and this card polls until the bot reports the chat.
export const TelegramConnection: React.FC = () => {
  const queryClient = useQueryClient()
  const [code, setCode] = useState<string | null>(null)
  const [botUsername, setBotUsername] = useState<string>('WAF_Project_Bot')
  const [copied, setCopied] = useState(false)
  const [confirmDisconnect, setConfirmDisconnect] = useState(false)
  const { t } = useT()

  const { data: status, isLoading, isError } = useQuery({
    queryKey: ['telegram-status'],
    queryFn: alertsApi.getConnectionStatus,
    refetchInterval: code ? 3000 : false,
  })

  const connectMutation = useMutation({
    mutationFn: alertsApi.startConnection,
    onSuccess: (data) => {
      setCode(data.code)
      if (data.bot_username) setBotUsername(data.bot_username)
    },
    onError: () => toast.error(t('Could not start the Telegram connection. Try again.', 'เริ่มเชื่อม Telegram ไม่สำเร็จ ลองใหม่อีกครั้ง')),
  })

  const disconnectMutation = useMutation({
    mutationFn: alertsApi.disconnect,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
      queryClient.invalidateQueries({ queryKey: ['notification-prefs'] })
      toast.success(t('Telegram disconnected', 'ยกเลิกการเชื่อม Telegram แล้ว'))
    },
    onError: () => toast.error(t('Could not disconnect Telegram. Try again.', 'ยกเลิกการเชื่อม Telegram ไม่สำเร็จ ลองใหม่อีกครั้ง')),
    onSettled: () => setConfirmDisconnect(false),
  })

  useEffect(() => {
    if (!code) return
    const interval = setInterval(async () => {
      try {
        const res = await alertsApi.pollConnection(code)
        if (res.status === 'connected') {
          setCode(null)
          queryClient.invalidateQueries({ queryKey: ['telegram-status'] })
          queryClient.invalidateQueries({ queryKey: ['notification-prefs'] })
          toast.success(tr('Telegram connected', 'เชื่อม Telegram แล้ว'))
        } else if (res.status === 'expired') {
          setCode(null)
          toast.error(tr('The pairing code expired. Start again to get a new one.', 'รหัสจับคู่หมดอายุแล้ว เริ่มใหม่เพื่อรับรหัสใหม่'))
        }
      } catch {
        // A failed poll is retried on the next tick.
      }
    }, 3000)
    return () => clearInterval(interval)
  }, [code, queryClient])

  const copyCode = () => {
    if (!code) return
    navigator.clipboard.writeText(code)
    setCopied(true)
    toast.success(t('Pairing code copied', 'คัดลอกรหัสจับคู่แล้ว'))
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section className="dash-card p-4 sm:p-5" aria-labelledby="telegram-heading">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <span className="w-9 h-9 rounded-lg bg-sky-500/10 flex items-center justify-center text-sky-700 dark:text-sky-400 shrink-0">
            <Send size={16} aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h2 id="telegram-heading" className="m-0 text-[14px] font-semibold text-[var(--text-primary)]">Telegram</h2>
              {isLoading ? (
                <Badge color="gray" size="sm">{t('Checking…', 'กำลังตรวจ…')}</Badge>
              ) : isError ? (
                <Badge color="gray" size="sm">{t('Status unavailable', 'ไม่มีข้อมูลสถานะ')}</Badge>
              ) : (
                <Badge color={status?.connected ? 'success' : 'warning'} size="sm" dot>
                  {status?.connected ? t('Connected', 'เชื่อมแล้ว') : t('Not connected', 'ยังไม่เชื่อม')}
                </Badge>
              )}
            </div>
            <p className="m-0 mt-0.5 text-[12.5px] text-[var(--text-muted)]">
              {status?.connected ? (
                <span className="inline-flex items-center gap-1">
                  <CheckCircle2 size={12} className="text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
                  {t('Messages go to chat', 'ส่งข้อความไปที่แชท')} <span className="font-mono">{status.chat_id}</span>
                </span>
              ) : (
                t('Get attack, outage and certificate notices for your sites in a Telegram chat.', 'รับแจ้งการโจมตี เว็บล่ม และใบรับรองของเว็บคุณทางแชท Telegram')
              )}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {!status?.connected && !code && (
            <Button
              variant="brand"
              size="sm"
              onClick={() => connectMutation.mutate()}
              isLoading={connectMutation.isPending}
              disabled={isLoading || isError}
              icon={<Send size={12} />}
            >
              {t('Connect Telegram', 'เชื่อม Telegram')}
            </Button>
          )}
          {status?.connected && (
            <Button variant="outline" size="sm" onClick={() => setConfirmDisconnect(true)}>
              {t('Disconnect', 'ยกเลิกการเชื่อม')}
            </Button>
          )}
        </div>
      </div>

      {code && (
        <div className="mt-4 pt-4 border-t border-[var(--bg-border-subtle)] space-y-2.5 text-[12.5px]">
          <ol className="m-0 pl-5 space-y-1 text-[var(--text-secondary)]">
            <li>{t('Open the bot in Telegram.', 'เปิดบอทใน Telegram')}</li>
            <li>{t('Send it this pairing code. The page updates by itself once the bot answers.', 'ส่งรหัสจับคู่นี้ให้บอท หน้านี้จะอัปเดตเองเมื่อบอทตอบ')}</li>
          </ol>
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 font-mono font-semibold text-sky-800 dark:text-sky-300 bg-sky-500/10 border border-sky-500/25 px-2.5 py-1 rounded">
              {code}
              <button
                type="button"
                onClick={copyCode}
                className="p-0.5 hover:text-sky-900 dark:hover:text-white cursor-pointer"
                aria-label={t('Copy pairing code', 'คัดลอกรหัสจับคู่')}
              >
                {copied ? <Check size={13} className="text-emerald-600" /> : <Copy size={13} />}
              </button>
            </span>
            <a
              href={`https://t.me/${botUsername}?start=${code}`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 px-2.5 py-1 bg-sky-600 hover:bg-sky-700 text-white rounded text-[12px] font-medium"
            >
              {t('Open', 'เปิด')} @{botUsername}
              <ExternalLink size={11} aria-hidden="true" />
            </a>
            <span className="text-[12px] text-[var(--text-muted)] inline-flex items-center gap-1">
              <RefreshCw size={11} className="animate-spin motion-reduce:animate-none" aria-hidden="true" />
              {t('Waiting for the bot…', 'รอบอทตอบ…')}
            </span>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={confirmDisconnect}
        onCancel={() => setConfirmDisconnect(false)}
        onConfirm={() => {
          if (!disconnectMutation.isPending) disconnectMutation.mutate()
        }}
        title={t('Disconnect Telegram?', 'ยกเลิกการเชื่อม Telegram?')}
        message={t(
          'You will stop receiving notifications in this chat until you connect again. Your per-site choices are kept.',
          'คุณจะไม่ได้รับการแจ้งเตือนในแชทนี้จนกว่าจะเชื่อมใหม่ การตั้งค่าของแต่ละเว็บยังเก็บไว้',
        )}
        confirmText={disconnectMutation.isPending ? t('Disconnecting…', 'กำลังยกเลิก…') : t('Disconnect', 'ยกเลิกการเชื่อม')}
        isDanger
      />
    </section>
  )
}

export default TelegramConnection
