import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { useAuthStore } from '../store/authStore'
import { DeviceSession, describeUserAgent } from '../lib/devices'
import { timeAgo } from '../lib/mlRules'
import { useT } from '../i18n'

// Signed-in devices of this account. Each sign-in is its own session; any one
// can be signed out here without touching the others.
const Devices: React.FC = () => {
  const queryClient = useQueryClient()
  const logout = useAuthStore((s) => s.logout)
  const { t, lang } = useT()

  const { data, isLoading, isError } = useQuery({
    queryKey: ['my-sessions'],
    queryFn: async () => (await api.get<{ sessions: DeviceSession[] }>('/auth/sessions')).data.sessions,
    refetchInterval: 30000,
  })

  const revoke = useMutation({
    mutationFn: async (s: DeviceSession) =>
      (await api.delete<{ status: string; current: boolean }>(`/auth/sessions/${s.session_id}`)).data,
    onSuccess: (res) => {
      if (res.current) {
        logout()
        window.location.href = '/login'
        return
      }
      toast.success(t('Device signed out', 'ออกจากระบบอุปกรณ์นั้นแล้ว'))
      queryClient.invalidateQueries({ queryKey: ['my-sessions'] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || t('Could not sign that device out', 'ออกจากระบบอุปกรณ์นั้นไม่สำเร็จ')),
  })

  const signOutAll = async () => {
    try {
      await api.post('/auth/logout-all')
    } finally {
      logout()
      window.location.href = '/login'
    }
  }

  const sessions = data || []
  return (
    <div className="animate-fade-in pb-12">
      <TopBar
        title={t('Signed-in devices', 'อุปกรณ์ที่ลงชื่อเข้าใช้')}
        subtitle={t(
          'Every place your account is signed in. Signing out one device does not affect the others.',
          'ทุกที่ที่บัญชีของคุณลงชื่อเข้าใช้อยู่ การออกจากระบบอุปกรณ์หนึ่งไม่กระทบอุปกรณ์อื่น',
        )}
        action={
          <Button variant="outline" onClick={signOutAll} disabled={sessions.length === 0}>
            {t('Sign out of all devices', 'ออกจากระบบทุกอุปกรณ์')}
          </Button>
        }
      />
      <div className="dash-card p-0 overflow-x-auto">
        {isLoading && <p className="p-5 text-[13px] text-[var(--text-muted)]">{t('Loading devices...', 'กำลังโหลดอุปกรณ์...')}</p>}
        {isError && <p className="p-5 text-[13px] text-[var(--text-muted)]">{t('Could not load your devices. Try again in a moment.', 'โหลดรายการอุปกรณ์ไม่สำเร็จ ลองใหม่อีกสักครู่')}</p>}
        {!isLoading && !isError && sessions.length === 0 && (
          <p className="p-5 text-[13px] text-[var(--text-muted)]">{t('No active sessions.', 'ไม่มีการเข้าระบบที่ใช้งานอยู่')}</p>
        )}
        {sessions.length > 0 && (
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-[11px] text-[var(--text-muted)]">
                <th className="px-5 py-3 font-medium">{t('Device', 'อุปกรณ์')}</th>
                <th className="px-5 py-3 font-medium">{t('IP address', 'IP')}</th>
                <th className="px-5 py-3 font-medium">{t('Signed in', 'ลงชื่อเข้าใช้เมื่อ')}</th>
                <th className="px-5 py-3 font-medium">{t('Last active', 'ใช้งานล่าสุด')}</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.session_id} className="border-t border-[var(--bg-border)]">
                  <td className="px-5 py-3">
                    <span className="font-medium text-[var(--text-primary)]" title={s.user_agent}>
                      {describeUserAgent(s.user_agent, lang)}
                    </span>
                    {s.current && (
                      <span className="ml-2 rounded-full bg-[var(--accent-subtle,rgba(16,185,129,.12))] px-2 py-0.5 text-[11px] text-[var(--accent,#10b981)]">
                        {t('This device', 'อุปกรณ์นี้')}
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3 font-mono text-[var(--text-secondary)]">{s.ip || '—'}</td>
                  <td className="px-5 py-3 text-[var(--text-secondary)]">{timeAgo(s.created_at, Date.now(), lang)}</td>
                  <td className="px-5 py-3 text-[var(--text-secondary)]">{timeAgo(s.last_seen_at, Date.now(), lang)}</td>
                  <td className="px-5 py-3 text-right">
                    <Button
                      variant={s.current ? 'outline' : 'danger'}
                      onClick={() => revoke.mutate(s)}
                      isLoading={revoke.isPending && revoke.variables?.session_id === s.session_id}
                    >
                      {s.current ? t('Sign out here', 'ออกจากระบบที่นี่') : t('Sign out', 'ออกจากระบบ')}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default Devices
