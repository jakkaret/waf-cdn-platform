import React from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { api } from '../api/axios'
import { TopBar } from '../components/layout/TopBar'
import { Button } from '../components/ui/Button'
import { useAuthStore } from '../store/authStore'
import { DeviceSession, describeUserAgent } from '../lib/devices'
import { timeAgo } from '../lib/mlRules'

// Signed-in devices of this account. Each sign-in is its own session; any one
// can be signed out here without touching the others.
const Devices: React.FC = () => {
  const queryClient = useQueryClient()
  const logout = useAuthStore((s) => s.logout)

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
      toast.success('Device signed out')
      queryClient.invalidateQueries({ queryKey: ['my-sessions'] })
    },
    onError: (e: any) => toast.error(e.response?.data?.detail || 'Could not sign that device out'),
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
        title="Signed-in devices"
        subtitle="Every place your account is signed in. Signing out one device does not affect the others."
        action={
          <Button variant="outline" onClick={signOutAll} disabled={sessions.length === 0}>
            Sign out of all devices
          </Button>
        }
      />
      <div className="dash-card p-0 overflow-x-auto">
        {isLoading && <p className="p-5 text-[13px] text-[var(--text-muted)]">Loading devices...</p>}
        {isError && <p className="p-5 text-[13px] text-[var(--text-muted)]">Could not load your devices. Try again in a moment.</p>}
        {!isLoading && !isError && sessions.length === 0 && (
          <p className="p-5 text-[13px] text-[var(--text-muted)]">No active sessions.</p>
        )}
        {sessions.length > 0 && (
          <table className="w-full text-[13px]">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-[var(--text-muted)]">
                <th className="px-5 py-3 font-medium">Device</th>
                <th className="px-5 py-3 font-medium">IP address</th>
                <th className="px-5 py-3 font-medium">Signed in</th>
                <th className="px-5 py-3 font-medium">Last active</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.session_id} className="border-t border-[var(--bg-border)]">
                  <td className="px-5 py-3">
                    <span className="font-medium text-[var(--text-primary)]" title={s.user_agent}>
                      {describeUserAgent(s.user_agent)}
                    </span>
                    {s.current && (
                      <span className="ml-2 rounded-full bg-[var(--accent-subtle,rgba(16,185,129,.12))] px-2 py-0.5 text-[11px] text-[var(--accent,#10b981)]">
                        This device
                      </span>
                    )}
                  </td>
                  <td className="px-5 py-3 font-mono text-[var(--text-secondary)]">{s.ip || '—'}</td>
                  <td className="px-5 py-3 text-[var(--text-secondary)]">{timeAgo(s.created_at)}</td>
                  <td className="px-5 py-3 text-[var(--text-secondary)]">{timeAgo(s.last_seen_at)}</td>
                  <td className="px-5 py-3 text-right">
                    <Button
                      variant={s.current ? 'outline' : 'danger'}
                      onClick={() => revoke.mutate(s)}
                      isLoading={revoke.isPending && revoke.variables?.session_id === s.session_id}
                    >
                      {s.current ? 'Sign out here' : 'Sign out'}
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
