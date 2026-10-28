import React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { authApi } from '../api/auth'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Users as UsersIcon, Shield, Trash2, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'
import { PLATFORM_ROLE_LABEL } from '../lib/roles'
import { useT } from '../i18n'

export const Users: React.FC = () => {
  const queryClient = useQueryClient()
  const { t } = useT()

  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: authApi.getUsers,
  })

  const updateRoleMutation = useMutation({
    mutationFn: ({ id, role }: { id: string; role: 'admin' | 'viewer' }) => authApi.updateRole(id, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success(t('Role updated', 'อัปเดตสิทธิ์แล้ว'))
    },
    onError: () => toast.error(t('Failed to update role', 'อัปเดตสิทธิ์ไม่สำเร็จ')),
  })

  const deleteMutation = useMutation({
    mutationFn: authApi.deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success(t('User access revoked', 'ยกเลิกสิทธิ์ผู้ใช้แล้ว'))
    },
    onError: () => toast.error(t('Failed to delete user', 'ลบผู้ใช้ไม่สำเร็จ')),
  })

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title={t('Access control', 'สิทธิ์การเข้าถึง')}
        subtitle={t('Platform roles: who is a platform operator and who is a regular user.', 'สิทธิ์ระดับแพลตฟอร์ม: ใครเป็นผู้ดูแลแพลตฟอร์ม และใครเป็นผู้ใช้ทั่วไป')}
        badge={
          <Badge color="brand" dot>
            {users.length} {t('ACCOUNTS', 'บัญชี')}
          </Badge>
        }
      />

      <div className="dash-card overflow-hidden">
        <div className="dash-card-header">
          <div className="flex items-center gap-2">
            <UsersIcon size={16} className="text-orange-500" />
            <h3>{t('Accounts', 'บัญชีผู้ใช้')}</h3>
          </div>
          <span className="text-[11px] font-mono text-[var(--text-muted)]">{t('Admin management', 'การจัดการของผู้ดูแล')}</span>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>{t('User', 'ผู้ใช้')}</th>
                <th>{t('Email', 'อีเมล')}</th>
                <th>{t('Sign-in method', 'วิธีลงชื่อเข้าใช้')}</th>
                <th>{t('Role', 'สิทธิ์')}</th>
                <th className="text-right">{t('Revoke access', 'ยกเลิกสิทธิ์')}</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    <RefreshCw size={16} className="animate-spin inline mr-2 text-orange-500" />
                    {t('Loading users...', 'กำลังโหลดผู้ใช้...')}
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    {t('No users registered yet.', 'ยังไม่มีผู้ใช้ในระบบ')}
                  </td>
                </tr>
              ) : (
                users.map((u) => (
                  <tr key={u.user_id} className="hover:bg-[var(--bg-hover)]">
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/20 text-orange-500 flex items-center justify-center font-mono font-bold text-[12px]">
                          {u.avatar_url ? (
                            <img src={u.avatar_url} className="w-full h-full rounded-lg object-cover" alt={t('avatar', 'รูปโปรไฟล์')} />
                          ) : (
                            u.username.charAt(0).toUpperCase()
                          )}
                        </div>
                        <span className="font-semibold text-[13px] font-mono text-[var(--text-primary)]">
                          {u.username}
                        </span>
                      </div>
                    </td>
                    <td className="font-mono text-[12px] text-[var(--text-secondary)]">{u.email}</td>
                    <td>
                      <Badge color={u.auth_provider === 'google' ? 'info' : 'gray'}>
                        {u.auth_provider.toUpperCase()}
                      </Badge>
                    </td>
                    <td>
                      <select
                        className="dash-input py-1 text-[12px] font-mono cursor-pointer"
                        aria-label={t(`Role of ${u.username}`, `สิทธิ์ของ ${u.username}`)}
                        value={u.role}
                        onChange={(e) =>
                          updateRoleMutation.mutate({
                            id: u.user_id,
                            role: e.target.value as 'admin' | 'viewer',
                          })
                        }
                      >
                        <option value="viewer">{t(PLATFORM_ROLE_LABEL.viewer, 'ผู้ใช้')}</option>
                        <option value="admin">{t(PLATFORM_ROLE_LABEL.admin, 'Support (ผู้ดูแล)')}</option>
                      </select>
                    </td>
                    <td className="text-right">
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => {
                          if (window.confirm(t(`Revoke access for user ${u.username}?`, `ยกเลิกสิทธิ์ของผู้ใช้ ${u.username}?`))) {
                            deleteMutation.mutate(u.user_id)
                          }
                        }}
                        icon={<Trash2 size={13} />}
                      >
                        {t('Revoke', 'ยกเลิกสิทธิ์')}
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Users
