import React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { authApi } from '../api/auth'
import { TopBar } from '../components/layout/TopBar'
import { Badge } from '../components/ui/Badge'
import { Button } from '../components/ui/Button'
import { Users as UsersIcon, Shield, Trash2, RefreshCw } from 'lucide-react'
import toast from 'react-hot-toast'

export const Users: React.FC = () => {
  const queryClient = useQueryClient()

  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: authApi.getUsers,
  })

  const updateRoleMutation = useMutation({
    mutationFn: ({ id, role }: { id: string; role: 'admin' | 'viewer' }) => authApi.updateRole(id, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success('Access role updated successfully')
    },
    onError: () => toast.error('Failed to update role'),
  })

  const deleteMutation = useMutation({
    mutationFn: authApi.deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success('User access revoked')
    },
    onError: () => toast.error('Failed to delete user'),
  })

  return (
    <div className="space-y-6 animate-fade-in">
      <TopBar
        title="Role-Based Access Control (RBAC)"
        subtitle="Manage administrator and observer privileges across the CloudWAF control plane"
        badge={
          <Badge color="brand" dot>
            {users.length} ACCOUNTS
          </Badge>
        }
      />

      <div className="dash-card overflow-hidden">
        <div className="dash-card-header">
          <div className="flex items-center gap-2">
            <UsersIcon size={16} className="text-orange-500" />
            <h3>Authorized Accounts</h3>
          </div>
          <span className="text-[11px] font-mono text-[var(--text-muted)]">Admin Management</span>
        </div>

        <div className="overflow-x-auto">
          <table className="dash-table">
            <thead>
              <tr>
                <th>User Identity</th>
                <th>Email Address</th>
                <th>Authentication Provider</th>
                <th>Privilege Level</th>
                <th className="text-right">Revoke Access</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    <RefreshCw size={16} className="animate-spin inline mr-2 text-orange-500" />
                    Loading user directory...
                  </td>
                </tr>
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-10 text-center text-[var(--text-muted)] font-mono text-[12px]">
                    No users registered in system.
                  </td>
                </tr>
              ) : (
                users.map((u) => (
                  <tr key={u.user_id} className="hover:bg-[var(--bg-hover)]">
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/20 text-orange-500 flex items-center justify-center font-mono font-bold text-[12px]">
                          {u.avatar_url ? (
                            <img src={u.avatar_url} className="w-full h-full rounded-lg object-cover" alt="avatar" />
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
                        value={u.role}
                        onChange={(e) =>
                          updateRoleMutation.mutate({
                            id: u.user_id,
                            role: e.target.value as 'admin' | 'viewer',
                          })
                        }
                      >
                        <option value="viewer">Viewer (Read-Only)</option>
                        <option value="admin">Admin (Full Control)</option>
                      </select>
                    </td>
                    <td className="text-right">
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => {
                          if (window.confirm(`Revoke access for user ${u.username}?`)) {
                            deleteMutation.mutate(u.user_id)
                          }
                        }}
                        icon={<Trash2 size={13} />}
                      >
                        Revoke
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
