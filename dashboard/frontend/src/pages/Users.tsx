import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { authApi } from '../api/auth'
import { TopBar } from '../components/layout/TopBar'
import { Card } from '../components/ui/Card'
import { Button } from '../components/ui/Button'
import { Badge } from '../components/ui/Badge'
import toast from 'react-hot-toast'

export const Users: React.FC = () => {
  const queryClient = useQueryClient()
  
  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: authApi.getUsers,
  })

  const updateRoleMutation = useMutation({
    mutationFn: ({ id, role }: { id: string, role: 'admin' | 'viewer' }) => authApi.updateRole(id, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success('Role updated successfully')
    },
    onError: () => toast.error('Failed to update role')
  })

  const deleteMutation = useMutation({
    mutationFn: authApi.deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success('User deleted')
    },
    onError: () => toast.error('Failed to delete user')
  })

  return (
    <div>
      <TopBar title="Users & Roles" subtitle="Manage access control (Admin Only)" />

      <Card noPadding>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-white/5 text-text-muted text-[11px] uppercase tracking-wider">
              <tr>
                <th className="p-4 font-semibold">User</th>
                <th className="p-4 font-semibold">Email</th>
                <th className="p-4 font-semibold">Provider</th>
                <th className="p-4 font-semibold">Role</th>
                <th className="p-4 font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {isLoading ? (
                <tr><td colSpan={5} className="p-8 text-center text-text-muted">Loading users...</td></tr>
              ) : users.length === 0 ? (
                <tr><td colSpan={5} className="p-8 text-center text-text-muted">No users found</td></tr>
              ) : (
                users.map((u) => (
                  <tr key={u.user_id} className="hover:bg-white/5 transition-colors">
                    <td className="p-4">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-full bg-white/10 flex items-center justify-center font-bold">
                          {u.avatar_url ? <img src={u.avatar_url} className="rounded-full" alt="avatar" /> : u.username.charAt(0).toUpperCase()}
                        </div>
                        <span className="font-semibold">{u.username}</span>
                      </div>
                    </td>
                    <td className="p-4 text-text-muted">{u.email}</td>
                    <td className="p-4"><Badge color={u.auth_provider === 'google' ? 'info' : 'gray'}>{u.auth_provider}</Badge></td>
                    <td className="p-4">
                      <select 
                        className="bg-bg-surface border border-white/10 rounded px-2 py-1 text-sm outline-none"
                        value={u.role}
                        onChange={(e) => updateRoleMutation.mutate({ id: u.user_id, role: e.target.value as 'admin'|'viewer' })}
                      >
                        <option value="viewer">Viewer</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td className="p-4">
                      <Button variant="danger" size="sm" onClick={() => {
                        if(window.confirm('Delete user?')) deleteMutation.mutate(u.user_id)
                      }}>Remove</Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

export default Users
