import { api } from './axios'
import { User } from '../types'

export const authApi = {
  login: async (email: string, password: string) => {
    const res = await api.post<{ access_token: string; token_type: string }>('/auth/login', {
      email,
      password,
    })
    return res.data
  },

  getMe: async () => {
    const res = await api.get<User>('/auth/me')
    return res.data
  },

  register: async (data: { email: string; password: string; username: string }) => {
    const res = await api.post<{ message: string; user_id: string }>('/auth/register', data)
    return res.data
  },

  // Email verification by a 6-digit code (api/auth.py /verify-email).
  sendVerifyCode: async () => {
    const res = await api.post<{ verified: boolean; sent?: boolean; retry_after?: number; expires_in?: number }>(
      '/auth/verify-email/send'
    )
    return res.data
  },

  confirmVerifyCode: async (code: string) => {
    const res = await api.post<{ verified: boolean; user: User }>('/auth/verify-email/confirm', { code })
    return res.data
  },

  forgotPassword: async (email: string) => {
    const res = await api.post<{ message: string }>('/auth/password/forgot', { email })
    return res.data
  },

  // Signs the account out on every device (api/auth.py reset_password).
  resetPassword: async (email: string, code: string, newPassword: string) => {
    const res = await api.post<{ message: string }>('/auth/password/reset', { email, code, new_password: newPassword })
    return res.data
  },

  getUsers: async () => {
    const res = await api.get<{ users: User[] }>('/auth/users')
    return res.data.users
  },

  updateRole: async (userId: string, role: 'admin' | 'viewer') => {
    const res = await api.put(`/auth/users/${userId}/role`, { role })
    return res.data
  },

  deleteUser: async (userId: string) => {
    const res = await api.delete(`/auth/users/${userId}`)
    return res.data
  }
}
