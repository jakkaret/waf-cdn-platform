import { api } from './axios'
import { User } from '../types'

export const authApi = {
  login: async (email: string, password: string) => {
    // FastAPI OAuth2PasswordRequestForm needs x-www-form-urlencoded
    const formData = new URLSearchParams()
    formData.append('username', email)
    formData.append('password', password)

    const res = await api.post<{ access_token: string; token_type: string }>('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
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
