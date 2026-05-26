import axios from 'axios'
import { useAuthStore } from '../store/authStore'

export const api = axios.create({
  baseURL: '/api',
  withCredentials: true, // ส่ง HttpOnly cookie ทุก request (ใช้สำหรับ OAuth cookie-based session)
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request Interceptor: add token
api.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response Interceptor: handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear store if token is invalid/expired
      useAuthStore.getState().logout()
    }
    return Promise.reject(error)
  }
)
