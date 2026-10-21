import axios from 'axios'
import { useAuthStore } from '../store/authStore'
import { parseEmailGate, useEmailGateStore } from '../lib/emailGate'

export const api = axios.create({
  baseURL: '/api',
  withCredentials: true, // ส่ง HttpOnly cookie ทุก request (ใช้สำหรับ OAuth cookie-based session)
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request Interceptor: double-submit CSRF token.
// Auth rides the HttpOnly session cookie (sent via withCredentials), so we no
// longer attach a Bearer token from JS. For state-changing methods we copy the
// non-HttpOnly csrf_token cookie into the X-CSRF-Token header; the backend
// requires the two to match.
function readCookie(name: string): string | null {
  const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
  return m ? decodeURIComponent(m[1]) : null
}

api.interceptors.request.use(
  (config) => {
    const method = (config.method || 'get').toLowerCase()
    if (!['get', 'head', 'options'].includes(method)) {
      const csrf = readCookie('csrf_token')
      if (csrf) config.headers['X-CSRF-Token'] = csrf
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Response Interceptor: handle 401, and the unverified-email gate (403
// email_unverified) for any button a page did not guard itself: open the
// dialog that says why, and turn the detail into a plain message so the
// page's own error toast still reads well.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Clear store if token is invalid/expired
      useAuthStore.getState().logout()
    }
    const gate = parseEmailGate(error)
    if (gate) {
      useEmailGateStore.getState().show(gate.action)
      error.response.data.detail = gate.message
    }
    return Promise.reject(error)
  }
)
