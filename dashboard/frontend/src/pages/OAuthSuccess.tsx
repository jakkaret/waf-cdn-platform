import React, { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'
import { api } from '../api/axios'
import { User } from '../types'

/**
 * [S2 FIX] หน้านี้ไม่อ่าน ?token= จาก URL อีกต่อไป
 * เพราะ token ใน URL ถูกบันทึกใน browser history / server logs
 *
 * แทนที่ด้วย: backend set HttpOnly cookie ตอน redirect มาหน้านี้
 * แล้ว frontend เรียก GET /api/auth/me ผ่าน cookie (withCredentials: true)
 * เพื่อ hydrate session เอง
 */
export const OAuthSuccess: React.FC = () => {
  const navigate = useNavigate()
  const setAuth = useAuthStore(state => state.setAuth)

  useEffect(() => {
    // เรียก /api/auth/me ด้วย withCredentials เพื่อให้ axios ส่ง HttpOnly cookie
    api.get<User>('/auth/me', { withCredentials: true })
      .then(res => {
        // สำหรับ cookie-based auth: token ใน store เป็น empty string
        // axios จะแนบ cookie อัตโนมัติทุก request
        setAuth('', res.data)
        toast.success('Logged in with Google successfully!')
        navigate('/')
      })
      .catch(() => {
        toast.error('Authentication failed — please try again')
        navigate('/login')
      })
  }, [navigate, setAuth])

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <div className="animate-spin w-8 h-8 border-4 border-white/10 border-t-accent rounded-full mx-auto mb-4"></div>
        <p className="text-text-muted">Completing sign in...</p>
      </div>
    </div>
  )
}

export default OAuthSuccess
