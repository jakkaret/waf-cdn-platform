import React, { useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'

export const OAuthSuccess: React.FC = () => {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const setAuth = useAuthStore(state => state.setAuth)

  useEffect(() => {
    const token = searchParams.get('token')
    
    if (token) {
      useAuthStore.setState({ token })
      
      authApi.getMe()
        .then(user => {
          setAuth(token, user)
          toast.success('Logged in with Google successfully!')
          navigate('/')
        })
        .catch(() => {
          toast.error('Failed to get user profile')
          useAuthStore.setState({ token: null })
          navigate('/login')
        })
    } else {
      toast.error('Authentication failed')
      navigate('/login')
    }
  }, [searchParams, navigate, setAuth])

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <div className="animate-spin w-8 h-8 border-4 border-white/10 border-t-accent rounded-full mx-auto mb-4"></div>
        <p className="text-text-muted">Authenticating...</p>
      </div>
    </div>
  )
}

export default OAuthSuccess
