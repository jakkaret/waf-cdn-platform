import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'
import { Button } from '../components/ui/Button'
import { Card } from '../components/ui/Card'

export const Login: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const setAuth = useAuthStore(state => state.setAuth)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      const { access_token } = await authApi.login(email, password)
      
      // Temporarily set token in store to allow getMe to work
      useAuthStore.setState({ token: access_token })
      
      const user = await authApi.getMe()
      setAuth(access_token, user)
      toast.success('Logged in successfully')
      navigate('/')
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Login failed')
      useAuthStore.setState({ token: null })
    } finally {
      setLoading(false)
    }
  }

  const handleGoogleLogin = () => {
    window.location.href = '/api/auth/google/login'
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md p-8">
        <div className="text-center mb-8">
          <div className="w-12 h-12 rounded-xl gradient-brand flex items-center justify-center font-bold text-white text-2xl mx-auto mb-4 shadow-card">
            W
          </div>
          <h2 className="text-2xl font-bold text-text-primary">Welcome Back</h2>
          <p className="text-text-muted text-sm mt-2">Sign in to your WAF security dashboard</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[12px] font-bold text-text-muted uppercase tracking-wider mb-2">Email</label>
            <input
              type="email"
              required
              className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:border-accent focus:ring-1 focus:ring-accent outline-none transition-colors"
              value={email}
              onChange={e => setEmail(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-[12px] font-bold text-text-muted uppercase tracking-wider mb-2">Password</label>
            <input
              type="password"
              required
              className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:border-accent focus:ring-1 focus:ring-accent outline-none transition-colors"
              value={password}
              onChange={e => setPassword(e.target.value)}
            />
          </div>
          
          <Button type="submit" className="w-full" isLoading={loading}>
            Sign In
          </Button>
        </form>

        <div className="my-6 flex items-center">
          <div className="flex-1 border-t border-white/10"></div>
          <span className="px-3 text-[12px] text-text-muted uppercase font-semibold tracking-wider">OR</span>
          <div className="flex-1 border-t border-white/10"></div>
        </div>

        <Button variant="secondary" className="w-full" onClick={handleGoogleLogin}>
          <svg className="w-4 h-4 mr-2" viewBox="0 0 24 24">
            <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
            <path fill="#34A853" d="M12 24c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 21.53 7.7 24 12 24z" />
            <path fill="#FBBC05" d="M5.84 15.1c-.22-.66-.35-1.36-.35-2.1s.13-1.44.35-2.1V8.06H2.18C1.43 9.55 1 11.22 1 13s.43 3.45 1.18 4.94l3.66-2.84z" />
            <path fill="#EA4335" d="M12 4.69c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 1.18 14.97 0 12 0 7.7 0 3.99 2.47 2.18 6.06l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
          </svg>
          Continue with Google
        </Button>

        <p className="mt-6 text-center text-sm text-text-muted">
          Don't have an account? <Link to="/register" className="text-accent hover:text-accent-light transition-colors">Sign up</Link>
        </p>
      </Card>
    </div>
  )
}

export default Login
