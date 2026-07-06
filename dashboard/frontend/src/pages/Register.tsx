import React, { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { authApi } from '../api/auth'
import toast from 'react-hot-toast'
import { Button } from '../components/ui/Button'
import { Card } from '../components/ui/Card'

export const Register: React.FC = () => {
  const [formData, setFormData] = useState({ username: '', email: '', password: '' })
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      await authApi.register(formData)
      toast.success('Registration successful! Please login.')
      navigate('/login')
    } catch (err: any) {
      const detail = err.response?.data?.detail
      const message = typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: any) => d.msg || JSON.stringify(d)).join(', ')
          : 'Registration failed'
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  const getStrengthScore = (pass: string) => {
    let score = 0
    if (pass.length > 5) score += 1
    if (pass.length > 8) score += 1
    if (/[A-Z]/.test(pass)) score += 1
    if (/[0-9]/.test(pass)) score += 1
    if (/[^A-Za-z0-9]/.test(pass)) score += 1
    return score
  }

  const score = getStrengthScore(formData.password)
  const colors = ['bg-bg-surface', 'bg-danger', 'bg-warning', 'bg-success/80', 'bg-success', 'bg-success']
  const strengthColor = formData.password ? colors[score] : 'bg-bg-surface'

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md p-8">
        <div className="text-center mb-8">
          <h2 className="text-2xl font-bold text-text-primary">Create Account</h2>
          <p className="text-text-muted text-sm mt-2">Join the WAF security platform</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[12px] font-bold text-text-muted uppercase tracking-wider mb-2">Username</label>
            <input
              type="text"
              required
              className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:border-accent focus:ring-1 focus:ring-accent outline-none"
              value={formData.username}
              onChange={e => setFormData({ ...formData, username: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-[12px] font-bold text-text-muted uppercase tracking-wider mb-2">Email</label>
            <input
              type="email"
              required
              className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:border-accent focus:ring-1 focus:ring-accent outline-none"
              value={formData.email}
              onChange={e => setFormData({ ...formData, email: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-[12px] font-bold text-text-muted uppercase tracking-wider mb-2">Password</label>
            <input
              type="password"
              required
              className="w-full bg-bg-surface border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white focus:border-accent focus:ring-1 focus:ring-accent outline-none mb-2"
              value={formData.password}
              onChange={e => setFormData({ ...formData, password: e.target.value })}
            />
            {formData.password && (
              <div className="flex gap-1 h-1">
                {[1, 2, 3, 4].map(i => (
                  <div key={i} className={`flex-1 rounded-full ${score >= i ? strengthColor : 'bg-bg-surface border border-white/5'}`} />
                ))}
              </div>
            )}
          </div>
          
          <Button type="submit" className="w-full mt-6" isLoading={loading}>
            Sign Up
          </Button>
        </form>

        <p className="mt-6 text-center text-sm text-text-muted">
          Already have an account? <Link to="/login" className="text-accent hover:text-accent-light transition-colors">Log in</Link>
        </p>
      </Card>
    </div>
  )
}

export default Register
