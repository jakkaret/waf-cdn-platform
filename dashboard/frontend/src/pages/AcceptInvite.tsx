import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api/axios'
import { useAuthStore } from '../store/authStore'

// Landing page of an origin-sharing invitation (N9/H64). Access goes to the
// signed-in account that opens the emailed link.
const AcceptInvite: React.FC = () => {
  const { isAuthenticated, sessionChecked } = useAuthStore()
  const navigate = useNavigate()
  const token = new URLSearchParams(window.location.search).get('token') || ''
  const [state, setState] = useState<'idle' | 'working' | 'done' | 'error'>('idle')
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!token || !isAuthenticated || state !== 'idle') return
    setState('working')
    api
      .post<{ origin_id: string; role: string }>('/invites/accept', { token })
      .then((res) => {
        setState('done')
        setMessage(`You now have ${res.data.role} access.`)
        setTimeout(() => navigate(`/origins/${res.data.origin_id}`), 1200)
      })
      .catch((e) => {
        setState('error')
        setMessage(e.response?.data?.detail || 'This invitation could not be accepted.')
      })
  }, [token, isAuthenticated, state, navigate])

  let body: React.ReactNode
  if (!token) body = <p>This link has no invitation code.</p>
  else if (!isAuthenticated && !sessionChecked) body = <p>Checking your session...</p>
  else if (!isAuthenticated)
    body = (
      <p>
        Sign in first, then open the invitation link again.{' '}
        <Link to="/login" className="underline">Sign in</Link>
      </p>
    )
  else body = <p>{state === 'working' ? 'Accepting the invitation...' : message}</p>

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <div className="max-w-md w-full rounded-xl border p-6 space-y-3">
        <h1 className="text-lg font-semibold">Origin invitation</h1>
        {body}
      </div>
    </div>
  )
}

export default AcceptInvite
