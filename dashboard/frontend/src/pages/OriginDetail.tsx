import React from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getOrigin, deleteOrigin } from '../api/origins'
import { toast } from 'react-hot-toast'

export const OriginDetail = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const { data: origin, isLoading, error } = useQuery({
    queryKey: ['origin', id],
    queryFn: () => getOrigin(id!),
    enabled: !!id
  })

  const deleteMutation = useMutation({
    mutationFn: deleteOrigin,
    onSuccess: () => {
      toast.success('Origin deleted successfully')
      queryClient.invalidateQueries({ queryKey: ['origins'] })
      navigate('/origins')
    },
    onError: () => {
      toast.error('Failed to delete origin')
    }
  })

  const handleDelete = () => {
    if (window.confirm('Are you sure you want to delete this origin? This action cannot be undone.')) {
      deleteMutation.mutate(id!)
    }
  }

  if (isLoading) return <div className="p-6 flex justify-center"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div></div>
  if (error || !origin) return <div className="p-6 text-red-600">Failed to load origin details.</div>

  return (
    <div className="p-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
        <div>
          <div className="flex items-center space-x-2 text-sm text-gray-500 mb-2">
            <Link to="/origins" className="hover:text-blue-600 transition-colors">Origins</Link>
            <span>/</span>
            <span className="text-gray-900 dark:text-gray-300">{origin.label}</span>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            {origin.label}
            <span className={`px-2.5 py-1 text-xs font-medium rounded-full ${
              origin.status === 'active' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
              origin.status === 'down' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
              'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
            }`}>
              {origin.status}
            </span>
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-2 flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            {origin.ip}:{origin.port}
          </p>
        </div>
        <div className="flex space-x-3">
          <button 
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors shadow-sm font-medium"
          >
            Edit Settings
          </button>
          <button 
            onClick={handleDelete}
            disabled={deleteMutation.isPending}
            className="px-4 py-2 border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/10 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/30 transition-colors shadow-sm font-medium"
          >
            {deleteMutation.isPending ? 'Deleting...' : 'Delete Origin'}
          </button>
        </div>
      </div>

      {/* Grid Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column (Main Configs) */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Domains Card Placeholder */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>
                Domains (Phase 2)
              </h3>
              <button className="text-sm text-blue-600 hover:text-blue-700 font-medium">+ Add Domain</button>
            </div>
            <div className="text-center py-8 text-gray-500 dark:text-gray-400 border-2 border-dashed border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800/50">
              <p>No domains configured yet.</p>
              <p className="text-sm mt-1">Domain & DNS management will be implemented in Phase 2.</p>
            </div>
          </div>

          {/* WAF Config Card Placeholder */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
                Per-Origin WAF (Phase 4)
              </h3>
            </div>
            <div className="opacity-60 pointer-events-none">
              <div className="flex items-center justify-between py-3 border-b border-gray-100 dark:border-gray-700">
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Web Application Firewall</div>
                  <div className="text-sm text-gray-500">Enable OWASP Core Rule Set protection</div>
                </div>
                <div className="w-11 h-6 bg-blue-600 rounded-full relative"><div className="absolute right-1 top-1 w-4 h-4 bg-white rounded-full"></div></div>
              </div>
              <div className="flex items-center justify-between py-3">
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">Paranoia Level</div>
                  <div className="text-sm text-gray-500">Strictness of WAF rules (1-4)</div>
                </div>
                <select className="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg p-2 dark:bg-gray-700 dark:border-gray-600 dark:text-white"><option>Level 1 (Default)</option></select>
              </div>
            </div>
          </div>
          
        </div>

        {/* Right Column (Side Stats) */}
        <div className="space-y-6">
          
          {/* SSL Status Card Placeholder */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-bold text-gray-900 dark:text-white flex items-center gap-2 mb-4">
              <svg className="w-5 h-5 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
              SSL Certificate (Phase 3)
            </h3>
            <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4 border border-gray-100 dark:border-gray-700">
              <div className="flex items-center text-yellow-600 dark:text-yellow-400 mb-2">
                <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                <span className="font-medium text-sm">Not Configured</span>
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Add a domain to automatically provision a Let's Encrypt certificate.</p>
            </div>
          </div>

          {/* Quick Stats Placeholder */}
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-sm border border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Traffic (24h)</h3>
            <div className="space-y-4">
              <div>
                <div className="text-sm text-gray-500 dark:text-gray-400 mb-1">Total Requests</div>
                <div className="text-2xl font-semibold text-gray-900 dark:text-white">---</div>
              </div>
              <div>
                <div className="text-sm text-gray-500 dark:text-gray-400 mb-1">Blocked (WAF)</div>
                <div className="text-2xl font-semibold text-gray-900 dark:text-white">---</div>
              </div>
            </div>
          </div>

        </div>

      </div>
    </div>
  )
}
export default OriginDetail
