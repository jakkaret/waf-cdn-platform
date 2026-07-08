import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getOrigins } from '../api/origins'
import { AddOriginModal } from '../components/AddOriginModal'
import { Link } from 'react-router-dom'

export const Origins = () => {
  const [isAddModalOpen, setIsAddModalOpen] = useState(false)
  const { data: origins, isLoading, error } = useQuery({
    queryKey: ['origins'],
    queryFn: getOrigins
  })

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Origin Servers</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">Manage your backend origins and routing</p>
        </div>
        <button
          onClick={() => setIsAddModalOpen(true)}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors shadow-sm flex items-center space-x-2"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          <span>Add Origin</span>
        </button>
      </div>

      {isLoading ? (
        <div className="flex justify-center p-12">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      ) : error ? (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg">Failed to load origins.</div>
      ) : origins?.length === 0 ? (
        <div className="text-center py-12 bg-white dark:bg-gray-800 rounded-lg shadow border border-gray-200 dark:border-gray-700">
          <svg className="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 002-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
          </svg>
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No origins</h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Get started by creating a new origin server.</p>
          <div className="mt-6">
            <button
              onClick={() => setIsAddModalOpen(true)}
              className="inline-flex items-center px-4 py-2 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700"
            >
              Add Origin
            </button>
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {origins?.map(origin => (
            <Link key={origin.id} to={`/origins/${origin.id}`} className="block group">
              <div className="bg-white dark:bg-gray-800 rounded-xl p-5 shadow-sm border border-gray-200 dark:border-gray-700 hover:shadow-md hover:border-blue-500 transition-all duration-200">
                <div className="flex justify-between items-start mb-4">
                  <h3 className="font-semibold text-lg text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">{origin.label}</h3>
                  <span className={`px-2.5 py-1 text-xs font-medium rounded-full ${
                    origin.status === 'active' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' :
                    origin.status === 'down' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400' :
                    'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                  }`}>
                    {origin.status}
                  </span>
                </div>
                <div className="space-y-2 text-sm text-gray-600 dark:text-gray-300">
                  <div className="flex items-center">
                    <svg className="w-4 h-4 mr-2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    {origin.ip}:{origin.port}
                  </div>
                  <div className="flex items-center">
                    <svg className="w-4 h-4 mr-2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    Added {new Date(origin.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}

      <AddOriginModal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} />
    </div>
  )
}
export default Origins
