import React, { useState } from 'react'
import { createOrigin } from '../api/origins'
import { toast } from 'react-hot-toast'
import { useQueryClient } from '@tanstack/react-query'

interface AddOriginModalProps {
  isOpen: boolean
  onClose: () => void
}

export const AddOriginModal: React.FC<AddOriginModalProps> = ({ isOpen, onClose }) => {
  const [label, setLabel] = useState('')
  const [ip, setIp] = useState('')
  const [port, setPort] = useState(80)
  const [isLoading, setIsLoading] = useState(false)
  const queryClient = useQueryClient()

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    // IP Validation
    const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/
    if (!ipPattern.test(ip)) {
      toast.error('Invalid IP address format')
      return
    }

    try {
      setIsLoading(true)
      await createOrigin({ label, ip, port: Number(port) })
      toast.success('Origin added successfully')
      queryClient.invalidateQueries({ queryKey: ['origins'] })
      onClose()
      // reset form
      setLabel('')
      setIp('')
      setPort(80)
    } catch (error: any) {
      toast.error(error.response?.data?.detail || 'Failed to add origin')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md shadow-2xl transition-all">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-gray-900 dark:text-white">Add Origin Server</h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Label</label>
            <input 
              type="text" 
              required
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              value={label}
              onChange={e => setLabel(e.target.value)}
              placeholder="e.g. Production Web Server"
            />
          </div>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">IP Address</label>
            <input 
              type="text" 
              required
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              value={ip}
              onChange={e => setIp(e.target.value)}
              placeholder="192.168.1.100"
            />
          </div>
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Port</label>
            <input 
              type="number" 
              required
              min={1}
              max={65535}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white"
              value={port}
              onChange={e => setPort(Number(e.target.value))}
            />
          </div>
          <div className="flex justify-end space-x-3">
            <button 
              type="button" 
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-700 transition-colors"
            >
              Cancel
            </button>
            <button 
              type="submit" 
              disabled={isLoading}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {isLoading ? 'Adding...' : 'Add Origin'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
