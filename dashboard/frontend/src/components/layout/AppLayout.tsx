import React from 'react'
import { Sidebar } from './Sidebar'

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex-1 ml-[260px] p-8">
        <div className="max-w-6xl mx-auto page-enter">
          {children}
        </div>
      </div>
    </div>
  )
}
