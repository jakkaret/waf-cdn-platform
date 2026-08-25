import React from 'react'
import { Sidebar } from './Sidebar'
import { AICopilotWidget } from '../copilot/AICopilotWidget'

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="flex min-h-screen bg-[var(--bg-app)] text-[var(--text-primary)]">
      <Sidebar />
      <main className="flex-1 ml-[240px] p-5 sm:p-7 min-w-0">
        <div className="max-w-[1560px] mx-auto animate-fade-in">
          {children}
        </div>
      </main>
      <AICopilotWidget />
    </div>
  )
}

export default AppLayout
