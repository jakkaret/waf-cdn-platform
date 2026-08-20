import React from 'react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
}

export const Modal: React.FC<ModalProps> = ({ open, onClose, title, children }) => {
  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm animate-fade-in">
      <div className="dash-card w-full max-w-lg shadow-2xl overflow-hidden border border-[var(--bg-border-hover)]">
        <div className="flex justify-between items-center px-5 py-4 border-b border-[var(--bg-border-subtle)] bg-[var(--bg-surface-elevated)]">
          <h3 className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">{title}</h3>
          <button
            onClick={onClose}
            className="text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors p-1 cursor-pointer font-mono"
          >
            ✕
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  )
}
