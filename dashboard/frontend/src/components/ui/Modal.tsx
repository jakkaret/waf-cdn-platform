import React, { useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { useDialog } from './useDialog'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
}

export const Modal: React.FC<ModalProps> = ({ open, onClose, title, children }) => {
  const panelRef = useRef<HTMLDivElement>(null)
  const titleId = useId()
  // Escape, focus trap/return and scroll lock live in useDialog, shared with
  // Drawer. This component used to have only the scroll lock, so Escape did
  // nothing (confirmed on the archive-origin dialog) and a keyboard user could
  // Tab straight out of it into the page behind.
  useDialog(open, onClose, panelRef)

  if (!open || typeof document === 'undefined') return null

  return createPortal(
    <div
      className="modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="dash-modal w-full max-w-lg shadow-2xl focus:outline-none"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-center px-5 py-4 border-b border-[var(--bg-border-subtle)] bg-[var(--bg-surface-elevated)]">
          <h3 id={titleId} className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0">
            {title}
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close dialog"
            className="text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors p-1 rounded cursor-pointer font-mono focus:outline-none focus-visible:ring-2 focus-visible:ring-orange-500/60"
          >
            <span aria-hidden="true">✕</span>
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>,
    document.body
  )
}
