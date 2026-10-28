import React, { useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import { useDialog } from './useDialog'
import { useT } from '../../i18n'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  // One line under the title saying what the dialog is for.
  description?: string
  children: React.ReactNode
}

export const Modal: React.FC<ModalProps> = ({ open, onClose, title, description, children }) => {
  const panelRef = useRef<HTMLDivElement>(null)
  const { t } = useT()
  const titleId = useId()
  const descriptionId = useId()
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
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
        className="dash-modal w-full max-w-lg shadow-2xl focus:outline-none"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex justify-between items-start gap-4 px-5 py-4 border-b border-[var(--bg-border-subtle)] bg-[var(--bg-surface-elevated)]">
          <div className="min-w-0">
            <h3 id={titleId} className="text-[15px] font-semibold text-[var(--text-primary)] m-0">
              {title}
            </h3>
            {description && (
              <p id={descriptionId} className="mt-1 mb-0 text-[12.5px] leading-relaxed text-[var(--text-muted)] [text-wrap:pretty]">
                {description}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label={t('Close dialog', 'ปิดหน้าต่าง')}
            className="-mr-1 shrink-0 text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors p-1.5 rounded-md cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>,
    document.body
  )
}
