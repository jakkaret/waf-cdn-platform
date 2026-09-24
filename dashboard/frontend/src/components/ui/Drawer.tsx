import React, { useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { useDialog } from './useDialog'

// Side panel for looking at (or editing) one record while the list it came
// from stays visible behind it. Same behaviour as Modal via useDialog; the
// difference is layout: it slides in from the right instead of covering the
// centre of the page.
//
// Uses the app's CSS variables directly (bg-[var(--bg-surface)] etc.), like
// Modal and every page does. An earlier version used utility names such as
// `bg-bg-surface` that Tailwind had no colour for, so it generated no CSS and
// the panel rendered transparent.

type DrawerSize = 'md' | 'lg' | 'xl'

const SIZE_CLASS: Record<DrawerSize, string> = {
  md: 'max-w-md',
  lg: 'max-w-xl',
  xl: 'max-w-2xl',
}

interface DrawerProps {
  open: boolean
  onClose: () => void
  title: React.ReactNode
  children: React.ReactNode
  size?: DrawerSize
}

export const Drawer: React.FC<DrawerProps> = ({ open, onClose, title, children, size = 'md' }) => {
  const panelRef = useRef<HTMLDivElement>(null)
  const titleId = useId()
  useDialog(open, onClose, panelRef)

  if (!open || typeof document === 'undefined') return null

  // Portal to <body>: a `position: fixed` panel is positioned relative to the
  // nearest ancestor that has a transform/filter, and the page shell animates.
  return createPortal(
    <>
      <div
        className="fixed inset-0 z-[55] bg-black/60 backdrop-blur-sm animate-fade-in"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={`fixed inset-y-0 right-0 z-[56] w-full ${SIZE_CLASS[size]} flex flex-col bg-[var(--bg-surface)] border-l border-[var(--bg-border)] shadow-2xl animate-slide-in-right motion-reduce:animate-none focus:outline-none`}
      >
        <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-[var(--bg-border-subtle)] bg-[var(--bg-surface-elevated)]">
          <h3 id={titleId} className="text-[14px] font-bold text-[var(--text-primary)] font-mono m-0 leading-snug">
            {title}
          </h3>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="shrink-0 p-1 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-hover)] transition-colors cursor-pointer focus:outline-none focus-visible:ring-2 focus-visible:ring-orange-500/60"
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </div>
    </>,
    document.body
  )
}
