import { useEffect, useRef, RefObject } from 'react'

// One implementation of "modal" behaviour for every overlay (Modal, Drawer) so
// they cannot drift apart. Covers what a keyboard or screen-reader user needs
// and a mouse user never notices:
//   - Escape closes the dialog on top (and only that one);
//   - Tab / Shift+Tab stay inside it;
//   - focus moves in on open and returns to whatever opened it on close;
//   - the page behind does not scroll (counted, so stacked dialogs restore it
//     only when the last one closes).

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

// Open dialogs, oldest first. Only the last one reacts to Escape and Tab, so a
// ConfirmDialog opened from a Drawer closes by itself and leaves the Drawer up.
const stack: symbol[] = []
let scrollLocks = 0
let savedOverflow = ''

export function useDialog(
  open: boolean,
  onClose: () => void,
  panelRef: RefObject<HTMLElement>,
  initialFocusRef?: RefObject<HTMLElement>
) {
  // onClose is read through a ref, not listed as an effect dependency. Callers
  // pass a fresh inline arrow every render; depending on it re-ran the effect
  // on every parent re-render (Alerts refetches every few seconds), which
  // yanked focus back to the panel and then to the opener each time.
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!open) return

    const id = Symbol('dialog')
    stack.push(id)

    const opener = document.activeElement as HTMLElement | null

    if (scrollLocks++ === 0) {
      savedOverflow = document.body.style.overflow
      document.body.style.overflow = 'hidden'
    }

    // Next frame: the panel is rendered through a portal and may not be in the
    // DOM yet at effect time.
    const raf = requestAnimationFrame(() => {
      const panel = panelRef.current
      const target =
        initialFocusRef?.current ?? panel?.querySelector<HTMLElement>(FOCUSABLE) ?? panel
      target?.focus()
    })

    const onKeyDown = (e: KeyboardEvent) => {
      if (stack[stack.length - 1] !== id) return

      if (e.key === 'Escape') {
        e.preventDefault()
        onCloseRef.current()
        return
      }

      if (e.key !== 'Tab') return
      const panel = panelRef.current
      if (!panel) return
      const items = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => el.offsetParent !== null
      )
      if (items.length === 0) {
        e.preventDefault()
        panel.focus()
        return
      }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement
      if (e.shiftKey && (active === first || !panel.contains(active))) {
        e.preventDefault()
        last.focus()
      } else if (!e.shiftKey && (active === last || !panel.contains(active))) {
        e.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)

    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener('keydown', onKeyDown)
      const at = stack.indexOf(id)
      if (at >= 0) stack.splice(at, 1)
      if (--scrollLocks === 0) document.body.style.overflow = savedOverflow
      // Only if it is still on the page: a row that re-rendered away should not
      // make focus fall back to <body> via a stale node.
      if (opener && document.contains(opener)) opener.focus()
    }
  }, [open, panelRef, initialFocusRef])
}
