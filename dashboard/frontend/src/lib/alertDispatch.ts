import type { WafAlert } from '../types'

export type DispatchState = 'sent' | 'failed' | 'unknown'

export interface DispatchLabel {
  state: DispatchState
  label: string
}

/**
 * Human label for an alert's Telegram dispatch state.
 *
 * `alert.status` is the HTTP status the WAF answered the client with (403,
 * 400, ...), NOT a dispatch result. The backend does not currently persist a
 * dispatch outcome, so unless it supplies `dispatch_status` (or boolean
 * `dispatched`) the honest answer is "Not tracked" rather than inventing one.
 */
export function getDispatchLabel(alert: Pick<WafAlert, 'dispatch_status' | 'dispatched'>): DispatchLabel {
  const raw = String(alert.dispatch_status ?? '').trim().toLowerCase()
  if (raw) {
    if (['sent', 'delivered', 'ok', 'success', 'dispatched'].includes(raw)) return { state: 'sent', label: 'Sent' }
    if (['failed', 'error', 'undelivered'].includes(raw)) return { state: 'failed', label: 'Failed' }
    if (['skipped', 'none', 'not_dispatched', 'not dispatched', 'pending'].includes(raw)) {
      return { state: 'unknown', label: 'Not dispatched' }
    }
  }
  if (alert.dispatched === true) return { state: 'sent', label: 'Sent' }
  if (alert.dispatched === false) return { state: 'unknown', label: 'Not dispatched' }
  return { state: 'unknown', label: 'Not tracked' }
}
