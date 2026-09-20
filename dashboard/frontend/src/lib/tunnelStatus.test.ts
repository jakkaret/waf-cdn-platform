import { describe, it, expect } from 'vitest'
import { tunnelStatusBadge, tunnelConnectivityBadge, originStatusBadge, combineTunnelHubStatus } from './tunnelStatus'

describe('tunnelStatusBadge', () => {
  // Production change that would make this fail: the Tunnels page table row
  // used to render a hardcoded "🟢 ONLINE" badge unconditionally, never
  // reading the API's `is_online` field at all -- every proxy showed online
  // even when the backend explicitly marked it is_online: false.
  it('shows ONLINE only when is_online is true', () => {
    expect(tunnelStatusBadge(true)).toEqual({ label: '🟢 ONLINE', color: 'success' })
  })

  it('shows OFFLINE when is_online is false', () => {
    expect(tunnelStatusBadge(false)).toEqual({ label: '🔴 OFFLINE', color: 'danger' })
  })

  it('treats a missing is_online as offline, not online', () => {
    expect(tunnelStatusBadge(undefined)).toEqual({ label: '🔴 OFFLINE', color: 'danger' })
  })
})

describe('tunnelConnectivityBadge', () => {
  it('shows CONNECTED when live_connected is true', () => {
    expect(tunnelConnectivityBadge(true)).toEqual({ label: '🟢 CONNECTED', color: 'success' })
  })

  it('shows DISCONNECTED when live_connected is false', () => {
    expect(tunnelConnectivityBadge(false)).toEqual({ label: '🔴 DISCONNECTED', color: 'danger' })
  })

  it('treats null (non-tunnel origin) as disconnected rather than crashing', () => {
    expect(tunnelConnectivityBadge(null)).toEqual({ label: '🔴 DISCONNECTED', color: 'danger' })
  })
})

describe('combineTunnelHubStatus', () => {
  // Production change that would make this fail: the Tunnels page's "Tunnel
  // Hub Status" card used to render a hardcoded "ONLINE & READY" string with
  // no data behind it at all -- it would say this even if both tunnel
  // backends were completely unreachable.
  it('shows ONLINE & READY only when both FRP and cloudwaf are reachable', () => {
    expect(combineTunnelHubStatus(true, { server_running: true })).toEqual({
      online: true, label: 'ONLINE & READY', detail: 'Both tunnel systems reachable',
    })
  })

  it('shows PARTIALLY ONLINE when only FRP is reachable', () => {
    const result = combineTunnelHubStatus(true, { server_running: false, reason: 'stale' })
    expect(result.online).toBe(true)
    expect(result.label).toBe('PARTIALLY ONLINE')
    expect(result.detail).toContain('cloudwaf')
  })

  it('shows PARTIALLY ONLINE when only cloudwaf is reachable', () => {
    const result = combineTunnelHubStatus(false, { server_running: true })
    expect(result.online).toBe(true)
    expect(result.label).toBe('PARTIALLY ONLINE')
    expect(result.detail).toContain('FRP')
  })

  it('shows OFFLINE with the real reason when neither backend is reachable', () => {
    const result = combineTunnelHubStatus(false, {
      server_running: false,
      reason: 'No state update for 120s; the tunnel server may be down.',
    })
    expect(result.online).toBe(false)
    expect(result.label).toBe('OFFLINE')
    expect(result.detail).toBe('No state update for 120s; the tunnel server may be down.')
  })

  it('treats a missing/undefined cloudwaf response as not running, not a crash', () => {
    const result = combineTunnelHubStatus(false, undefined)
    expect(result.online).toBe(false)
    expect(result.label).toBe('OFFLINE')
  })
})

describe('originStatusBadge', () => {
  // Production change that would make this fail: the Origins page card
  // badge used to render the raw `status` field for every origin, including
  // tunnel-backed ones whose `status` stays "active" forever regardless of
  // whether the underlying FRP tunnel is actually connected right now.
  it('shows TUNNEL DISCONNECTED for an active tunnel-backed origin whose live check failed', () => {
    expect(originStatusBadge('active', true, false)).toEqual({
      label: 'TUNNEL DISCONNECTED', color: 'danger',
    })
  })

  it('shows ACTIVE for an active tunnel-backed origin that is actually connected', () => {
    expect(originStatusBadge('active', true, true)).toEqual({ label: 'ACTIVE', color: 'success' })
  })

  it('shows ACTIVE for a non-tunnel origin regardless of live_connected', () => {
    expect(originStatusBadge('active', false, null)).toEqual({ label: 'ACTIVE', color: 'success' })
  })

  it('shows PENDING for a pending origin even if it is a tunnel', () => {
    expect(originStatusBadge('pending', true, false)).toEqual({ label: 'PENDING', color: 'warning' })
  })

  it('shows ARCHIVED as gray', () => {
    expect(originStatusBadge('archived', false, null)).toEqual({ label: 'ARCHIVED', color: 'gray' })
  })

  it('falls back to danger for any other status', () => {
    expect(originStatusBadge('error', false, null)).toEqual({ label: 'ERROR', color: 'danger' })
  })
})
