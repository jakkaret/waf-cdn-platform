// Pure decision logic for tunnel/origin live-connectivity badges, pulled out
// of Tunnels.tsx / Origins.tsx / OriginDetail.tsx so it's one tested place
// instead of three copies of the same ternary. Each consumer only supplies
// the couple of fields it actually has.

export type BadgeColor = 'success' | 'danger' | 'warning' | 'gray'

export interface TunnelStatusBadge {
  label: string
  color: BadgeColor
}

/** Tunnels page's "Live Connected Tunnel Proxies" table row. */
export function tunnelStatusBadge(isOnline: boolean | undefined): TunnelStatusBadge {
  return isOnline
    ? { label: '🟢 ONLINE', color: 'success' }
    : { label: '🔴 OFFLINE', color: 'danger' }
}

/** OriginDetail.tsx's "Tunnel Connectivity" row (only rendered when the
 * origin is tunnel-backed, so this takes just the one field it needs). */
export function tunnelConnectivityBadge(liveConnected: boolean | null | undefined): TunnelStatusBadge {
  return liveConnected
    ? { label: '🟢 CONNECTED', color: 'success' }
    : { label: '🔴 DISCONNECTED', color: 'danger' }
}

/** Origins.tsx's card status badge. `status` is the origin's CRUD lifecycle
 * state; `isTunnel`/`liveConnected` are the separate, read-time-computed
 * live-connectivity fields. A tunnel-backed origin whose `status` still says
 * "active" but whose live check says the FRP proxy isn't connected shows as
 * disconnected instead of the stale "ACTIVE" -- that mismatch (status never
 * reflecting real connectivity) was the bug this replaces. */
export interface TunnelHubStatus {
  online: boolean
  label: string
  detail: string
}

/** Tunnels page's top "Tunnel Hub Status" card. This platform runs two
 * parallel tunnel systems -- FRP (shared-token clients: juice/dvwa/bwapp)
 * and a custom domain-scoped protocol (cloudwaf, e.g. vampi) -- and this
 * card used to show a hardcoded "ONLINE & READY" string regardless of
 * whether either backend was actually reachable. Combines the FRP status
 * query's own fetch outcome with the cloudwaf tunnel server's real
 * state-file freshness (GET /api/tunnel/status's `server_running`). */
export function combineTunnelHubStatus(
  frpReachable: boolean,
  cloudwaf: { server_running?: boolean; reason?: string | null } | undefined
): TunnelHubStatus {
  const cloudwafOnline = cloudwaf?.server_running === true

  if (frpReachable && cloudwafOnline) {
    return { online: true, label: 'ONLINE & READY', detail: 'Both tunnel systems reachable' }
  }
  if (frpReachable || cloudwafOnline) {
    const downSystem = frpReachable ? 'Custom tunnel (cloudwaf)' : 'FRP'
    return { online: true, label: 'PARTIALLY ONLINE', detail: `${downSystem} unreachable` }
  }
  return {
    online: false,
    label: 'OFFLINE',
    detail: cloudwaf?.reason || 'Neither tunnel system is reachable',
  }
}

export function originStatusBadge(
  status: string,
  isTunnel: boolean | undefined,
  liveConnected: boolean | null | undefined
): TunnelStatusBadge {
  const isActive = status === 'active'
  if (isTunnel && isActive && liveConnected === false) {
    return { label: 'TUNNEL DISCONNECTED', color: 'danger' }
  }
  if (isActive) return { label: status.toUpperCase(), color: 'success' }
  if (status === 'pending') return { label: status.toUpperCase(), color: 'warning' }
  if (status === 'archived') return { label: status.toUpperCase(), color: 'gray' }
  return { label: status.toUpperCase(), color: 'danger' }
}
