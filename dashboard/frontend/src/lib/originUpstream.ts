import type { Origin } from '../types'

// Where the WAF sends an origin's traffic, written the same way on the origin
// list and the origin page. A direct connection proxies to
// origin_scheme://ip:port (http when the backend never set a scheme, which is
// what nginx does too); an agent connection goes through the tunnel, so the
// ip:port is the agent's local target and has no scheme the WAF chooses.
export function originUpstreamLabel(origin: Pick<Origin, 'ip' | 'port' | 'connection_mode' | 'origin_scheme' | 'is_tunnel'>): string {
  const target = `${origin.ip}:${origin.port}`
  if (origin.connection_mode === 'direct') return `${origin.origin_scheme || 'http'}://${target}`
  if (origin.connection_mode === 'agent' || origin.is_tunnel) return `Tunnel to ${target}`
  return target
}
