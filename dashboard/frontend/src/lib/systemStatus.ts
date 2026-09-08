// Pure selector over GET /api/system/status `cdn_nodes`.
//
// The Dashboard edge-node cards used to hardcode a permanent "ONLINE (Healthy)"
// badge and a fixed "~12 ms" latency — they stayed green even when a node was
// degraded or down. This maps one node's real reported status/latency into the
// small view the card needs, so the badge tells the truth.

export interface SystemNode {
  region: string
  status?: string
  latency_ms?: number
}

export interface NodeView {
  online: boolean
  statusLabel: string
  latencyLabel: string
}

export function selectNode(
  nodes: SystemNode[] | null | undefined,
  region: string
): NodeView {
  const node = nodes?.find((n) => n.region === region)
  if (!node) {
    return { online: false, statusLabel: 'UNKNOWN', latencyLabel: '—' }
  }
  const status = (node.status ?? '').toLowerCase()
  const online = status === 'healthy'
  const statusLabel =
    status === 'healthy' ? 'ONLINE (Healthy)'
    : status === 'degraded' ? 'DEGRADED'
    : status === 'offline' ? 'OFFLINE'
    : 'UNKNOWN'
  // latency_ms is 0 when the backend could not measure it — don't print "~0 ms".
  const ms = node.latency_ms ?? 0
  const latencyLabel = ms > 0 ? `~${ms} ms` : 'n/a'
  return { online, statusLabel, latencyLabel }
}
