// Edge state on the CDN page. /cdn/nodes probes each edge with a 1.2 s
// timeout, so one slow answer turns a working edge "offline" for a single
// poll and the page flickers (seen live: 1/2 online, then 2/2 seconds later).
// An edge is only called Offline after two failed checks in a row; a first
// miss is shown as what it is -- no answer to the last check.

export type EdgeState = 'online' | 'missed' | 'offline' | 'unknown'

export function nextEdgeState(previous: EdgeState | undefined, answered: boolean | undefined): EdgeState {
  if (answered === undefined) return 'unknown'
  if (answered) return 'online'
  // The first check after page load counts as one miss too: that is exactly
  // when the flicker was seen.
  return previous === 'missed' || previous === 'offline' ? 'offline' : 'missed'
}

export const EDGE_STATE_LABEL: Record<EdgeState, string> = {
  online: 'Online',
  missed: 'No answer to the last check',
  offline: 'Offline',
  unknown: 'Checking',
}
